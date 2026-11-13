//! Безопасная при перезапуске HTTP-передача файлов по подписанным манифестам.
//! Частичные байты сами по себе никогда не считаются доверенными: сильный HTTP-валидатор
//! контролирует повторное использование Range, а подписанный SHA-256 подтверждает весь
//! подготовленный файл до переноса его в установку клиента.
use crate::{file_ownership, network_resilience::{self, Directive},
    replace_verified_managed_file_0224, set_executable_if_needed, ManifestFile};
use reqwest::{header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, ETAG, RANGE, IF_RANGE, ACCEPT_ENCODING}, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, Weak}};
use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}, sync::{Mutex as AsyncMutex, watch}};

const PARTIAL_SCHEMA: u32 = 1;
const META_MAX_SIZE: u64 = 8192;
// CDN может ограничивать каждый ответ 206 размером меньше запрошенного конца.
// Продолжайте получать последующие диапазоны, не расходуя бюджет повторов на правильные ответы.
const MAX_RANGE_SEGMENTS: usize = 256;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartialMetadata {
    schema_version: u32,
    url: String,
    expected_sha256: String,
    expected_size: u64,
    /// В If-Range допустимы только сильные теги сущности.
    etag: Option<String>,
}

impl PartialMetadata {
    fn matches(&self, file: &ManifestFile) -> bool {
        self.schema_version == PARTIAL_SCHEMA &&
        self.expected_size == file.size &&
        self.expected_sha256.eq_ignore_ascii_case(&file.sha256) &&
        self.etag.as_deref().map_or(true, strong_etag)
    }
}

static FILE_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<AsyncMutex<()>>>>> = OnceLock::new();

fn file_mutex(path: &Path) -> Arc<AsyncMutex<()>> {
    let mut locks = FILE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
        .lock().expect("Блокировка частичной передачи повреждена");
    locks.retain(|_, lock| lock.strong_count() > 0);
    let key = path.to_path_buf();
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) { return lock }
    let lock = Arc::new(AsyncMutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn partial_paths(root: &Path, target: &Path) -> Result<(PathBuf, PathBuf), String> {
    // Храните внутреннее состояние вне пользовательских каталогов, где пользователь
    // вправе иметь собственные файлы с именами *.part или *.json.
    let relative = target.strip_prefix(root).map_err(|_| "Целевой путь расположен за пределами каталога установки")?;
    let id = hex::encode(Sha256::digest(relative.to_string_lossy().as_bytes()));
    let directory = root.join(".launcher").join("downloads").join(&id[..2]);
    Ok((directory.join(format!("{id}.part")), directory.join(format!("{id}.part.json"))))
}

fn strong_etag(etag: &str) -> bool {
    // ETag — непрозрачный сильный валидатор в кавычках (RFC 9110, раздел 8.8.3).
    // Не используйте слабые валидаторы или строки с CR/LF в заголовках HTTP.
    etag.len() >= 2 && etag.starts_with('"') && etag.ends_with('"') &&
        !etag.as_bytes()[1..etag.len()-1].iter().any(|b| *b < 0x21 || *b == b'"' || *b == 0x7f)
}

fn response_etag(response: &reqwest::Response) -> Option<String> {
    response.headers().get(ETAG).and_then(|value| value.to_str().ok())
        .filter(|value| strong_etag(value)).map(ToOwned::to_owned)
}

fn check_identity_encoding(response: &reqwest::Response) -> Result<(), String> {
    if let Some(encoding) = response.headers().get(CONTENT_ENCODING) {
        if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
            return Err("Для подписанных файлов запрещено кодирование Content-Encoding, отличное от identity".into());
        }
    }
    Ok(())
}

fn content_length(response: &reqwest::Response) -> Result<Option<u64>, String> {
    response.headers().get(CONTENT_LENGTH).map(|value| {
        value.to_str().map_err(|_| "Заголовок Content-Length содержит данные не в UTF-8".to_string())?
            .parse::<u64>().map_err(|_| "Некорректное значение: Content-Length".to_string())
    }).transpose()
}

fn expected_range(response: &reqwest::Response, start: u64, total: u64) -> Result<u64, String> {
    // Строгий разбор единственного диапазона. Без произвольного общего размера, multipart и неудовлетворимых диапазонов.
    let value = response.headers().get(CONTENT_RANGE)
        .ok_or("Ответ HTTP 206 не содержит Content-Range")?
        .to_str().map_err(|_| "Некорректное значение: кодирование заголовка Content-Range")?;
    let range = value.strip_prefix("bytes ").ok_or("Некорректная единица диапазона Content-Range")?;
    let (bounds, total_str) = range.split_once('/').ok_or("Некорректный заголовок Content-Range")?;
    let (low, high) = bounds.split_once('-').ok_or("Некорректные границы диапазона Content-Range")?;
    let first = low.parse::<u64>().map_err(|_| "Некорректное значение: начальная позиция Content-Range")?;
    let last = high.parse::<u64>().map_err(|_| "Некорректное значение: конечная позиция Content-Range")?;
    let complete = total_str.parse::<u64>().map_err(|_| "Некорректное значение: общий размер Content-Range")?;
    if first != start || last < first || complete != total || last >= total {
        return Err(format!("Небезопасное значение Content-Range: {value}; запрошено {start}-/{total}"));
    }
    let length = last - first + 1;
    if content_length(response)?.is_some_and(|reported| reported != length) {
        return Err("Content-Length не совпадает с Content-Range".into());
    }
    Ok(length)
}

fn check_full_response(response: &reqwest::Response, size: u64) -> Result<(), String> {
    if response.status() != StatusCode::OK { return Err(format!("Ожидался ответ HTTP 200, получен {}", response.status())) }
    if response.headers().contains_key(CONTENT_RANGE) {
        return Err("Ответ HTTP 200 неожиданно содержит Content-Range".into());
    }
    if content_length(response)?.is_some_and(|len| len != size) {
        return Err("Content-Length не совпадает с подписанным манифестом".into());
    }
    check_identity_encoding(response)
}

async fn remove_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("Не удалось удалить частичный файл {}: {err}", path.display())),
    }
}

async fn discard(part: &Path, meta: &Path) -> Result<(), String> {
    remove_if_present(part).await?;
    remove_if_present(meta).await
}

async fn read_metadata(path: &Path) -> Option<PartialMetadata> {
    if fs::metadata(path).await.ok()?.len() > META_MAX_SIZE { return None }
    serde_json::from_slice(&fs::read(path).await.ok()?).ok()
}

async fn store_metadata(root: &Path, meta_path: &Path, data: &PartialMetadata) -> Result<(), String> {
    let payload = serde_json::to_vec(data).map_err(|e| e.to_string())?;
    let name = meta_path.file_name().ok_or("Некорректное имя файла метаданных")?.to_string_lossy();
    let tmp = meta_path.with_file_name(format!("{name}.tmp-{:016x}", rand::random::<u64>()));
    let outcome = async {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).await
            .map_err(|e| format!("Не удалось создать метаданные частичной загрузки: {e}"))?;
        file.write_all(&payload).await.map_err(|e| format!("Не удалось записать метаданные частичного файла: {e}"))?;
        file.sync_all().await.map_err(|e| format!("Не удалось синхронизировать метаданные частичного файла: {e}"))?;
        drop(file);
        // При смене зеркала сначала сохраните новую идентичность источника, затем дописывайте.
        // И в Windows выполняйте атомарную замену; нельзя оставлять валидатор отсутствующим.
        crate::platform_fs::replace_file(root, &tmp, meta_path)
            .map_err(|e| format!("Не удалось опубликовать метаданные частичного файла: {e}"))
    }.await;
    if outcome.is_err() { let _ = fs::remove_file(&tmp).await; }
    outcome
}

async fn digest_existing(path: &Path) -> Result<(u64, Sha256), String> {
    let mut input = fs::File::open(path).await.map_err(|e| format!("Не удалось открыть частичный файл для вычисления хеша: {e}"))?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).await.map_err(|e| format!("Не удалось вычислить хеш частичного файла: {e}"))?;
        if count == 0 { break }
        size = size.checked_add(count as u64).ok_or("Переполнение длины частичного файла")?;
        digest.update(&buffer[..count]);
    }
    Ok((size, digest))
}

async fn install_verified(root: &Path, file: &ManifestFile, target: &Path, part: &Path, meta: &Path) -> Result<(), String> {
    file_ownership::ensure_no_symlinks(root, target)?;
    replace_verified_managed_file_0224(part, target).await?;
    set_executable_if_needed(target, file.executable).await?;
    remove_if_present(meta).await
}

fn request_error(path: &str, error: String) -> String {
    if error.starts_with("[retry:") || error == "download paused" || error == "Загрузка отменена" {
        error
    } else { format!("{path}: ошибка HTTP-запроса: {error}") }
}

async fn request_with_control(client: &reqwest::Client, url: &str,
    range: Option<(u64, Option<&str>)>, control: &mut watch::Receiver<Directive>) -> Result<reqwest::Response, String> {
    network_resilience::check(control)?;
    let mut request = client.get(url).header(ACCEPT_ENCODING, "identity");
    if let Some((start, validator)) = range {
        request = request.header(RANGE, format!("bytes={start}-"));
        // Валидаторы относятся только к одному источнику. Между подписанными зеркалами
        // Range служит лишь оптимизацией трафика: решающим остаётся полный дайджест.
        if let Some(validator) = validator { request = request.header(IF_RANGE, validator); }
    }
    let response = tokio::select! {
        result = tokio::time::timeout(network_resilience::REQUEST_TIMEOUT, request.send()) => {
            match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(network_resilience::transient(format!("Ошибка соединения или HTTP-запроса: {error}"), None)),
                Err(_) => return Err(network_resilience::transient("Превышено время ожидания HTTP-запроса", None)),
            }
        },
        state = network_resilience::interrupted(control) => return Err(state.error().into()),
    };
    if network_resilience::retryable_status(response.status()) {
        let wait = network_resilience::retry_after(&response);
        return Err(network_resilience::transient(format!("Временная ошибка HTTP {}", response.status()), wait));
    }
    Ok(response)
}

/// Продолжайте файл из проверенного манифеста, при необходимости используя
/// сохранённый частичный файл от прерванного запуска. `transferred` учитывает байты *сети*.
/// И Desktop-загрузки, и Repair вызывают это через download_scheduler::run.
pub(crate) async fn download_verified(
    client: &reqwest::Client, root: &Path, file: &ManifestFile, target: &Path,
    transferred: impl Fn(u64),
) -> Result<(), String> {
    let (_sender, receiver) = watch::channel(Directive::Running);
    download_verified_controlled(client, root, file, target, transferred, receiver).await
}

pub(crate) async fn download_verified_controlled(
    client: &reqwest::Client, root: &Path, file: &ManifestFile, target: &Path,
    transferred: impl Fn(u64), control: watch::Receiver<Directive>,
) -> Result<(), String> {
    let lock = file_mutex(target);
    let _guard = lock.lock().await;
    for _ in 0..MAX_RANGE_SEGMENTS {
        if download_verified_segment(client, root, file, target, &transferred, control.clone()).await? {
            return Ok(());
        }
    }
    Err(network_resilience::transient(
        "Сервер вернул слишком много диапазонов HTTP; частичный файл сохранён", None))
}

/// Один полный ответ или ограниченный диапазон. Возвращает false только если
/// сервер выдал префикс с проверенной длиной и требуется следующий диапазон.
async fn download_verified_segment(
    client: &reqwest::Client, root: &Path, file: &ManifestFile, target: &Path,
    transferred: impl Fn(u64), mut control: watch::Receiver<Directive>,
) -> Result<bool, String> {
    network_resilience::check(&control)?;
    file_ownership::ensure_no_symlinks(root, target)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await.map_err(|e| format!("{}: mkdir: {e}", file.path))?;
    }
    let (part, meta) = partial_paths(root, target)?;
    file_ownership::ensure_no_symlinks(root, &part)?;
    file_ownership::ensure_no_symlinks(root, &meta)?;
    fs::create_dir_all(part.parent().ok_or("Некорректный каталог частичных загрузок")?).await
        .map_err(|e| format!("{}: не удалось создать хранилище частичной загрузки: {e}", file.path))?;
    file_ownership::ensure_no_symlinks(root, &part)?;
    file_ownership::ensure_no_symlinks(root, &meta)?;

    let exists_part = fs::try_exists(&part).await.map_err(|e| e.to_string())?;
    let exists_meta = fs::try_exists(&meta).await.map_err(|e| e.to_string())?;
    let previous = if exists_part && exists_meta { read_metadata(&meta).await } else { None };
    // Повторно используйте префикс того же источника лишь с сильным ETag.
    // Другое подписанное зеркало может отдать суффикс без специфичного источнику
    // If-Range; окончательный SHA-256 подтверждает объединённый файл.
    let mut resume = None;
    if let Some(state) = previous.filter(|m| m.matches(file)) {
        let len = fs::metadata(&part).await.map_err(|e| e.to_string())?.len();
        if len == file.size {
            let (actual_len, hash) = digest_existing(&part).await?;
            if actual_len == file.size && hex::encode(hash.finalize()).eq_ignore_ascii_case(&file.sha256) {
                network_resilience::check(&control)?;
                install_verified(root, file, target, &part, &meta).await?;
                return Ok(true);
            }
        }
        if len > 0 && len < file.size {
            if state.url == file.url {
                if let Some(etag) = state.etag { resume = Some((len, Some(etag))); }
            } else {
                resume = Some((len, None));
            }
        }
    }
    if resume.is_none() { discard(&part, &meta).await?; }

    let mut response = request_with_control(client, &file.url,
        resume.as_ref().map(|(start, etag)| (*start, etag.as_deref())), &mut control).await
        .map_err(|e| request_error(&file.path, e))?;
    let mut append = false;
    let mut prefix_len = 0u64;
    let mut allowed_body_len = file.size;
    if let Some((start, expected_etag)) = &resume {
        match response.status() {
            StatusCode::PARTIAL_CONTENT => {
                let valid = check_identity_encoding(&response)
                    .and_then(|_| expected_range(&response, *start, file.size))
                    .and_then(|length| {
                        if expected_etag.as_deref().is_some_and(|expected|
                            response_etag(&response).as_deref() != Some(expected)) {
                            return Err("В ответе HTTP 206 отсутствует исходный строгий ETag".into());
                        }
                        Ok(length)
                    });
                match valid {
                    Ok(length) => {
                        if expected_etag.is_none() {
                            // Сохраните новую идентичность зеркала атомарно до записи байтов
                            // смешанного происхождения. Следующий повтор не должен отправлять
                            // валидатор прежнего источника этому зеркалу.
                            store_metadata(root, &meta, &PartialMetadata {
                                schema_version: PARTIAL_SCHEMA, url: file.url.clone(),
                                expected_sha256: file.sha256.clone(), expected_size: file.size,
                                etag: response_etag(&response),
                            }).await?;
                        }
                        append = true;
                        prefix_len = *start;
                        allowed_body_len = length;
                    }
                    Err(_) => {
                        // Повреждённый или не совпадающий ответ 206 нельзя дописывать. Отбросьте
                        // его и получите чистый 200 (а не второй Range).
                        drop(response);
                        discard(&part, &meta).await?;
                        response = request_with_control(client, &file.url, None, &mut control).await
                            .map_err(|e| request_error(&file.path, e))?;
                    }
                }
            }
            StatusCode::OK => {
                // Валидатор If-Range изменился или сервер проигнорировал Range. Это
                // полное представление; никогда не соединяйте его со старыми байтами.
                discard(&part, &meta).await?;
            }
            StatusCode::RANGE_NOT_SATISFIABLE => {
                // 416 может означать уменьшение удалённого объекта или отклонение Range.
                // Локальный префикс не является авторитетным относительно сервера.
                drop(response);
                discard(&part, &meta).await?;
                response = request_with_control(client, &file.url, None, &mut control).await
                    .map_err(|e| request_error(&file.path, e))?;
            }
            status => return Err(format!("{}: возобновление загрузки, HTTP {status}", file.path)),
        }
    }
    if append {
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(format!("{}: ожидался ответ HTTP 206", file.path));
        }
    } else {
        check_full_response(&response, file.size).map_err(|e| format!("{}: {e}", file.path))?;
        // Примечание: неудачный первый полный ответ оставляет прежний частичный файл
        // нетронутым только если он всё ещё допускает последующее безопасное продолжение.
        discard(&part, &meta).await?;
        let state = PartialMetadata { schema_version: PARTIAL_SCHEMA, url: file.url.clone(),
            expected_sha256: file.sha256.clone(), expected_size: file.size,
            etag: response_etag(&response) };
        store_metadata(root, &meta, &state).await?;
    }

    let mut digest = Sha256::new();
    if append {
        let (len, prefix_hash) = digest_existing(&part).await?;
        if len != prefix_len { return Err(format!("{}: частичный файл был одновременно изменён другим процессом", file.path)) }
        digest = prefix_hash;
    }
    let mut output = fs::OpenOptions::new().write(true).create(!append).append(append)
        .truncate(!append).open(&part).await
        .map_err(|e| format!("{}: не удалось открыть частичный файл: {e}", file.path))?;
    let mut body_len = 0u64;
    loop {
        let packet = tokio::select! {
            result = tokio::time::timeout(network_resilience::READ_TIMEOUT, response.chunk()) => result,
            state = network_resilience::interrupted(&mut control) => {
                output.flush().await.map_err(|e| format!("Не удалось сбросить буфер частичного файла при паузе или отмене: {e}"))?;
                output.sync_all().await.map_err(|e| format!("Не удалось синхронизировать частичный файл при паузе или отмене: {e}"))?;
                return Err(state.error().into());
            }
        };
        let chunk = match packet {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                output.flush().await.map_err(|io| format!("{}: ошибка сброса буфера частичного файла: {io}", file.path))?;
                output.sync_all().await.map_err(|io| format!("{}: ошибка синхронизации частичного файла: {io}", file.path))?;
                return Err(network_resilience::transient(format!("{}: передача тела HTTP-ответа прервана: {error}", file.path), None));
            },
            Err(_) => {
                output.flush().await.map_err(|io| format!("{}: ошибка сброса буфера частичного файла: {io}", file.path))?;
                output.sync_all().await.map_err(|io| format!("{}: ошибка синхронизации частичного файла: {io}", file.path))?;
                return Err(network_resilience::transient(format!("{}: истекло время ожидания чтения", file.path), None));
            }
        };
        transferred(chunk.len() as u64);
        if chunk.len() as u64 > allowed_body_len.saturating_sub(body_len) {
            drop(output);
            discard(&part, &meta).await?;
            return Err(format!("{}: тело HTTP-ответа превышает заявленный или подписанный размер", file.path));
        }
        for piece in chunk.chunks(64 * 1024) {
            output.write_all(piece).await.map_err(|e| format!("{}: не удалось записать частичный файл: {e}", file.path))?;
            digest.update(piece);
            body_len += piece.len() as u64;
        }
    }
    output.flush().await.map_err(|e| format!("{}: не удалось сбросить буфер частичного файла: {e}", file.path))?;
    output.sync_all().await.map_err(|e| format!("{}: не удалось синхронизировать частичный файл: {e}", file.path))?;
    drop(output);
    if body_len != allowed_body_len {
        // Короткое корректное HTTP-тело всё равно означает прерывание с возможностью
        // продолжения, пока закреплён сильный ETag; никогда не активируйте такой файл.
        return Err(network_resilience::transient(format!("{}: неполное тело HTTP-ответа ({body_len}/{allowed_body_len})", file.path), None));
    }
    if prefix_len + body_len != file.size {
        // Корректный ограниченный ответ 206 не является ошибкой. Его сильный ETag
        // остаётся закреплённым для следующего Range в этой операции.
        return Ok(false);
    }
    if !hex::encode(digest.finalize()).eq_ignore_ascii_case(&file.sha256) {
        discard(&part, &meta).await?;
        if append {
            // Повреждение префикса или различающиеся байты зеркал нельзя активировать.
            // Повторите с этого источника с нулевого байта до отказа или переключения.
            return Err(network_resilience::transient(
                format!("{}: SHA-256 после возобновления не совпадает; повторная загрузка полного файла", file.path), None));
        }
        return Err(format!("{}: полная проверка SHA-256 не пройдена", file.path));
    }
    network_resilience::check(&control)?;
    install_verified(root, file, target, &part, &meta).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

    struct Reply {
        status: &'static str,
        headers: Vec<(String, String)>,
        bytes: Vec<u8>,
    }
    fn response(status: &'static str, etag: Option<&str>, data: &[u8], declared: u64) -> Reply {
        let mut headers = vec![("Content-Length".into(), declared.to_string())];
        if let Some(tag) = etag { headers.push(("ETag".into(), tag.into())); }
        Reply { status, headers, bytes: data.to_vec() }
    }

    async fn mock_http(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", server.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = server.accept().await.unwrap();
                let mut header = Vec::new();
                let mut buf = [0u8; 1024];
                while !header.ends_with(b"\r\n\r\n") {
                    let count = stream.read(&mut buf).await.unwrap();
                    if count == 0 { return }
                    header.extend_from_slice(&buf[..count]);
                    if header.len() > 16384 { panic!("HTTP-запрос превышает допустимый размер") }
                    if header.windows(4).any(|w| w == b"\r\n\r\n") { break }
                }
                observed.lock().unwrap().push(String::from_utf8(header).unwrap());
                let mut payload = format!("HTTP/1.1 {}\r\nConnection: close\r\n", reply.status);
                for (name, value) in reply.headers { payload.push_str(&format!("{name}: {value}\r\n")); }
                payload.push_str("\r\n");
                stream.write_all(payload.as_bytes()).await.unwrap();
                stream.write_all(&reply.bytes).await.unwrap();
                let _ = stream.shutdown().await;
            }
        });
        (url, requests, task)
    }

    fn file(url: String, data: &[u8]) -> ManifestFile {
        ManifestFile { path: "libraries/data.jar".into(), url, size: data.len() as u64,
            sha256: hex::encode(Sha256::digest(data)), mirrors: vec![], required: true, executable: false,
            target_os: vec![], ownership: "required".into() }
    }

    async fn workspace() -> PathBuf {
        let root = std::env::temp_dir().join(format!("nl-http-resume-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(root.join("libraries")).await.unwrap();
        root
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .build().unwrap()
    }

    #[tokio::test]
    async fn interrupted_transfer_persists_validator_and_sends_if_range_after_restart() {
        let data = b"0123456789ABCDEFGHIJ";
        let first = response("200 OK", Some("\"v1\""), &data[..8], data.len() as u64);
        let mut second = response("206 Partial Content", Some("\"v1\""), &data[8..], 12);
        second.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let (url, requests, server) = mock_http(vec![first, second]).await;
        let f = file(url, data);
        let root = workspace().await;
        let target = root.join(&f.path);
        let transferred = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let result = download_verified(&client(), &root, &f, &target, |n| {
            transferred.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }).await;
        assert!(result.is_err(), "Был принят неполный ответ");
        let (part, metadata) = partial_paths(&root, &target).unwrap();
        assert_eq!(fs::read(&part).await.unwrap(), &data[..8]);
        assert_eq!(read_metadata(&metadata).await.unwrap().etag.as_deref(), Some("\"v1\""));
        // Новый HTTP-клиент и модель вызовов учитывают семантику перезапуска процесса.
        download_verified(&client(), &root, &f, &target, |n| {
            transferred.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        assert!(!fs::try_exists(&part).await.unwrap());
        assert!(!fs::try_exists(&metadata).await.unwrap());
        assert_eq!(transferred.load(std::sync::atomic::Ordering::Relaxed), 20);
        server.await.unwrap();
        let history = requests.lock().unwrap();
        assert_eq!(history.len(), 2);
        assert!(!history[0].to_ascii_lowercase().contains("range: bytes="));
        assert!(history[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(history[1].to_ascii_lowercase().contains("if-range: \"v1\""));
        drop(history);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn changed_etag_and_http_200_append_old_content() {
        let old = b"OOOOOOOOOOabcdefghij";
        let new = b"NNNNNNNNNNabcdefghij";
        let replies = vec![
            response("200 OK", Some("\"old\""), &old[..10], 20),
            response("200 OK", Some("\"new\""), new, 20),
        ];
        let (url, history, server) = mock_http(replies).await;
        let root = workspace().await;
        let f = file(url, new);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(target).await.unwrap(), new);
        server.await.unwrap();
        assert!(history.lock().unwrap()[1].to_ascii_lowercase().contains("if-range: \"old\""));
        fs::remove_dir_all(root).await.unwrap();
    }

    async fn corrupted_resume_response_is_restarted(invalid: Reply) {
        let data = b"0123456789ABCDEFGHIJ";
        let replies = vec![
            response("200 OK", Some("\"fixed\""), &data[..8], 20),
            invalid,
            response("200 OK", Some("\"fixed\""), data, 20),
        ];
        let (url, requests, server) = mock_http(replies).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(target).await.unwrap(), data);
        server.await.unwrap();
        let history = requests.lock().unwrap();
        assert_eq!(history.len(), 3);
        assert!(history[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(!history[2].to_ascii_lowercase().contains("range: bytes="));
        drop(history);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn malformed_content_range_must_fallback_to_fresh_get() {
        let mut invalid = response("206 Partial Content", Some("\"fixed\""), b"garbage", 7);
        invalid.headers.push(("Content-Range".into(), "bytes 9-15/20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn response_etag_mismatch_on_206_forces_fresh_get() {
        let mut invalid = response("206 Partial Content", Some("\"changed\""), b"garbage", 7);
        invalid.headers.push(("Content-Range".into(), "bytes 8-14/20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn range_not_satisfiable_forces_fresh_get() {
        let mut invalid = response("416 Range Not Satisfiable", Some("\"fixed\""), b"", 0);
        invalid.headers.push(("Content-Range".into(), "bytes */20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn incorrect_partial_content_length_forces_fresh_get() {
        let mut invalid = response("206 Partial Content", Some("\"fixed\""), b"garbage", 7);
        invalid.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn wrong_hash_discards_partial_and_preserves_previous_target() {
        let correct = b"expected";
        let (url, _, server) = mock_http(vec![response("200 OK", Some("\"t1\""), b"BAD_DATA", 8)]).await;
        let root = workspace().await;
        let f = file(url, correct);
        let target = root.join(&f.path);
        fs::write(&target, b"\xd0\x98\xd1\x81\xd1\x85\xd0\xbe\xd0\xb4\xd0\xbd\xd1\x8b\xd0\xb5 \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5 \xd0\xba\xd0\xbb\xd0\xb8\xd0\xb5\xd0\xbd\xd1\x82\xd0\xb0").await.unwrap();
        let result = download_verified(&client(), &root, &f, &target, |_| {}).await;
        assert!(result.unwrap_err().contains("SHA-256"));
        assert_eq!(fs::read(&target).await.unwrap(), b"\xd0\x98\xd1\x81\xd1\x85\xd0\xbe\xd0\xb4\xd0\xbd\xd1\x8b\xd0\xb5 \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5 \xd0\xba\xd0\xbb\xd0\xb8\xd0\xb5\xd0\xbd\xd1\x82\xd0\xb0");
        let (part, meta) = partial_paths(&root, &target).unwrap();
        assert!(!fs::try_exists(part).await.unwrap());
        assert!(!fs::try_exists(meta).await.unwrap());
        server.await.unwrap();
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn weak_or_missing_validator_triggers_range_reuse() {
        let data = b"0123456789ABCDEFGHIJ";
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("W/\"weak\""), &data[..7], 20),
            response("200 OK", Some("\"strong\""), data, 20),
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(target).await.unwrap(), data);
        server.await.unwrap();
        let observed = history.lock().unwrap();
        assert!(!observed[1].to_ascii_lowercase().contains("range: bytes="));
        drop(observed);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn stale_signed_identity_or_corrupt_metadata_is_not_reused() {
        let data = b"0123456789ABCDEFGHIJ";
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("\"v3\""), data, 20),
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        let (part, meta) = partial_paths(&root, &target).unwrap();
        fs::create_dir_all(part.parent().unwrap()).await.unwrap();
        fs::write(&part, b"old bytes").await.unwrap();
        fs::write(&meta, b"{broken metadata").await.unwrap();
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        assert!(!fs::try_exists(&part).await.unwrap());
        server.await.unwrap();
        assert!(!history.lock().unwrap()[0].to_ascii_lowercase().contains("range: bytes="));
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn completed_partial_from_prior_process_installs_without_network() {
        let data = b"complete signed artifact";
        // Заведомо недоступный URL: никакой запрос не должен отправляться.
        let root = workspace().await;
        let f = file("http://127.0.0.1:1/unreachable".into(), data);
        let target = root.join(&f.path);
        let (part, meta) = partial_paths(&root, &target).unwrap();
        fs::create_dir_all(part.parent().unwrap()).await.unwrap();
        fs::write(&part, data).await.unwrap();
        store_metadata(&root, &meta, &PartialMetadata {
            schema_version: PARTIAL_SCHEMA, url: f.url.clone(),
            expected_sha256: f.sha256.clone(), expected_size: f.size,
            etag: Some("\"cached\"".into()),
        }).await.unwrap();
        download_verified(&client(), &root, &f, &target, |_| panic!("Тело сетевого ответа уже прочитано"))
            .await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        assert!(!fs::try_exists(part).await.unwrap());
        assert!(!fs::try_exists(meta).await.unwrap());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn bounded_206_ranges_continue_without_restarting_or_consuming_retry_budget() {
        let data = b"0123456789ABCDEFGHIJ";
        let mut middle = response("206 Partial Content", Some("\"stable\""), &data[8..14], 6);
        middle.headers.push(("Content-Range".into(), "bytes 8-13/20".into()));
        let mut tail = response("206 Partial Content", Some("\"stable\""), &data[14..], 6);
        tail.headers.push(("Content-Range".into(), "bytes 14-19/20".into()));
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("\"stable\""), &data[..8], 20),
            middle, tail,
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        // Один вызов объединяет оба правильных ограниченных ответа без потери
        // первых восьми байтов и без повтора на уровне приложения.
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        server.await.unwrap();
        let h = history.lock().unwrap();
        assert_eq!(h.len(), 3);
        assert!(h[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(h[2].to_ascii_lowercase().contains("range: bytes=14-"));
        assert!(h[2].to_ascii_lowercase().contains("if-range: \"stable\""));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn failed_primary_mirror_resumes_suffix_without_leaking_origin_etag() {
        let data = b"0123456789ABCDEFGHIJ";
        let (primary, primary_history, primary_server) = mock_http(vec![
            response("200 OK", Some("\"primary\""), &data[..8], 20),
        ]).await;
        let mut suffix = response("206 Partial Content", Some("\"mirror\""), &data[8..], 12);
        suffix.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let (mirror, mirror_history, mirror_server) = mock_http(vec![suffix]).await;
        let root = workspace().await;
        let f = file(primary, data);
        let target = root.join(&f.path);
        fs::write(&target, b"previous client").await.unwrap();
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        assert_eq!(fs::read(&target).await.unwrap(), b"previous client");
        let mut alternate = f.clone();
        alternate.url = mirror;
        download_verified(&client(), &root, &alternate, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        primary_server.await.unwrap();
        mirror_server.await.unwrap();
        assert_eq!(primary_history.lock().unwrap().len(), 1);
        let h = mirror_history.lock().unwrap();
        assert_eq!(h.len(), 1);
        assert!(h[0].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(!h[0].to_ascii_lowercase().contains("if-range:"));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn interrupted_mirror_transfer_pins_new_origin_etag_before_resuming() {
        let data = b"0123456789ABCDEFGHIJ";
        let (primary, _, first_server) = mock_http(vec![
            response("200 OK", Some("\"origin-a\""), &data[..8], 20),
        ]).await;
        let mut interrupted = response("206 Partial Content", Some("\"origin-b\""), &data[8..13], 12);
        interrupted.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let mut finished = response("206 Partial Content", Some("\"origin-b\""), &data[13..], 7);
        finished.headers.push(("Content-Range".into(), "bytes 13-19/20".into()));
        let (mirror, requests, second_server) = mock_http(vec![interrupted, finished]).await;
        let root = workspace().await;
        let original = file(primary, data);
        let target = root.join(&original.path);
        assert!(download_verified(&client(), &root, &original, &target, |_| {}).await.is_err());
        let mut fallback = original.clone();
        fallback.url = mirror.clone();
        assert!(download_verified(&client(), &root, &fallback, &target, |_| {}).await.is_err());
        let (part, meta) = partial_paths(&root, &target).unwrap();
        assert_eq!(fs::read(&part).await.unwrap(), &data[..13]);
        let state = read_metadata(&meta).await.unwrap();
        assert_eq!(state.url, mirror);
        assert_eq!(state.etag.as_deref(), Some("\"origin-b\""));
        // Новый вызов моделирует перезапуск Desktop после очередного сбоя.
        download_verified(&client(), &root, &fallback, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        first_server.await.unwrap();
        second_server.await.unwrap();
        let h = requests.lock().unwrap();
        assert_eq!(h.len(), 2);
        assert!(!h[0].to_ascii_lowercase().contains("if-range:"));
        assert!(h[1].to_ascii_lowercase().contains("range: bytes=13-"));
        assert!(h[1].to_ascii_lowercase().contains("if-range: \"origin-b\""));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_partial_is_discarded_and_retry_from_zero_repairs_automatically() {
        let data = b"0123456789ABCDEFGHIJ";
        let mut resumed = response("206 Partial Content", Some("\"stable\""), &data[8..], 12);
        resumed.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("\"stable\""), &data[..8], 20),
            resumed,
            response("200 OK", Some("\"stable\""), data, 20),
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        fs::write(&target, b"\xd0\x9f\xd1\x80\xd0\xb5\xd0\xb4\xd1\x8b\xd0\xb4\xd1\x83\xd1\x89\xd0\xb0\xd1\x8f \xd1\x80\xd0\xb0\xd0\xb1\xd0\xbe\xd1\x82\xd0\xbe\xd1\x81\xd0\xbf\xd0\xbe\xd1\x81\xd0\xbe\xd0\xb1\xd0\xbd\xd0\xb0\xd1\x8f \xd0\xb2\xd0\xb5\xd1\x80\xd1\x81\xd0\xb8\xd1\x8f \xd0\xba\xd0\xbb\xd0\xb8\xd0\xb5\xd0\xbd\xd1\x82\xd0\xb0").await.unwrap();
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        let (part, meta) = partial_paths(&root, &target).unwrap();
        fs::write(&part, b"XXXXXXXX").await.unwrap();
        let error = download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap_err();
        assert!(network_resilience::retry_delay(&error, 0).is_some());
        assert!(!fs::try_exists(&part).await.unwrap());
        assert!(!fs::try_exists(&meta).await.unwrap());
        assert_eq!(fs::read(&target).await.unwrap(), b"\xd0\x9f\xd1\x80\xd0\xb5\xd0\xb4\xd1\x8b\xd0\xb4\xd1\x83\xd1\x89\xd0\xb0\xd1\x8f \xd1\x80\xd0\xb0\xd0\xb1\xd0\xbe\xd1\x82\xd0\xbe\xd1\x81\xd0\xbf\xd0\xbe\xd1\x81\xd0\xbe\xd0\xb1\xd0\xbd\xd0\xb0\xd1\x8f \xd0\xb2\xd0\xb5\xd1\x80\xd1\x81\xd0\xb8\xd1\x8f \xd0\xba\xd0\xbb\xd0\xb8\xd0\xb5\xd0\xbd\xd1\x82\xd0\xb0");
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        server.await.unwrap();
        let h = history.lock().unwrap();
        assert_eq!(h.len(), 3);
        assert!(h[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(!h[2].to_ascii_lowercase().contains("range: bytes="));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn strict_http_range_parsing_and_weak_validator_rejection() {
        assert!(strong_etag("\"abc\""));
        assert!(!strong_etag("W/\"abc\""));
        assert!(!strong_etag("\"abc\r\n\""));
        assert!(!strong_etag("1234"));
    }
}
