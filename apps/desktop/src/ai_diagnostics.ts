/** Local diagnostics: raw logs are input only. Reports contain fixed rule IDs and bounded numbers. */
export const MAX_LOG_FILES = 5;
export const HEAD_BYTES = 64 * 1024;
export const TAIL_BYTES = 512 * 1024;
const MAX_LINE = 8192;
const MAX_COUNT = 100_000;
export type Source = 'launcher' | 'java' | 'download' | 'runtime' | 'file-check' | 'minecraft-log' | 'crash-report' | 'mod-log' | 'java-log' | 'download-log';
export type ImportSource = Extract<Source, 'minecraft-log' | 'crash-report' | 'mod-log' | 'java-log' | 'download-log'>;
export const IMPORT_SOURCES: readonly ImportSource[] = ['minecraft-log','crash-report','mod-log','java-log','download-log'];
export type LocalSnapshot = {
  stage: string; logs: readonly string[];
  java: {found: boolean; compatible: boolean; requiredMajorVersion: number; detectedMajorVersion?: number; message: string; versionOutput: string} | null;
  download: {failed: number; messages: readonly string[]} | null;
  transfer: {phase: string; failed: number} | null;
  launch: {state: string; success?: boolean; exitCode?: number; message: string} | null;
  files: readonly {status: string}[];
};
type Rule = {id: string; category: 'java' | 'minecraft' | 'mods' | 'download' | 'launcher'; pattern: RegExp; ru: string; en: string; actionRu: string; actionEn: string};
// Match concrete failure markers, not generic words such as "Java", "mod", "download" or "signature".
export const RULES = [
  {id:'java-version',category:'java',pattern:/unsupportedclassversionerror|class file version \d+.*(?:recognizes|supports)|(?:java|jre).{0,90}(?:version mismatch|incompatible|несовместим|не подходит|требуется java)|requires (?:java|jre) (?:version )?\d+|java.{0,90}не соответствует диапазону/i,ru:'Несовместимая версия Java',en:'Incompatible Java version',actionRu:'Сверьте обязательную версию Java профиля с обнаруженной. Выберите управляемую Java подходящей версии.',actionEn:'Compare the required and detected Java versions. Select a compatible managed Java runtime.'},
  {id:'java-missing',category:'java',pattern:/java_home.{0,80}(?:not set|invalid)|(?:java|jre)(?: executable)? (?:not found|is missing|не найден[ао]?)|could not find (?:a valid )?java|не удалось найти java/i,ru:'Java не найдена',en:'Java not found',actionRu:'Проверьте выбор Java в настройках и наличие управляемого runtime.',actionEn:'Check the Java selection and managed runtime installation.'},
  {id:'heap-oom',category:'java',pattern:/outofmemoryerror:\s*(?:java heap space|gc overhead limit exceeded)|java heap space/i,ru:'Исчерпана память Java heap',en:'Java heap exhausted',actionRu:'Проверьте лимиты памяти профиля и доступную RAM; не выделяйте всю системную память игре.',actionEn:'Review profile memory limits and available RAM; do not allocate all system memory to the game.'},
  {id:'native-memory',category:'java',pattern:/could not reserve enough space|native memory allocation \(mmap\) failed|insufficient memory for the java runtime|outofmemoryerror:\s*(?:unable to create native thread|direct buffer memory|metaspace)/i,ru:'Недостаточно нативной памяти JVM',en:'JVM native memory exhausted',actionRu:'Освободите системную память и проверьте параметры JVM; увеличение heap может ухудшить ситуацию.',actionEn:'Free system memory and inspect JVM options; increasing the heap may make this worse.'},
  {id:'jvm-options',category:'java',pattern:/unrecognized vm option|invalid maximum heap size|invalid initial heap size|could not create the java virtual machine/i,ru:'Ошибка параметров JVM',en:'Invalid JVM options',actionRu:'Сверьте JVM-параметры с версией Java и настройками подписанного профиля.',actionEn:'Check JVM options against the Java version and signed profile configuration.'},
  {id:'mod-dependency',category:'mods',pattern:/incompatible mods found|modresolutionexception|modloadingexception|missing (?:mandatory|required) dependenc|(?:mod|mod id).{0,180}requires.{0,180}(?:version|missing|not installed|but only|but found)|depends on.{0,150}(?:missing|not installed)|could not find required mod/i,ru:'Зависимость или версия модификации не подходит',en:'Missing or incompatible mod dependency',actionRu:'Сверьте зависимости и версии модов с Minecraft и загрузчиком. Для управляемых файлов используйте проверку профиля.',actionEn:'Check mod dependencies and versions against Minecraft and the loader. Verify managed profile files.'},
  {id:'mixin',category:'mods',pattern:/mixinapplyerror|mixintransformererror|invalidmixinexception|injectionerror|critical injection failure|mixin.{0,100}(?:failed to apply|apply failed|injection failed)/i,ru:'Ошибка Mixin / трансформации',en:'Mixin / transformation failure',actionRu:'Проверьте совместимость модов и загрузчика, воспроизведите сбой на разрешённом тестовом профиле.',actionEn:'Check mod and loader compatibility and reproduce on an authorized test profile.'},
  {id:'mod-duplicate',category:'mods',pattern:/duplicate mods? (?:found|detected)|duplicate mod id|duplicatemodsexception|found duplicate mod/i,ru:'Дублирование модификаций',en:'Duplicate mods',actionRu:'Сверьте список модов с каталогом профиля; не удаляйте управляемые файлы вручную.',actionEn:'Compare the mod list with the profile catalog; do not manually remove managed files.'},
  {id:'class-loading',category:'mods',pattern:/classnotfoundexception|noclassdeffounderror|nosuchmethoderror|nosuchfielderror|abstractmethoderror|linkageerror/i,ru:'Ошибка загрузки классов / несовместимый API',en:'Class loading / API incompatibility',actionRu:'Проверьте соответствие модов, библиотек, версии Minecraft и загрузчика; причина не обязательно в моде.',actionEn:'Check mods, libraries, Minecraft version and loader; a mod is not necessarily the cause.'},
  {id:'graphics',category:'minecraft',pattern:/glfw error|failed to create (?:the )?window|failed to initialize (?:glfw|opengl)|opengl.{0,100}(?:not supported|unsupported|error)|pixel format not accelerated/i,ru:'Ошибка графики / OpenGL',en:'Graphics / OpenGL failure',actionRu:'Проверьте драйвер GPU, поддержку OpenGL и использование подходящего графического адаптера.',actionEn:'Check GPU drivers, OpenGL support and the selected graphics adapter.'},
  {id:'native-crash',category:'minecraft',pattern:/a fatal error has been detected by the java runtime|exception_access_violation|sigsegv|sigbus|unsatisfiedlinkerror/i,ru:'Нативный сбой JVM или библиотеки',en:'Native JVM or library crash',actionRu:'Проверьте архитектуру Java и нативных библиотек; изучите hs_err_pid локально.',actionEn:'Check Java and native library architecture; inspect the hs_err_pid report locally.'},
  {id:'world-data',category:'minecraft',pattern:/failed to (?:load|read) (?:level|world|chunk)|corrupt(?:ed)? (?:chunk|region file)|reportedexception: (?:ticking entity|ticking world)/i,ru:'Сбой мира или игрового объекта',en:'World or game object failure',actionRu:'Сделайте резервную копию мира и проверьте воспроизведение в отдельном мире. Не удаляйте сохранения.',actionEn:'Back up the world and test a separate world. Do not delete saves.'},
  {id:'tls',category:'download',pattern:/sslhandshakeexception|pkix path building failed|certificate (?:verify failed|expired|unknown|validation failed)|tls handshake (?:failed|error|timeout)|invalid peer certificate/i,ru:'Ошибка TLS / сертификата',en:'TLS / certificate failure',actionRu:'Проверьте часы ОС, цепочку сертификатов и настройки сети. Не отключайте TLS-проверку.',actionEn:'Check system time, certificate chain and networking. Do not disable TLS verification.'},
  {id:'network',category:'download',pattern:/sockettimeoutexception|connectexception|unknownhostexception|connection (?:reset|refused|timed out|aborted)|network is unreachable|temporary failure in name resolution|dns (?:lookup )?(?:failed|error)|(?:download|загрузк).{0,100}(?:timeout|timed out|обрыв|тайм-аут)/i,ru:'Сетевой сбой',en:'Network failure',actionRu:'Проверьте подключение, DNS и доступность сервера; повторите штатную загрузку после восстановления сети.',actionEn:'Check connectivity, DNS and server availability; retry the normal download once connectivity returns.'},
  {id:'http-denied',category:'download',pattern:/\bhttp(?:\/\d(?:\.\d)?)?\s+(?:status\s*)?[=:]?\s*(?:401|403)\b|(?:download|загрузк).{0,100}\b(?:401|403)\b/i,ru:'HTTP-доступ отклонён',en:'HTTP access denied',actionRu:'Проверьте действительность сессии и права на профиль или артефакт.',actionEn:'Check session validity and access to the profile or artifact.'},
  {id:'http-unavailable',category:'download',pattern:/\bhttp(?:\/\d(?:\.\d)?)?\s+(?:status\s*)?[=:]?\s*(?:404|410|429|5\d\d)\b|(?:download|загрузк).{0,100}\b(?:404|410|429|5\d\d)\b/i,ru:'HTTP-ресурс недоступен или ограничен',en:'HTTP resource unavailable or rate limited',actionRu:'Проверьте публикацию релиза и доступность CDN; при ограничении запросов повторите позже.',actionEn:'Check release publication and CDN availability; retry later if rate limited.'},
  {id:'integrity',category:'download',pattern:/(?:sha-?256|checksum|hash|хеш|контрольн.{0,12}сумм).{0,100}(?:mismatch|invalid|failed|не совпада|неверн|не пройдена)|(?:несовпадение|несоответствие|не прош[её]л проверку).{0,80}sha-?256|(?:signature|подпис).{0,100}(?:invalid|mismatch|verification failed|недейств|не прошла)|invalid (?:manifest|package) signature/i,ru:'Проверка целостности или подписи не пройдена',en:'Integrity or signature verification failed',actionRu:'Не запускайте повреждённый пакет. Используйте штатную проверку или восстановление подписанного профиля.',actionEn:'Do not run the damaged package. Use the normal signed profile verification or repair.'},
  {id:'disk',category:'launcher',pattern:/no space left on device|disk (?:is )?full|not enough (?:free )?disk space|enospc|недостаточно места|нет места на диске/i,ru:'Недостаточно места на диске',en:'Insufficient disk space',actionRu:'Освободите место на диске установки и временных файлов, сохранив пользовательские данные.',actionEn:'Free space on the installation and temporary volumes without removing user data.'},
  {id:'permission',category:'launcher',pattern:/permission denied|accessdeniedexception|access is denied|eacces|read-only file system|отказано в доступе/i,ru:'Файловый доступ отклонён',en:'File access denied',actionRu:'Проверьте права на каталог и блокировки файлов; не отключайте защиту ОС.',actionEn:'Check directory permissions and file locks; do not disable OS protection.'},
  {id:'auth',category:'launcher',pattern:/invalid_grant|session (?:expired|revoked|invalid)|authentication failed|invalid session|сессия (?:истекла|отозвана|недействительна)/i,ru:'Ошибка авторизации',en:'Authentication failure',actionRu:'Повторно войдите штатным способом и проверьте доступ к проекту.',actionEn:'Sign in again using the normal flow and verify project access.'},
  {id:'archive',category:'download',pattern:/zipexception|unexpected end of (?:file|archive)|invalid (?:zip|archive)|corrupt(?:ed)? archive|failed to extract/i,ru:'Повреждённый или неполный архив',en:'Damaged or incomplete archive',actionRu:'Повторите проверенную загрузку и восстановление; не извлекайте непроверенный архив вручную.',actionEn:'Retry verified download and repair; do not manually extract an unverified archive.'},
  {id:'download-failed',category:'download',pattern:/(?:download|загрузк).{0,100}(?:failed|ошиб|не удалось)|failed to download|(?:ошибка|не удалось).{0,40}загруз/i,ru:'Загрузка завершилась ошибкой',en:'Download failed',actionRu:'Проверьте детализацию загрузки и повторите штатную операцию после устранения причины.',actionEn:'Inspect download details and retry the normal operation after addressing the cause.'},
  {id:'launch-failed',category:'minecraft',pattern:/game crashed|minecraft.{0,70}(?:crashed|failed to launch)|process exited with (?:non.zero|code -?[1-9]\d*)|не удалось запустить (?:minecraft|игру)/i,ru:'Неуспешный запуск игры',en:'Game launch failed',actionRu:'Изучите последние логи и crash-report; код завершения сам по себе не устанавливает причину.',actionEn:'Inspect recent logs and the crash report; an exit code alone does not establish the cause.'},
  {id:'file-check',category:'launcher',pattern:/(?:managed file|файл).{0,100}(?:missing|invalid|отсутствует|повреждён)/i,ru:'Отсутствующий или повреждённый файл',en:'Missing or invalid file',actionRu:'Выполните штатную проверку файлов и при необходимости восстановление.',actionEn:'Run normal file verification and repair if necessary.'},
  {id:'other-error',category:'launcher',pattern:/\b(?:ERROR|FATAL|Exception|failed|failure)\b|ошибка|не удалось/i,ru:'Другой сигнал ошибки',en:'Other error signal',actionRu:'Точных признаков недостаточно. Добавьте актуальный журнал или crash-report.',actionEn:'Specific evidence is insufficient. Add a current log or crash report.'},
] as const satisfies readonly Rule[];
export type RuleId = typeof RULES[number]['id'];
export type Evidence = {id: RuleId; count: number};
export type Scan = {source: Source; lines: number; truncated: boolean; evidence: Evidence[]};
export type Report = {schema: 'ai-diagnostics/1'; stage: string; java?: {found: boolean; compatible: boolean; required?: number; detected?: number}; download?: {failed: number}; transfer?: {phase: string; failed: number}; launch?: {state: string; success?: boolean; exitCode?: number}; fileCheck?: {missing: number; invalid: number}; scans: Scan[]};
const stages = ['idle','connecting','session','project','profile','manifest','java','files','repair','cleanup','ready','launching','running','failed'];
const phases = ['starting','downloading','retrying','mirror-fallback','cache-hit','cache-write-failed','verified','staged','verifying','publishing','completed','paused','cancelled','failed','failed-file'];
const processStates = ['running','stopping','exited'];
const safeEnum = (v: string, allowed: readonly string[]) => allowed.includes(v) ? v : 'other';
const count = (v: number) => Number.isSafeInteger(v) && v >= 0 ? Math.min(v, MAX_COUNT) : 0;
const major = (v: number | undefined) => typeof v === 'number' && Number.isInteger(v) && v > 0 && v < 100 ? v : undefined;
const exit = (v: number | undefined) => typeof v === 'number' && Number.isInteger(v) && v >= -2147483648 && v <= 4294967295 ? v : undefined;
export function scanLines(source: Source, chunks: readonly string[], truncated = false): Scan {
  const hits = new Map<RuleId, number>(); let lines = 0;
  for (const chunk of chunks) {
    for (const raw of chunk.split(/\r\n|\n|\r/)) {
      if (!raw.trim()) continue;
      if (lines >= MAX_COUNT) {truncated = true; break;}
      lines++;
      if (raw.length > MAX_LINE) truncated = true;
      const line = raw.slice(0, MAX_LINE);
      const matched = RULES.slice(0,-1).filter(rule => rule.pattern.test(line));
      const rules = matched.length ? matched : RULES.slice(-1).filter(rule => rule.pattern.test(line));
      for (const rule of rules) hits.set(rule.id, (hits.get(rule.id) ?? 0) + 1);
    }
  }
  return {source, lines, truncated, evidence: RULES.filter(r => hits.has(r.id)).map(r => ({id:r.id,count:hits.get(r.id)!}))};
}
/** File picker grants only the files explicitly selected. Bound reads and never expose filenames. */
export async function scanFile(file: Blob, source: ImportSource): Promise<Scan> {
  if (!IMPORT_SOURCES.includes(source) || file.size === 0) throw new Error('invalid-log');
  const truncated = file.size > HEAD_BYTES + TAIL_BYTES;
  const parts = truncated ? [file.slice(0, HEAD_BYTES), file.slice(file.size - TAIL_BYTES)] : [file];
  const chunks: string[] = [];
  for (let i=0;i<parts.length;i++) {
    const bytes = new Uint8Array(await parts[i].arrayBuffer());
    // Reject compressed/binary input (including UTF-16); accept ordinary UTF-8 logs only.
    if (bytes.includes(0) || (bytes[0] === 0x1f && bytes[1] === 0x8b) || (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4)) throw new Error('invalid-log');
    let text = new TextDecoder('utf-8').decode(bytes);
    if (text.includes('\ufffd')) {
      // A partial slice can split a UTF-8 code point; tolerate only the boundary.
      const interior = truncated ? (i === 0 ? text.slice(0,-4) : text.slice(4)) : text;
      if (interior.includes('\ufffd')) throw new Error('invalid-log');
    }
    if (truncated) {
      if (i === 0) {const end = Math.max(text.lastIndexOf('\n'),text.lastIndexOf('\r')); text = end < 0 ? '' : text.slice(0,end);}
      else {const start = text.search(/[\r\n]/); text = start < 0 ? '' : text.slice(start+1);}
    }
    chunks.push(text);
  }
  return scanLines(source, chunks, truncated);
}
export function localReport(snapshot: LocalSnapshot, imports: readonly Scan[] = []): Report {
  const {java,download,transfer,launch,files} = snapshot;
  const report: Report = {schema:'ai-diagnostics/1',stage:safeEnum(snapshot.stage,stages),scans:[scanLines('launcher',snapshot.logs.slice(0,80).map(s=>s.slice(0,MAX_LINE)),snapshot.logs.length > 80 || snapshot.logs.some(s=>s.length>MAX_LINE))]};
  const add = (source: Source, messages: readonly string[]) => report.scans.push(scanLines(source,messages.slice(0,80).map(s=>s.slice(0,MAX_LINE)),messages.length>80 || messages.some(s=>s.length>MAX_LINE)));
  if (java) {report.java = {found:java.found===true,compatible:java.compatible===true,required:major(java.requiredMajorVersion),detected:major(java.detectedMajorVersion)}; add('java',[java.message,java.versionOutput]);}
  if (download) {report.download={failed:count(download.failed)}; add('download',download.messages);}
  if (transfer) report.transfer={phase:safeEnum(transfer.phase,phases),failed:count(transfer.failed)};
  if (launch) {report.launch={state:safeEnum(launch.state,processStates),success:typeof launch.success==='boolean'?launch.success:undefined,exitCode:exit(launch.exitCode)}; add('runtime',[launch.message]);}
  if (files.length) report.fileCheck={missing:count(files.filter(f=>f.status==='missing').length),invalid:count(files.filter(f=>f.status==='invalid').length)};
  report.scans.push(...imports.slice(0,MAX_LOG_FILES));
  return report;
}
export function findings(report: Report): RuleId[] {
  const ids = new Set(report.scans.flatMap(scan=>scan.evidence.map(e=>e.id)));
  if (report.java && !report.java.found) ids.add('java-missing');
  if (report.java?.found && !report.java.compatible) ids.add('java-version');
  if (report.download?.failed || report.transfer?.failed || report.transfer?.phase==='failed' || report.transfer?.phase==='failed-file') ids.add('download-failed');
  if (report.launch?.state==='exited' && (report.launch.success===false || (report.launch.exitCode!==undefined && report.launch.exitCode!==0))) ids.add('launch-failed');
  if (report.fileCheck?.missing || report.fileCheck?.invalid) ids.add('file-check');
  return RULES.filter(r=>ids.has(r.id)).map(r=>r.id);
}
export function diagnosticQuestion(report: Report, locale: 'ru'|'en'): string {
  const instruction = locale==='ru' ? 'Проанализируй диагностические признаки NeverLauncher. Укажи вероятные причины, приоритет безопасных проверок и чего не хватает для подтверждения. Не считай признаки доказанной причиной. Не предлагай отключать подписи, TLS или защиту; не удаляй пользовательские данные. Исходные логи не переданы.' : 'Analyze these NeverLauncher diagnostic indicators. Provide likely causes, prioritized safe checks, and missing evidence. Treat signals as hypotheses, not proven causes. Do not suggest disabling signatures, TLS or security, or deleting user data. Raw logs are not supplied.';
  // Only generated reports are accepted by the UI. Repeated source scans are separate observations.
  return `${instruction}\n${JSON.stringify({...report, findings:findings(report)})}`;
}
