//! Cancellable bounded HTTP retries for the signed-file downloader.
//! No unchecked bytes are ever installed: http_resume validates the final digest.
use reqwest::{header::RETRY_AFTER, Response, StatusCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

pub const MAX_ATTEMPTS: usize = 7;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const READ_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SERVER_WAIT_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Directive { Running, Paused, Cancelled }

impl Directive {
    pub fn error(self) -> &'static str {
        match self { Self::Running => "", Self::Paused => "download paused", Self::Cancelled => "download cancelled" }
    }
}

pub fn check(rx: &watch::Receiver<Directive>) -> Result<(), String> {
    match *rx.borrow() { Directive::Running => Ok(()), other => Err(other.error().into()) }
}

pub async fn interrupted(rx: &mut watch::Receiver<Directive>) -> Directive {
    loop {
        let value = *rx.borrow_and_update();
        if value != Directive::Running { return value; }
        if rx.changed().await.is_err() { std::future::pending::<()>().await; }
    }
}

pub fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

// RFC 9110 IMF-fixdate, strictly parsed without accepting arbitrary timezone offsets.
// Convert a Gregorian civil date to Unix days (Howard Hinnant's civil algorithm).
fn civil_days(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m as i64 + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn parse_http_date(value: &str, now: SystemTime) -> Option<Duration> {
    let fields: Vec<_> = value.trim().split_ascii_whitespace().collect();
    if fields.len() != 6 || !fields[0].ends_with(',') || fields[5] != "GMT" { return None; }
    if !["Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,", "Sun,"].contains(&fields[0]) { return None; }
    let day = fields[1].parse::<u32>().ok()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        .iter().position(|v| *v == fields[2])? as u32 + 1;
    let year = fields[3].parse::<i64>().ok()?;
    if !(1970..=9999).contains(&year) { return None; }
    let ts: Vec<_> = fields[4].split(':').collect();
    if ts.len() != 3 { return None; }
    let (h, min, sec) = (ts[0].parse::<u32>().ok()?, ts[1].parse::<u32>().ok()?, ts[2].parse::<u32>().ok()?);
    if h > 23 || min > 59 || sec > 59 || day == 0 || day > 31 { return None; }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month { 2 => if leap { 29 } else { 28 }, 4 | 6 | 9 | 11 => 30, _ => 31 };
    if day > max_day { return None; }
    let timestamp = civil_days(year, month, day).checked_mul(86400)?
        .checked_add((h * 3600 + min * 60 + sec) as i64)?;
    let deadline = UNIX_EPOCH.checked_add(Duration::from_secs(timestamp.try_into().ok()?))?;
    Some(deadline.duration_since(now).unwrap_or(Duration::ZERO))
}

pub fn retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?.trim();
    let duration = if let Ok(seconds) = value.parse::<u64>() {
        Duration::from_secs(seconds)
    } else { parse_http_date(value, SystemTime::now())? };
    Some(duration.min(Duration::from_millis(MAX_SERVER_WAIT_MS)))
}

// Structured transient error marker consumed only by the worker retry loop.
pub fn transient(reason: impl AsRef<str>, retry_after: Option<Duration>) -> String {
    format!("[retry:{}] {}", retry_after.unwrap_or(Duration::ZERO).as_millis().min(MAX_SERVER_WAIT_MS as u128), reason.as_ref())
}

pub fn retry_delay(error: &str, attempt: usize) -> Option<Duration> {
    let rest = error.strip_prefix("[retry:")?;
    let (minimum, _) = rest.split_once(']')?;
    let floor = minimum.parse::<u64>().ok()?.min(MAX_SERVER_WAIT_MS);
    let ceiling = (350_u64.saturating_mul(1_u64 << attempt.min(7))).min(20_000);
    let jitter = rand::random::<u64>() % (ceiling + 1);
    Some(Duration::from_millis(floor.max(jitter)))
}

pub async fn wait(delay: Duration, rx: &mut watch::Receiver<Directive>) -> Result<(), String> {
    check(rx)?;
    tokio::select! {
        _ = tokio::time::sleep(delay) => check(rx),
        state = interrupted(rx) => Err(state.error().into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_after_http_dates_and_seconds() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT", UNIX_EPOCH + Duration::from_secs(784111777)), Some(Duration::ZERO));
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:47 GMT", UNIX_EPOCH + Duration::from_secs(784111777)), Some(Duration::from_secs(10)));
        assert!(parse_http_date("Sun, 31 Feb 2026 08:49:37 GMT", SystemTime::now()).is_none());
        assert!(retry_delay(&transient("HTTP 429", Some(Duration::from_secs(10))), 0).unwrap() >= Duration::from_secs(10));
    }
    #[tokio::test]
    async fn pause_interrupts_backoff() {
        let (tx, mut rx) = watch::channel(Directive::Running);
        tx.send_replace(Directive::Paused);
        assert!(wait(Duration::from_secs(20), &mut rx).await.is_err());
    }
}
