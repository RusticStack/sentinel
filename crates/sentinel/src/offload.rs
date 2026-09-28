//! The controller's optional external S3 copy (R02/R03): the `sentinel_s3`
//! client adapted to the store's [`Bucket`] and read-through [`Remote`]
//! seams, and the replicator's thread.

use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use sentinel_s3::{Client, Error as S3Error};
use sentinel_store::{
    objects::Remote,
    replicate::{Bucket, BucketError, BucketResult, Replicator},
};

/// Pages one listing walks at most (1,000 keys or uploads each).
const MAX_LIST_PAGES: usize = 16;
/// The pause between passes with nothing to do.
const IDLE: Duration = Duration::from_secs(5);
/// The longest back-off after failures.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

pub struct S3Bucket {
    client: Client,
}

impl S3Bucket {
    pub fn new(client: Client) -> Self {
        S3Bucket { client }
    }
    pub fn client(&self) -> &Client {
        &self.client
    }
    /// A key relative to the prefix, back from a full one.
    fn relative<'a>(&self, full: &'a str) -> Option<&'a str> {
        full.strip_prefix(self.client.config().prefix.as_str())
    }
}

fn map(error: S3Error) -> BucketError {
    BucketError {
        transient: error.is_transient(),
        not_found: matches!(error, S3Error::NotFound(_)),
        message: error.to_string(),
    }
}

fn metadata(blake3: Option<&str>) -> Vec<(&str, &str)> {
    blake3.map(|b| ("blake3", b)).into_iter().collect()
}

/// `2026-09-28T12:00:00.000Z` as Unix milliseconds; `None` when it is not
/// that shape.
pub fn iso_ms(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| text.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400) + hh * 3_600 + mm * 60 + ss) * 1_000)
}

impl Bucket for S3Bucket {
    fn put(&self, key: &str, body: &[u8], blake3: Option<&str>) -> BucketResult<()> {
        self.client
            .put_object(&self.client.key(key), body, &metadata(blake3))
            .map(|_| ())
            .map_err(map)
    }
    fn create_multipart(&self, key: &str, blake3: Option<&str>) -> BucketResult<String> {
        self.client
            .create_multipart(&self.client.key(key), &metadata(blake3))
            .map_err(map)
    }
    fn upload_part(
        &self,
        key: &str,
        upload: &str,
        number: u32,
        body: &[u8],
    ) -> BucketResult<String> {
        self.client
            .upload_part(&self.client.key(key), upload, number, body)
            .map_err(map)
    }
    fn list_parts(&self, key: &str, upload: &str) -> BucketResult<Vec<(u32, String, u64)>> {
        self.client
            .list_parts(&self.client.key(key), upload)
            .map(|parts| {
                parts
                    .into_iter()
                    .map(|p| (p.number, p.etag, p.len))
                    .collect()
            })
            .map_err(map)
    }
    fn complete(&self, key: &str, upload: &str, parts: &[(u32, String)]) -> BucketResult<()> {
        let parts: Vec<sentinel_s3::Part> = parts
            .iter()
            .map(|(number, etag)| sentinel_s3::Part {
                number: *number,
                etag: etag.clone(),
                len: 0,
            })
            .collect();
        self.client
            .complete_multipart(&self.client.key(key), upload, &parts)
            .map(|_| ())
            .map_err(map)
    }
    fn abort(&self, key: &str, upload: &str) -> BucketResult<()> {
        self.client
            .abort_multipart(&self.client.key(key), upload)
            .map_err(map)
    }
    fn head(&self, key: &str) -> BucketResult<Option<(u64, Option<String>)>> {
        self.client
            .head_object(&self.client.key(key))
            .map(|h| h.map(|h| (h.len, h.meta("blake3").map(str::to_owned))))
            .map_err(map)
    }
    fn get(&self, key: &str, out: &mut dyn Write) -> BucketResult<u64> {
        let (len, mut reader) = self
            .client
            .get_object(&self.client.key(key), None)
            .map_err(map)?;
        let copied = std::io::copy(&mut reader, out).map_err(|e| BucketError {
            transient: true,
            not_found: false,
            message: format!("S3 read: {}", e.kind()),
        })?;
        if copied != len {
            return Err(BucketError {
                transient: true,
                not_found: false,
                message: "S3 read ended short".into(),
            });
        }
        Ok(copied)
    }
    fn delete(&self, key: &str) -> BucketResult<()> {
        self.client
            .delete_object(&self.client.key(key))
            .map_err(map)
    }
    fn list(&self, prefix: &str) -> BucketResult<Vec<String>> {
        let full = self.client.key(prefix);
        let mut keys = Vec::new();
        let mut next: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let page = self
                .client
                .list_objects(&full, next.as_deref())
                .map_err(map)?;
            keys.extend(
                page.objects
                    .iter()
                    .filter_map(|(k, _)| self.relative(k).map(str::to_owned)),
            );
            match page.next {
                Some(token) => next = Some(token),
                None => break,
            }
        }
        Ok(keys)
    }
    fn list_uploads(&self) -> BucketResult<Vec<(String, String, Option<i64>)>> {
        let prefix = self.client.config().prefix.clone();
        let mut out = Vec::new();
        let mut after: Option<(String, String)> = None;
        for _ in 0..MAX_LIST_PAGES {
            let (uploads, next) = self
                .client
                .list_multipart_uploads(
                    &prefix,
                    after.as_ref().map(|(k, u)| (k.as_str(), u.as_str())),
                )
                .map_err(map)?;
            out.extend(uploads.into_iter().filter_map(|u| {
                Some((
                    self.relative(&u.key)?.to_owned(),
                    u.upload_id,
                    iso_ms(&u.initiated),
                ))
            }));
            match next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(out)
    }
}

impl Remote for S3Bucket {
    fn fetch(&self, key: &str, out: &mut dyn Write) -> sentinel_store::Result<u64> {
        self.get(key, out)
            .map_err(|e| sentinel_store::Error::Io(std::io::Error::other(e.message)))
    }
}

/// The replicator's thread: a pass, then at once again while there is more
/// to do, every [`IDLE`] when there is not, and backing off (1 s doubling
/// to [`MAX_BACKOFF`]) while passes fail. Degraded and recovered moments
/// are logged once each.
pub struct Running {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Running {
    pub fn start(replicator: Replicator) -> std::io::Result<Running> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let thread = std::thread::Builder::new()
            .name("sentinel-s3-replicator".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || run(&replicator, &stopped));
            })?;
        Ok(Running {
            stop,
            thread: Some(thread),
        })
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn sleep(stop: &AtomicBool, total: Duration) {
    let step = Duration::from_millis(100);
    let mut slept = Duration::ZERO;
    while slept < total && !stop.load(Ordering::Acquire) {
        std::thread::sleep(step);
        slept += step;
    }
}

fn run(replicator: &Replicator, stop: &AtomicBool) {
    let status = replicator.status();
    let mut backoff = Duration::from_secs(1);
    let mut degraded = false;
    while !stop.load(Ordering::Acquire) {
        match replicator.pass() {
            Ok(pass) => {
                backoff = Duration::from_secs(1);
                if degraded && !status.backlog_full.load(Ordering::Relaxed) {
                    degraded = false;
                    tracing::info!(
                        event = "s3_recovered",
                        backlog_bytes = status.backlog_bytes.load(Ordering::Relaxed)
                    );
                }
                if !pass.more {
                    sleep(stop, IDLE);
                }
            }
            Err(why) => {
                if !degraded {
                    degraded = true;
                    tracing::warn!(event = "s3_degraded", reason = %why, backlog_bytes = status.backlog_bytes.load(Ordering::Relaxed), "the external copy is behind; local copies are kept until it catches up");
                }
                sleep(stop, backoff);
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
        if status.backlog_full.load(Ordering::Relaxed) && !degraded {
            degraded = true;
            tracing::warn!(
                event = "s3_degraded",
                reason = "backlog past its budget",
                backlog_bytes = status.backlog_bytes.load(Ordering::Relaxed),
                "new artifacts and uploads are refused until the external copy catches up"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::iso_ms;

    #[test]
    fn upload_initiation_times_parse_as_s3_writes_them() {
        assert_eq!(iso_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(iso_ms("2013-05-24T00:00:00.000Z"), Some(1_369_353_600_000));
        assert_eq!(iso_ms("2000-02-29T12:34:56Z"), Some(951_827_696_000));
        assert_eq!(iso_ms("yesterday"), None);
        assert_eq!(iso_ms("2026-13-01T00:00:00Z"), None);
    }
}
