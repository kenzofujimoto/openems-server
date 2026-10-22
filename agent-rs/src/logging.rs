//! Timestamped logs to stderr (interactive) or a rotating file (service).

use crate::error::Result;
use crate::runtime::Logger;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 2 * 1024 * 1024;
const BACKUPS: u32 = 3;

/// UTC timestamp in RFC 3339 form without external time crates.
pub fn timestamp(now: SystemTime) -> String {
    let seconds = now.duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs()) as i64;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant), valid for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

pub fn stderr_logger() -> Logger {
    Arc::new(|message: &str| eprintln!("{} {message}", timestamp(SystemTime::now())))
}

struct RotatingFile {
    path: PathBuf,
    file: File,
}

impl RotatingFile {
    fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(RotatingFile { path: path.to_path_buf(), file })
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        if self.file.metadata()?.len() < MAX_BYTES {
            return Ok(());
        }
        for index in (1..BACKUPS).rev() {
            let _ = fs::rename(
                self.path.with_extension(format!("log.{index}")),
                self.path.with_extension(format!("log.{}", index + 1)),
            );
        }
        fs::rename(&self.path, self.path.with_extension("log.1"))?;
        self.file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        Ok(())
    }
}

/// File logger for the service. A failed write is surfaced on stderr instead of being dropped.
pub fn file_logger(path: &Path) -> Result<Logger> {
    let target = Mutex::new(RotatingFile::open(path)?);
    Ok(Arc::new(move |message: &str| {
        let mut target = target.lock().unwrap_or_else(|poison| poison.into_inner());
        let line = format!("{} {message}\n", timestamp(SystemTime::now()));
        if target.rotate_if_needed().and_then(|()| Ok(target.file.write_all(line.as_bytes())?)).is_err() {
            eprintln!("log unavailable; message withheld");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_secs(1_792_674_000)), "2026-10-22T13:00:00Z");
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn file_logger_appends_and_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        fs::write(&path, vec![b'x'; MAX_BYTES as usize]).unwrap();
        let log = file_logger(&path).unwrap();
        log("after rotation");
        assert!(fs::read_to_string(&path).unwrap().ends_with("after rotation\n"));
        assert_eq!(fs::metadata(path.with_extension("log.1")).unwrap().len(), MAX_BYTES);
    }
}
