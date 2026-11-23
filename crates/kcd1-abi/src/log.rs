//! 文件日志（跟随 DLL 所在目录）与日志目录单一来源。
//!
//! 只写文件：写引擎控制台在控制台处于"标记"选择模式时会阻塞调用线程
//! ，所以后台线程永远不碰控制台。

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

static LOG_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();
static LOG_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

fn file_slot() -> &'static Mutex<Option<File>> {
    LOG_FILE.get_or_init(|| Mutex::new(None))
}

/// 初始化日志文件（幂等；失败静默——日志是尽力而为）。
pub fn init(path: PathBuf) {
    if let Some(parent) = path.parent() {
        let _ = LOG_DIRECTORY.set(parent.to_path_buf());
    }
    let mut handle = file_slot().lock().unwrap_or_else(|err| err.into_inner());
    if handle.is_some() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
        *handle = Some(file);
    }
}

/// 日志/命令通道目录（DLL 所在目录；未初始化 = `None`）。
pub fn directory() -> Option<&'static PathBuf> {
    LOG_DIRECTORY.get()
}

fn write_line(level: &str, message: &str) {
    let line = format_line(level, format_args!("{message}"));
    let mut handle = file_slot().lock().unwrap_or_else(|err| err.into_inner());
    if let Some(file) = handle.as_mut() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

fn format_line(level: &str, message: fmt::Arguments<'_>) -> String {
    format!("[{level}] {message}\n")
}

/// Writes a debug record only if it fits in the remaining byte budget, including its prefix
/// and newline. Uses the log file lock to share the budget between concurrent callers.
pub fn debug_bounded(message: fmt::Arguments<'_>, remaining: &AtomicUsize) {
    if remaining.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut handle = file_slot().lock().unwrap_or_else(|err| err.into_inner());
    if let Some(file) = handle.as_mut() {
        write_bounded(file, message, remaining);
    }
}

fn write_bounded(file: &mut impl Write, message: fmt::Arguments<'_>, remaining: &AtomicUsize) {
    let available = remaining.load(Ordering::Relaxed);
    if available == 0 {
        return;
    }
    let line = format_line("DEBUG", message);
    let Some(left) = available.checked_sub(line.len()) else {
        remaining.store(0, Ordering::Relaxed);
        return;
    };
    let result = file.write_all(line.as_bytes()).and_then(|()| file.flush());
    remaining.store(if result.is_ok() { left } else { 0 }, Ordering::Relaxed);
}

/// INFO 级。
pub fn info(message: &str) {
    write_line("INFO", message);
}

/// DEBUG 级。
pub fn debug(message: &str) {
    write_line("DEBUG", message);
}

/// WARN 级。
pub fn warn(message: &str) {
    write_line("WARN", message);
}

/// ERROR 级。
pub fn error(message: &str) {
    write_line("ERROR", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_log_counts_utf8_prefix_and_newline() {
        let mut output = Vec::new();
        let remaining = AtomicUsize::new(23);
        write_bounded(&mut output, format_args!("é"), &remaining);
        assert_eq!(remaining.load(Ordering::Relaxed), 12);
        write_bounded(&mut output, format_args!("abc"), &remaining);
        assert_eq!(remaining.load(Ordering::Relaxed), 0);
        write_bounded(&mut output, format_args!("one more"), &remaining);
        assert_eq!(output, "[DEBUG] é\n[DEBUG] abc\n".as_bytes());
    }

    #[test]
    fn bounded_log_stops_before_writing_an_oversized_record() {
        let mut output = Vec::new();
        let remaining = AtomicUsize::new(10);
        write_bounded(&mut output, format_args!("é"), &remaining);
        write_bounded(&mut output, format_args!("x"), &remaining);
        assert!(output.is_empty());
        assert_eq!(remaining.load(Ordering::Relaxed), 0);
    }
}
