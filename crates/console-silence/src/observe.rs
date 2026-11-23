//! The print hook copies text into a bounded queue. The supervisor writes the log.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use crossbeam_queue::ArrayQueue;

const LINE_BYTES: usize = 4096;
const QUEUE_LINES: usize = 512;
static QUEUE: OnceLock<ArrayQueue<Line>> = OnceLock::new();
static REMAINING: AtomicUsize = AtomicUsize::new(8 * 1024 * 1024);
static SKIPPED: AtomicUsize = AtomicUsize::new(0);

struct Line {
    bytes: [u8; LINE_BYTES],
    len: usize,
    truncated: bool,
}

pub fn init() {
    QUEUE.get_or_init(|| ArrayQueue::new(QUEUE_LINES));
}

pub fn record(text: &[u8]) {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return;
    }
    let Some(queue) = QUEUE.get() else {
        return;
    };
    let len = text.len().min(LINE_BYTES);
    let mut line = Line {
        bytes: [0; LINE_BYTES],
        len,
        truncated: text.len() > len,
    };
    line.bytes[..len].copy_from_slice(&text[..len]);
    if queue.push(line).is_err() {
        SKIPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn flush() {
    let Some(queue) = QUEUE.get() else {
        return;
    };
    // Bound each batch even when the producer is flooding continuously.
    for _ in 0..QUEUE_LINES {
        let Some(line) = queue.pop() else {
            break;
        };
        if REMAINING.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let text = String::from_utf8_lossy(&line.bytes[..line.len]);
        let suffix = if line.truncated { " [truncated]" } else { "" };
        kcd1_abi::log::debug_bounded(format_args!("console: {text}{suffix}"), &REMAINING);
    }
    let skipped = SKIPPED.swap(0, Ordering::Relaxed);
    if skipped != 0 {
        kcd1_abi::log::debug_bounded(
            format_args!("observe queue full: skipped {skipped} console line(s)"),
            &REMAINING,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        filter,
        rules::{Action, MatchKind, Rule, Rules},
    };
    use std::sync::Arc;

    #[test]
    fn records_suppressed_lines_and_command_echoes() {
        let _serial = filter::serial();
        init();
        let queue = QUEUE.get().expect("observation queue");
        let rule =
            Rule::new(9, MatchKind::Contains, Action::Drop, "spam", None).expect("valid rule");
        filter::publish(Rules {
            observe: true,
            rules: vec![Arc::new(rule)],
            ..Rules::default()
        });
        assert_eq!(filter::decide(b"spam output"), filter::Outcome::Drop(9));
        assert!(filter::matches_command(b"spam command"));
        for text in [b"spam output".as_slice(), b"spam command"] {
            let line = queue.pop().expect("queued");
            assert_eq!(&line.bytes[..line.len], text);
        }
        filter::publish(Rules::default());
    }
}
