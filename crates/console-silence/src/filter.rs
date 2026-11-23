//! 发布不可变规则快照。读侧以原子计数保护快照，监督线程回收退休快照。

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::rules::Rules;
use crate::status;
use crate::{observe, repeat};

/// 当前快照（`null` = 还没发布过）。
static LIVE: AtomicPtr<Rules> = AtomicPtr::new(core::ptr::null_mut());
/// 正在读快照的线程数（含钩子）。
static READERS: AtomicUsize = AtomicUsize::new(0);
/// 等待回收的旧快照。
///
/// 裸指针默认不是 `Send`；这里包一层并**用纪律**保证线程安全：队列只在 [`publish`]
/// （持锁 push）与 [`collect_retired`]（持锁 drain，且已确认 `READERS == 0`）里出现，
/// 指针本身从不跨线程解引用。
struct Retired(Vec<*mut Rules>);
// SAFETY: 见 `Retired` 的文档——指针只在上述两处持锁访问，且释放前确认无读者。
unsafe impl Send for Retired {}

static RETIRED: Mutex<Retired> = Mutex::new(Retired(Vec::new()));

/// 进程内单调毫秒（throttle 与 TTL 都用它）。
#[must_use]
pub fn now_ms() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

struct ReaderGuard;

impl ReaderGuard {
    fn new() -> ReaderGuard {
        READERS.fetch_add(1, Ordering::SeqCst);
        ReaderGuard
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        // unwind 也要减：否则一次 panic 会让退休队列永远不回收。
        READERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 发布一份新快照；旧快照进退休队列（由 [`collect_retired`] 释放）。
pub fn publish(rules: Rules) {
    let boxed = Box::into_raw(Box::new(rules));
    // SAFETY: `boxed` 刚由 `Box::into_raw` 产出，指向有效的 `Rules`。
    let previous = LIVE.swap(boxed, Ordering::SeqCst);
    if !previous.is_null() {
        RETIRED
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .0
            .push(previous);
    }
}

/// 释放已退休的快照；只在"此刻没有读者"时动手。返回释放了几份（监督线程调用）。
pub fn collect_retired() -> usize {
    let retired: Vec<*mut Rules> = {
        let mut guard = RETIRED.lock().unwrap_or_else(|err| err.into_inner());
        // 锁定本批旧指针再查读者。SeqCst 将计数和当前指针的操作排在同一顺序中：
        // 此后进入的读者只能取到当前指针，无法取得这批旧指针。
        if guard.0.is_empty() || READERS.load(Ordering::SeqCst) != 0 {
            return 0;
        }
        std::mem::take(&mut guard.0)
    };
    let count = retired.len();
    for pointer in retired {
        // SAFETY: 指针来自 `publish` 的 `Box::into_raw`，且刚刚确认没有读者；
        // 每份只在这里释放一次（drain 已经把它从队列里拿走）。
        drop(unsafe { Box::from_raw(pointer) });
    }
    count
}

fn with_snapshot<R>(f: impl FnOnce(&Rules) -> R) -> Option<R> {
    let _reader = ReaderGuard::new();
    let pointer = LIVE.load(Ordering::SeqCst);
    if pointer.is_null() {
        return None;
    }
    // SAFETY: 指针由 `publish` 发布；读者守卫在读取期间阻止它被回收。
    Some(f(unsafe { &*pointer }))
}

/// 一行的裁决结果。
///
/// 三态是必要的：**"被折叠"与"放行"都不是"命中规则"**，但它们对钩子的处置完全相反。
/// 用一个返回值同时表达它们，会让折叠计数增长而行仍然打进控制台。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 放行。
    Pass,
    /// 被某条规则吞掉；带规则 id。
    Drop(u32),
    /// 被"重复行折叠"吞掉（不属于任何一条规则）。
    Fold,
}

/// 裁决一行，并记计数。
///
pub fn decide(text: &[u8]) -> Outcome {
    let now = now_ms();
    let outcome = with_snapshot(|rules| {
        if rules.observe {
            observe::record(text);
        }
        if let Some((rule, drop)) = rules.decide(text, now) {
            return if drop {
                Outcome::Drop(rule.id())
            } else {
                Outcome::Pass
            };
        }
        if rules.enabled && repeat::should_suppress(text, now) {
            return Outcome::Fold;
        }
        Outcome::Pass
    })
    .unwrap_or(Outcome::Pass);
    match outcome {
        Outcome::Drop(_) => status::count_dropped(),
        Outcome::Fold => status::count_folded(),
        Outcome::Pass => status::count_passed(),
    }
    outcome
}

/// 控制台**命令**是否命中规则（只匹配，不改任何状态）。
///
/// 回显匹配独立于节流窗口和规则命中计数。
#[must_use]
pub fn matches_command(text: &[u8]) -> bool {
    let now = now_ms();
    with_snapshot(|rules| {
        if rules.observe {
            observe::record(text);
        }
        rules.match_only(text, now).is_some()
    })
    .unwrap_or(false)
}

/// 查询会吞掉这一行的规则，不更新节流状态或命中计数。
#[must_use]
pub fn which(text: &[u8]) -> Option<u32> {
    let now = now_ms();
    with_snapshot(|rules| rules.which(text, now).map(crate::rules::Rule::id)).flatten()
}

/// 当前规则面。
#[must_use]
pub fn shape() -> (bool, bool, usize) {
    let now = now_ms();
    with_snapshot(|rules| (rules.enabled, rules.observe, rules.active_count(now)))
        .unwrap_or((true, false, 0))
}

/// 每条生效规则的命中数（状态文件用）。
#[must_use]
pub fn rule_hits() -> Vec<(u32, String, u64)> {
    let now = now_ms();
    with_snapshot(|rules| rules.hits(now)).unwrap_or_default()
}

/// 隔离使用进程级快照、折叠表和计数器的单测。
#[cfg(test)]
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Action, MatchKind, Rule};
    use std::sync::Arc;

    fn install(pattern: &str) -> u32 {
        let rule = Rule::new(
            crate::rules::next_id(),
            MatchKind::Contains,
            Action::Drop,
            pattern,
            None,
        )
        .expect("valid rule");
        let id = rule.id();
        publish(Rules {
            rules: vec![Arc::new(rule)],
            ..Rules::default()
        });
        id
    }

    #[test]
    fn decide_reports_the_rule_and_commands_match_without_state() {
        let _serial = serial();
        let id = install("spam");
        assert_eq!(decide(b"xx spam yy"), Outcome::Drop(id));
        assert_eq!(decide(b"clean line"), Outcome::Pass);
        let before = rule_hits()[0].2;
        assert!(matches_command(b"spam"));
        assert_eq!(which(b"spam"), Some(id));
        assert_eq!(
            rule_hits()[0].2,
            before,
            "commands/which must not bump hits"
        );
    }

    #[test]
    fn retired_snapshots_are_reclaimed_when_no_readers() {
        let _serial = serial();
        for pattern in ["a", "b", "c"] {
            install(pattern);
        }
        assert!(collect_retired() >= 2);
        assert_eq!(collect_retired(), 0, "queue is empty now");
    }

    #[test]
    fn retired_snapshot_stays_live_while_a_reader_holds_it() {
        let _serial = serial();
        let id = install("held");
        with_snapshot(|rules| {
            install("current");
            assert_eq!(collect_retired(), 0);
            assert_eq!(rules.rules[0].id(), id);
        });
        assert!(collect_retired() >= 1);
    }

    #[test]
    fn first_matching_throttle_can_pass_a_line_even_with_folding_enabled() {
        let _serial = serial();
        publish(Rules::default());
        repeat::set_enabled(true);
        let text = b"repeated throttle regression";
        assert_eq!(decide(text), Outcome::Pass);
        assert_eq!(decide(text), Outcome::Pass);
        assert_eq!(decide(text), Outcome::Fold);
        let rule = Rule::new(
            crate::rules::next_id(),
            MatchKind::Contains,
            Action::Throttle { window_ms: 5000 },
            "repeated throttle regression",
            None,
        )
        .expect("valid throttle");
        let id = rule.id();
        publish(Rules {
            rules: vec![Arc::new(rule)],
            ..Rules::default()
        });
        assert_eq!(decide(text), Outcome::Pass);
        assert_eq!(decide(text), Outcome::Drop(id));
        repeat::set_enabled(false);
    }

    #[test]
    fn disabled_snapshot_passes_everything() {
        let _serial = serial();
        publish(Rules {
            enabled: false,
            rules: vec![Arc::new(
                Rule::new(
                    crate::rules::next_id(),
                    MatchKind::Contains,
                    Action::Drop,
                    "x",
                    None,
                )
                .expect("valid"),
            )],
            ..Rules::default()
        });
        repeat::set_enabled(true);
        for _ in 0..5 {
            assert_eq!(decide(b"xxx"), Outcome::Pass);
        }
        repeat::set_enabled(false);
        assert!(!matches_command(b"xxx"));
    }
}
