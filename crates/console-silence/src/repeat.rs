//! 重复行折叠：不依赖具体文本的刷屏抑制。
//!
//! 模组作者能改自己的脚本，改不掉引擎或别的脚本打进控制台的那一行；而在拿到
//! 确切文本之前，"按前缀吞"就无从下手。这一层用**同一行在窗口内重复出现**作为
//! 判据：只有完全相同的一行在 `window_ms` 内出现到第 `min_repeats` 次才折叠，
//! 不同文本、低频信息一律不动。
//!
//! 监督线程定期把折叠计数写入插件日志。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// 参与判重的槽位数（同时跟踪的最多不同行数）。
const SLOTS: usize = 8;

struct Slot {
    hash: AtomicU64,
    count: AtomicU32,
    stamp_ms: AtomicU64,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            hash: AtomicU64::new(0),
            count: AtomicU32::new(0),
            stamp_ms: AtomicU64::new(0),
        }
    }
}

static TABLE: [Slot; SLOTS] = [
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
];
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// 折叠策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// 开关。
    pub enabled: bool,
    /// 判重窗口（毫秒）。
    pub window_ms: u64,
    /// 窗口内出现到第几次开始折叠（1 = 从第二条起折叠）。
    pub min_repeats: u32,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            enabled: true,
            window_ms: 1000,
            min_repeats: 3,
        }
    }
}

/// 当前策略（配置热重载写、钩子读）。
static POLICY: AtomicU64 = AtomicU64::new(0);
/// 折叠默认**关闭**：ASI 出厂不该替任何人决定哪些行是噪音。
static POLICY_MIN: AtomicU32 = AtomicU32::new(3);
static POLICY_WINDOW: AtomicU64 = AtomicU64::new(1000);

/// 开/关重复行折叠。
pub fn set_enabled(enabled: bool) {
    POLICY.store(u64::from(enabled), Ordering::Relaxed);
}

/// 读当前策略。
#[must_use]
pub fn policy() -> Policy {
    Policy {
        enabled: POLICY.load(Ordering::Relaxed) != 0,
        window_ms: POLICY_WINDOW.load(Ordering::Relaxed),
        min_repeats: POLICY_MIN.load(Ordering::Relaxed),
    }
}

/// 折叠计数（汇总行与状态文件用）。
#[must_use]
pub fn suppressed() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

/// 裁决一行：`true` = 这一行属于重复刷屏，折叠掉。
///
/// 判据是 FNV-1a 哈希 + 窗口内计数。槽位竞争只可能让某一行**多**放行一次，
/// 不会误吞不同文本，也不会让钩子卡住。
pub fn should_suppress(text: &[u8], now_ms: u64) -> bool {
    let policy = policy();
    if !policy.enabled {
        return false;
    }
    let hash = fnv1a(text);
    if hash == 0 {
        return false;
    }
    let mut victim: Option<usize> = None;
    let mut oldest = (u64::MAX, 0usize);
    for (index, slot) in TABLE.iter().enumerate() {
        let slot_hash = slot.hash.load(Ordering::Relaxed);
        let stamp = slot.stamp_ms.load(Ordering::Relaxed);
        if slot_hash == hash && now_ms.saturating_sub(stamp) <= policy.window_ms {
            let count = slot.count.fetch_add(1, Ordering::Relaxed) + 1;
            slot.stamp_ms.store(now_ms, Ordering::Relaxed);
            if count >= policy.min_repeats {
                SUPPRESSED.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            return false;
        }
        if stamp < oldest.0 {
            oldest = (stamp, index);
        }
        if slot_hash == 0 && victim.is_none() {
            victim = Some(index);
        }
    }
    let index = victim.unwrap_or(oldest.1);
    let slot = &TABLE[index];
    slot.hash.store(hash, Ordering::Relaxed);
    slot.count.store(1, Ordering::Relaxed);
    slot.stamp_ms.store(now_ms, Ordering::Relaxed);
    false
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPolicy {
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for TestPolicy {
        fn drop(&mut self) {
            set_enabled(false);
            POLICY_WINDOW.store(1000, Ordering::Relaxed);
            POLICY_MIN.store(3, Ordering::Relaxed);
        }
    }

    fn test_set_policy(policy: Policy) -> TestPolicy {
        let serial = crate::filter::serial();
        set_enabled(policy.enabled);
        POLICY_WINDOW.store(policy.window_ms, Ordering::Relaxed);
        POLICY_MIN.store(policy.min_repeats, Ordering::Relaxed);
        for slot in &TABLE {
            slot.hash.store(0, Ordering::Relaxed);
            slot.count.store(0, Ordering::Relaxed);
            slot.stamp_ms.store(0, Ordering::Relaxed);
        }
        SUPPRESSED.store(0, Ordering::Relaxed);
        TestPolicy { _serial: serial }
    }

    #[test]
    fn identical_lines_collapse_only_after_the_threshold() {
        let _policy = test_set_policy(Policy::default());
        assert!(!should_suppress(b"spam", 100));
        assert!(!should_suppress(b"spam", 110));
        assert!(
            should_suppress(b"spam", 120),
            "third repeat in window folds"
        );
        assert!(should_suppress(b"spam", 130));
        assert_eq!(suppressed(), 2);
    }

    #[test]
    fn different_lines_do_not_interfere() {
        let _policy = test_set_policy(Policy::default());
        assert!(!should_suppress(b"alpha", 0));
        assert!(!should_suppress(b"beta", 1));
        assert!(!should_suppress(b"alpha", 2));
        assert!(!should_suppress(b"beta", 3));
        assert_eq!(suppressed(), 0);
    }

    #[test]
    fn the_window_expiry_restarts_the_count() {
        let _policy = test_set_policy(Policy::default());
        assert!(!should_suppress(b"spam", 0));
        assert!(!should_suppress(b"spam", 2000));
        assert!(
            !should_suppress(b"spam", 2100),
            "count restarted after the window"
        );
        assert!(should_suppress(b"spam", 2200));
    }

    #[test]
    fn disabled_policy_never_suppresses() {
        let _policy = test_set_policy(Policy {
            enabled: false,
            ..Policy::default()
        });
        for tick in 0..10 {
            assert!(!should_suppress(b"spam", tick));
        }
        assert_eq!(suppressed(), 0);
    }

    #[test]
    fn summary_policy_reports_the_configured_values() {
        let _policy = test_set_policy(Policy {
            enabled: true,
            window_ms: 250,
            min_repeats: 5,
        });
        let policy = policy();
        assert_eq!(policy.window_ms, 250);
        assert_eq!(policy.min_repeats, 5);
    }
}
