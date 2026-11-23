//! 行匹配规则（纯逻辑，无 FFI、可离线单测）。
//!
//! 一条规则回答一个问题：**这一行要不要吞**。识别方式从便宜到贵：
//!
//! | kind | 匹配方式 | 代价 |
//! |---|---|---|
//! | `contains` / `prefix` / `suffix` / `equals` | 字面比较（大小写不敏感） | 零分配字节扫描 |
//! | `wildcard` | `*`（任意串）`?`（任意单字符），其余字符按**字面量**处理 | 建规则时翻译成正则 |
//! | `regex` | 完整正则（大小写不敏感、线性时间） | 建规则时编译一次 |
//!
//! 通配与正则在注册时构造确定性自动机，匹配时只读取转换表。
//!
//! 动作有两种：
//! - [`Action::Drop`]：命中即吞，完全不出现在控制台；
//! - [`Action::Throttle`]：命中后按窗口放行，窗口内其余丢弃——用于"确实要让用户看见
//!   一次，但不要每 16 ms 一次"的告警类刷屏（例如"chart 加载失败"）。

use regex_automata::{
    dfa::{dense, Automaton},
    util::syntax,
    Input,
};
use std::sync::Arc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// 规则 id 分配器：cfg 与 Lua 共用同一个空间，id 稳定（删掉别人不会改变它）。
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// 取一个新的规则 id。
pub fn next_id() -> u32 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// `last_pass_ms` 的初值：从没放行过。
const NEVER: u64 = u64::MAX;

/// 命中后怎么处理。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// 直接丢弃。
    Drop,
    /// 每个窗口只放行第一条。
    Throttle {
        /// 放行窗口（毫秒）。
        window_ms: u64,
    },
}

impl Action {
    /// 配置里的写法（`drop` / `throttle:<ms>`）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Action> {
        let text = text.trim().to_ascii_lowercase();
        if text == "drop" {
            return Some(Action::Drop);
        }
        let window_ms = text.strip_prefix("throttle:")?.parse::<u64>().ok()?;
        (window_ms > 0).then_some(Action::Throttle { window_ms })
    }

    /// 反过来写成文本（状态文件 / `List()` 用）。
    #[must_use]
    pub fn as_text(&self) -> String {
        match self {
            Action::Drop => "drop".to_string(),
            Action::Throttle { window_ms } => format!("throttle:{window_ms}"),
        }
    }
}

/// 匹配方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// 子串。
    Contains,
    /// 前缀。
    Prefix,
    /// 后缀。
    Suffix,
    /// 整行相等。
    Equals,
    /// `*` / `?` 通配，其余字符字面量。
    Wildcard,
    /// 完整正则（大小写不敏感）。
    Regex,
}

impl MatchKind {
    /// 配置里的写法。
    #[must_use]
    pub fn parse(text: &str) -> Option<MatchKind> {
        match text.trim().to_ascii_lowercase().as_str() {
            "contains" => Some(MatchKind::Contains),
            "prefix" => Some(MatchKind::Prefix),
            "suffix" => Some(MatchKind::Suffix),
            "equals" | "equal" => Some(MatchKind::Equals),
            "wildcard" | "glob" => Some(MatchKind::Wildcard),
            "regex" | "regexp" => Some(MatchKind::Regex),
            _ => None,
        }
    }

    /// 反过来写成文本。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MatchKind::Contains => "contains",
            MatchKind::Prefix => "prefix",
            MatchKind::Suffix => "suffix",
            MatchKind::Equals => "equals",
            MatchKind::Wildcard => "wildcard",
            MatchKind::Regex => "regex",
        }
    }
}

/// 编译好的匹配器：字面量走字节比较，通配/正则走自动机。
#[derive(Debug)]
enum Matcher {
    Contains(Vec<u8>),
    Prefix(Vec<u8>),
    Suffix(Vec<u8>),
    Equals(Vec<u8>),
    Compiled(Box<dense::DFA<Vec<u32>>>),
}

/// 一条规则。
#[derive(Debug)]
pub struct Rule {
    id: u32,
    action: Action,
    matcher: Matcher,
    label: String,
    deadline: Option<u64>,
    hits: AtomicU64,
    last_pass_ms: AtomicU64,
}

impl Rule {
    /// 构造一条规则；通配/正则在**这里**编译一次，失败返回人话原因。
    ///
    /// id 用 [`next_id`] 取。
    pub fn new(
        id: u32,
        kind: MatchKind,
        action: Action,
        pattern: &str,
        label: Option<&str>,
    ) -> Result<Rule, String> {
        if pattern.is_empty() {
            return Err("empty pattern".to_string());
        }
        let matcher = match kind {
            MatchKind::Contains => Matcher::Contains(pattern.as_bytes().to_vec()),
            MatchKind::Prefix => Matcher::Prefix(pattern.as_bytes().to_vec()),
            MatchKind::Suffix => Matcher::Suffix(pattern.as_bytes().to_vec()),
            MatchKind::Equals => Matcher::Equals(pattern.as_bytes().to_vec()),
            MatchKind::Wildcard => Matcher::Compiled(compile(&wildcard_to_regex(pattern))?),
            MatchKind::Regex => Matcher::Compiled(compile(pattern)?),
        };
        Ok(Rule {
            id,
            action,
            matcher,
            label: label.map_or_else(|| pattern.to_string(), str::to_string),
            deadline: None,
            hits: AtomicU64::new(0),
            last_pass_ms: AtomicU64::new(NEVER),
        })
    }

    /// 稳定句柄。
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 命中次数。
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn set_deadline(&mut self, deadline: Option<u64>) {
        self.deadline = deadline;
    }

    fn expired(&self, now_ms: u64) -> bool {
        self.deadline.is_some_and(|deadline| now_ms >= deadline)
    }

    /// 这一行是否命中本规则（只看 `line` 的前 `scan_limit` 字节）。
    fn matches(&self, line: &[u8]) -> bool {
        match &self.matcher {
            Matcher::Contains(needle) => contains_ci(line, needle),
            Matcher::Prefix(needle) => {
                line.len() >= needle.len() && eq_ci(&line[..needle.len()], needle)
            }
            Matcher::Suffix(needle) => {
                line.len() >= needle.len() && eq_ci(&line[line.len() - needle.len()..], needle)
            }
            Matcher::Equals(needle) => line.len() == needle.len() && eq_ci(line, needle),
            Matcher::Compiled(regex) => regex
                .try_search_fwd(&Input::new(line).earliest(true))
                .is_ok_and(|matched| matched.is_some()),
        }
    }

    fn would_drop(&self, now_ms: u64) -> bool {
        match self.action {
            Action::Drop => true,
            Action::Throttle { window_ms } => {
                let last = self.last_pass_ms.load(Ordering::Relaxed);
                last != NEVER && now_ms.saturating_sub(last) < window_ms
            }
        }
    }

    /// 规则给出裁决：记录命中，并为窗口内的首行保留放行位置。
    fn verdict(&self, now_ms: u64) -> bool {
        self.hits.fetch_add(1, Ordering::Relaxed);
        let Action::Throttle { window_ms } = self.action else {
            return true;
        };
        self.last_pass_ms
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                (last == NEVER || now_ms.saturating_sub(last) >= window_ms).then_some(now_ms)
            })
            .is_err()
    }
}

/// 把 `*` / `?` 通配翻译成正则，其余字符一律转义——所以 `[ERVWHDO LUT Guard]`
/// 这种"看着像正则"的写法在通配里就是字面量。这是通配相对正则的关键好处。
fn wildcard_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 8);
    out.push_str("(?s)^");
    for ch in pattern.chars() {
        match ch {
            '*' => out.push_str("(?u:.*)"),
            '?' => out.push_str("(?u:.)"),
            other => {
                if regex_syntax::is_meta_character(other) {
                    out.push('\\');
                }
                out.push(other);
            }
        }
    }
    out.push('$');
    out
}

fn compile(pattern: &str) -> Result<Box<dense::DFA<Vec<u32>>>, String> {
    const SIZE_LIMIT: usize = 1 << 20;
    dense::Builder::new()
        .configure(
            dense::Config::new()
                .dfa_size_limit(Some(SIZE_LIMIT))
                .determinize_size_limit(Some(SIZE_LIMIT)),
        )
        .syntax(
            syntax::Config::new()
                .case_insensitive(true)
                .unicode(false)
                .utf8(false),
        )
        .thompson(regex_automata::nfa::thompson::Config::new().utf8(false))
        .build(pattern)
        .map(Box::new)
        .map_err(|error| format!("bad pattern: {error}"))
}

/// 整套规则 + 全局开关（配置热重载 / Lua 修改时整体替换）。
#[derive(Debug)]
pub struct Rules {
    /// 总开关（关掉 = 钩子仍然在，但一行都不吞）。
    pub enabled: bool,
    /// 观察模式：把每一行进出的行都写进日志（定位"到底哪一行在刷"用）。
    pub observe: bool,
    /// 只看每行的前 N 字节（引擎行有上限；把比较成本钉死）。
    pub scan_limit: usize,
    /// 规则表（按顺序，第一条命中即定案）。
    pub rules: Vec<Arc<Rule>>,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            enabled: true,
            observe: false,
            scan_limit: 512,
            rules: Vec::new(),
        }
    }
}

impl Rules {
    /// 裁决一行：只执行第一条匹配规则的动作。
    pub fn decide(&self, line: &[u8], now_ms: u64) -> Option<(&Rule, bool)> {
        let rule = self.match_only(line, now_ms)?;
        Some((rule, rule.verdict(now_ms)))
    }

    /// 查询第一条匹配规则此刻是否会吞掉该行。
    pub fn which(&self, line: &[u8], now_ms: u64) -> Option<&Rule> {
        self.match_only(line, now_ms)
            .filter(|rule| rule.would_drop(now_ms))
    }

    /// 只匹配，不改任何状态。
    pub fn match_only(&self, line: &[u8], now_ms: u64) -> Option<&Rule> {
        if !self.enabled {
            return None;
        }
        let window = &line[..line.len().min(self.scan_limit)];
        self.rules
            .iter()
            .map(Arc::as_ref)
            .find(|rule| !rule.expired(now_ms) && rule.matches(window))
    }

    pub fn active_count(&self, now_ms: u64) -> usize {
        self.rules
            .iter()
            .filter(|rule| !rule.expired(now_ms))
            .count()
    }

    /// 所有生效规则的命中计数快照（状态文件用）。
    pub fn hits(&self, now_ms: u64) -> Vec<(u32, String, u64)> {
        self.rules
            .iter()
            .filter(|rule| !rule.expired(now_ms))
            .map(|rule| (rule.id, rule.label.clone(), rule.hits()))
            .collect()
    }
}

fn eq_ci(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: MatchKind, action: Action, pattern: &str) -> Arc<Rule> {
        Arc::new(Rule::new(next_id(), kind, action, pattern, None).expect("valid rule"))
    }

    fn decide_index(set: &Rules, line: &[u8], now_ms: u64) -> Option<usize> {
        let (rule, drop) = set.decide(line, now_ms)?;
        drop.then(|| {
            set.rules
                .iter()
                .position(|entry| entry.id() == rule.id())
                .unwrap()
        })
    }

    fn rules(kind: MatchKind, action: Action, pattern: &str) -> Rules {
        Rules {
            rules: vec![rule(kind, action, pattern)],
            ..Rules::default()
        }
    }

    #[test]
    fn contains_is_case_insensitive() {
        let set = rules(
            MatchKind::Contains,
            Action::Drop,
            "r_colorgradingchartimage",
        );
        assert_eq!(
            decide_index(&set, b"Setting R_ColorGradingChartImage to x", 0),
            Some(0)
        );
        assert_eq!(decide_index(&set, b"Loading level", 0), None);
    }

    #[test]
    fn prefix_and_equals_are_distinct() {
        let prefix = rules(MatchKind::Prefix, Action::Drop, "$4[ERVWHDO");
        assert_eq!(decide_index(&prefix, b"$4[ERVWHDO LUT] x", 0), Some(0));
        assert_eq!(decide_index(&prefix, b" x $4[ERVWHDO", 0), None);

        let equals = rules(MatchKind::Equals, Action::Drop, "abc");
        assert_eq!(decide_index(&equals, b"ABC", 0), Some(0));
        assert_eq!(decide_index(&equals, b"ABCD", 0), None);
    }

    #[test]
    fn suffix_matches_tail_only() {
        let set = rules(MatchKind::Suffix, Action::Drop, "chart image");
        assert_eq!(
            decide_index(&set, b"r_ColorGradingChartImage chart image", 0),
            Some(0)
        );
        assert_eq!(decide_index(&set, b"chart image loaded", 0), None);
    }

    #[test]
    fn first_matching_rule_wins() {
        let set = Rules {
            rules: vec![
                rule(
                    MatchKind::Contains,
                    Action::Throttle { window_ms: 100 },
                    "keep",
                ),
                rule(MatchKind::Contains, Action::Drop, "keep me"),
            ],
            ..Rules::default()
        };
        assert!(set.which(b"keep me", 30).is_none());
        assert_eq!(decide_index(&set, b"keep me", 30), None);
        assert_eq!(
            set.which(b"keep me", 31).map(Rule::id),
            Some(set.rules[0].id())
        );
        assert_eq!(decide_index(&set, b"keep me", 31), Some(0));
        assert!(set.which(b"keep me", 130).is_none());
        assert_eq!(set.rules[0].hits(), 2);
        assert_eq!(set.rules[1].hits(), 0);
    }

    #[test]
    fn disabled_rules_pass_everything() {
        let set = Rules {
            enabled: false,
            rules: vec![rule(MatchKind::Contains, Action::Drop, "x")],
            ..Rules::default()
        };
        assert_eq!(decide_index(&set, b"xxx", 0), None);
        assert_eq!(set.rules[0].hits(), 0);
    }

    #[test]
    fn throttle_passes_one_line_per_window() {
        let set = rules(
            MatchKind::Contains,
            Action::Throttle { window_ms: 1000 },
            "spam",
        );
        assert_eq!(decide_index(&set, b"spam 1", 0), None);
        assert_eq!(decide_index(&set, b"spam 2", 10), Some(0));
        assert_eq!(decide_index(&set, b"spam 3", 999), Some(0));
        assert_eq!(decide_index(&set, b"spam 4", 1000), None);
        assert_eq!(set.rules[0].hits(), 4);
    }

    #[test]
    fn scan_limit_bounds_the_inspected_prefix() {
        let set = Rules {
            scan_limit: 8,
            rules: vec![rule(MatchKind::Contains, Action::Drop, "needle")],
            ..Rules::default()
        };
        assert_eq!(
            decide_index(&set, b"0123456789needle", 0),
            None,
            "a pattern that only occurs past scan_limit must not match"
        );
        assert_eq!(decide_index(&set, b"needle 0123456789", 0), Some(0));
    }

    #[test]
    fn empty_pattern_is_rejected() {
        assert!(Rule::new(next_id(), MatchKind::Contains, Action::Drop, "", None).is_err());
    }

    #[test]
    fn wildcard_treats_brackets_as_literals() {
        // 关键用例：`[ERVWHDO LUT Guard]` 在正则里是字符类，在通配里必须是字面量。
        let set = rules(MatchKind::Wildcard, Action::Drop, "[ERVWHDO LUT Guard]*");
        assert_eq!(
            decide_index(&set, b"[ERVWHDO LUT Guard] stopped", 0),
            Some(0)
        );
        assert_eq!(decide_index(&set, b"E stopped", 0), None);
    }

    #[test]
    fn wildcard_question_mark_matches_one_character() {
        let set = rules(MatchKind::Wildcard, Action::Drop, "a?c");
        assert_eq!(decide_index(&set, b"abc", 0), Some(0));
        assert_eq!(decide_index(&set, b"ac", 0), None);
        assert_eq!(decide_index(&set, b"abbc", 0), None);
    }

    #[test]
    fn regex_matches_with_case_insensitivity() {
        let set = rules(MatchKind::Regex, Action::Drop, r"chart.*\.dds$");
        assert_eq!(
            decide_index(&set, b"r_ColorGradingChartImage DATA//x/3.A24.DDS", 0),
            Some(0)
        );
        assert_eq!(decide_index(&set, b"nothing here", 0), None);
    }

    #[test]
    fn invalid_regex_is_rejected_with_a_reason() {
        let error = Rule::new(next_id(), MatchKind::Regex, Action::Drop, "([", None).unwrap_err();
        assert!(error.contains("bad pattern"), "got: {error}");
    }

    #[test]
    fn regex_and_wildcard_fold_ascii_only() {
        for (kind, pattern) in [(MatchKind::Regex, "Ča"), (MatchKind::Wildcard, "Ča?")] {
            let set = rules(kind, Action::Drop, pattern);
            assert!(set.decide("ČAé".as_bytes(), 0).is_some());
            assert!(set.decide("čAé".as_bytes(), 0).is_none());
        }
    }

    #[test]
    fn expired_rule_is_ignored_before_cleanup() {
        let mut first = Rule::new(next_id(), MatchKind::Contains, Action::Drop, "spam", None)
            .expect("valid rule");
        first.set_deadline(Some(100));
        let set = Rules {
            rules: vec![Arc::new(first)],
            ..Rules::default()
        };
        assert!(set.match_only(b"spam", 99).is_some());
        assert!(set.match_only(b"spam", 100).is_none());
        assert!(set.decide(b"spam", 100).is_none());
        assert!(set.which(b"spam", 100).is_none());
    }
}
