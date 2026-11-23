//! 普通文本经 IConsole::PrintLine 槽位，命令回显直接调用其实现。
//! 回显在写入行缓冲时按命令匹配，ExecuteString 负责原本的命令执行及日志。

use core::ffi::{c_char, c_void, CStr};
use core::sync::atomic::{AtomicUsize, Ordering};

use std::sync::Mutex;

use kcd1_abi::{hook::EntryDetour, log, mem, module::Module};

use crate::filter;

/// `WHGame.dll` 的模块名（`GetModuleHandle` 不区分大小写）。
pub const GAME_MODULE: &str = "WHGame.DLL";
/// `IConsole::PrintLine` 的 vtable 下标。
pub const PRINT_LINE_SLOT: usize = 26;
// BuildID 22623230: GetStatus reads this byte.
const CONSOLE_OPEN_OFFSET: usize = 476;
const CONSOLE_VTABLE_RVA: usize = 0x0269_68c8;

// Steam BuildID 22623230。三处命令回显直接调用 PrintLine 的实现。
const PRINT_LINE_BODY_RVA: usize = 0x0040_e3c8;
const PRINT_LINE_ENTRY: [u8; 8] = [0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x74];
const ECHO_CALL_SITES: [usize; 3] = [0x00ec_6c6e, 0x00ec_6b12, 0x00ec_7017];

/// 引擎侧 `void IConsole::PrintLine(const char*)`。
type PrintLineFn = unsafe extern "system" fn(*mut c_void, *const c_char);

/// 钩子状态机。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// 还没装（等 `pConsole` 出现）。
    Pending,
    /// 普通文本与命令回显钩子都已安装。
    Installed,
    /// 装过但槽位被别人改回去了（下一轮监督重装）。
    Lost,
    /// 装了也没用（模块/槽位校验失败），不再重试。
    Failed,
}

static STATE: AtomicUsize = AtomicUsize::new(0);
static PRINT_LINE_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static PRINT_LINE_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static ECHO_DETOUR: Mutex<Option<EntryDetour>> = Mutex::new(None);
static ECHO_MODULE_BASE: AtomicUsize = AtomicUsize::new(0);
static PRINT_LINE_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);

fn state_from_raw(raw: usize) -> State {
    match raw {
        1 => State::Installed,
        2 => State::Lost,
        3 => State::Failed,
        _ => State::Pending,
    }
}

fn store(state: State) {
    let raw = match state {
        State::Pending => 0,
        State::Installed => 1,
        State::Lost => 2,
        State::Failed => 3,
    };
    STATE.store(raw, Ordering::SeqCst);
}

/// 当前钩子状态。
#[must_use]
pub fn state() -> State {
    state_from_raw(STATE.load(Ordering::SeqCst))
}

/// 原 `PrintLine` 地址（0 = 未知）。
#[must_use]
pub fn original() -> usize {
    PRINT_LINE_ORIGINAL.load(Ordering::SeqCst)
}

/// 普通命令回显调用点（0 = 尚未装回显钩子）。
#[must_use]
pub fn command_echo_site() -> usize {
    match ECHO_MODULE_BASE.load(Ordering::Acquire) {
        0 => 0,
        base => base + ECHO_CALL_SITES[0],
    }
}

/// 当前 `PrintLine` 槽位里的地址（诊断用）。
#[must_use]
pub fn current_slot() -> usize {
    let address = PRINT_LINE_ADDRESS.load(Ordering::SeqCst);
    if address == 0 {
        return 0;
    }
    mem::read_pointer(address).unwrap_or(0)
}

/// 已定位好的控制台对象。
#[derive(Clone, Copy, Debug)]
pub struct Console {
    /// `IConsole` 对象地址。
    pub object: usize,
    /// `PrintLine` 槽位地址。
    pub print_line_slot: usize,
    /// WHGame.dll 基址。
    pub module_base: usize,
}

/// 从 `gEnv` 读 `pConsole` 并解析出文本槽位。
///
/// 任何一步读不到或看起来不像就返回 `None`（不猜地址）。
#[must_use]
pub fn locate(env: *mut c_void) -> Option<Console> {
    let env_address = env as usize;
    if env_address == 0 {
        return None;
    }
    let console = mem::read_pointer(env_address + kcd1_abi::env::CONSOLE_OFFSET)?;
    if console == 0 {
        return None;
    }
    let vtable = mem::read_pointer(console)?;
    let game = Module::named(GAME_MODULE)?;
    if vtable != game.base().get() + CONSOLE_VTABLE_RVA {
        return None;
    }
    let print_line_slot = vtable + PRINT_LINE_SLOT * core::mem::size_of::<usize>();
    let target = mem::read_pointer(print_line_slot)?;
    if !game.contains(target) && target != print_line_hook_address() {
        log::warn(&format!(
            "PrintLine slot 0x{print_line_slot:X} points outside {GAME_MODULE} (0x{target:X})"
        ));
        return None;
    }
    Some(Console {
        object: console,
        print_line_slot,
        module_base: game.base().get(),
    })
}

/// 装钩子。幂等：已经指向本钩子时直接成功。
pub fn install(console: &Console) -> Result<(), &'static str> {
    let mut missing = 0;
    if mem::read_pointer(console.print_line_slot) != Some(print_line_hook_address()) {
        missing += 1;
        let original =
            mem::read_pointer(console.print_line_slot).ok_or("unreadable PrintLine slot")?;
        PRINT_LINE_ORIGINAL.store(original, Ordering::SeqCst);
        if original == 0 || !mem::write_pointer(console.print_line_slot, print_line_hook_address())
        {
            return Err("writing the PrintLine slot failed");
        }
        PRINT_LINE_ADDRESS.store(console.print_line_slot, Ordering::SeqCst);
        log::info(&format!(
            "PrintLine hooked: console=0x{:X} slot=0x{:X} original=0x{:X} hook=0x{:X}",
            console.object,
            console.print_line_slot,
            original,
            print_line_hook_address()
        ));
    }
    if !echo_installed() {
        missing += 1;
        install_echo(console.module_base)?;
        log::info(&format!(
            "Command echo hooked: call=0x{:X}",
            command_echo_site()
        ));
    }
    store(State::Installed);
    if missing > 0 {
        crate::status::count_install();
    }
    Ok(())
}

fn install_echo(base: usize) -> Result<(), &'static str> {
    let mut active = ECHO_DETOUR.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(detour) = active.as_ref() {
        return detour
            .reinstall()
            .then_some(())
            .ok_or("command echo target changed");
    }
    for site in ECHO_CALL_SITES {
        let displacement = (PRINT_LINE_BODY_RVA as i32) - (site as i32 + 5);
        let mut call = [0xe8; 5];
        call[1..].copy_from_slice(&displacement.to_le_bytes());
        let mut actual = [0; 5];
        if !mem::read_bytes(base + site, &mut actual) || actual != call {
            return Err("unexpected command echo call");
        }
    }
    ECHO_MODULE_BASE.store(base, Ordering::Release);
    // SAFETY: 调用点已确认是支持版本的 PrintLine。入口第一条指令为
    // mov [rsp+0x10],rbx，可原样搬移。处理器与入口签名一致。
    let result = unsafe {
        EntryDetour::install(
            base + PRINT_LINE_BODY_RVA,
            PRINT_LINE_ENTRY,
            print_line_body_hook as *const () as usize,
            &PRINT_LINE_TRAMPOLINE,
        )
    };
    match result {
        Ok(detour) => {
            *active = Some(detour);
            Ok(())
        }
        Err(error) => {
            ECHO_MODULE_BASE.store(0, Ordering::Release);
            Err(error)
        }
    }
}

fn echo_installed() -> bool {
    ECHO_DETOUR
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_ref()
        .is_some_and(EntryDetour::is_installed)
}

/// 检查普通文本和命令回显钩子。
pub fn verify(console: &Console) -> bool {
    let print_line_ok =
        mem::read_pointer(console.print_line_slot) == Some(print_line_hook_address());
    let echo_ok = echo_installed();
    if print_line_ok && echo_ok {
        store(State::Installed);
        return true;
    }
    if state() == State::Installed {
        log::warn(&format!(
            "console hook lost (PrintLine ok={print_line_ok}, command echo ok={echo_ok}); reinstalling"
        ));
        crate::status::count_rearm();
    }
    store(State::Lost);
    false
}

/// 恢复原函数。调用方已停止引擎线程。
pub fn restore() {
    let slot = PRINT_LINE_ADDRESS.load(Ordering::SeqCst);
    let original = PRINT_LINE_ORIGINAL.load(Ordering::SeqCst);
    if slot != 0 && original != 0 && mem::read_pointer(slot) == Some(print_line_hook_address()) {
        if mem::write_pointer(slot, original) {
            log::info("PrintLine slot restored to the engine function");
        } else {
            log::error("PrintLine slot restore failed");
        }
    }
    if let Some(detour) = ECHO_DETOUR
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .take()
    {
        // SAFETY: 调用方已停止引擎，跳板不再执行。
        if unsafe { detour.restore() } {
            ECHO_MODULE_BASE.store(0, Ordering::Release);
        } else {
            log::error("command echo hook restore failed");
        }
    }
    store(State::Pending);
}

/// 读取当前对象的显示标志，用于状态文件。
pub fn console_open(environment: *mut c_void) -> bool {
    let Some(object) = mem::read_pointer(environment as usize + kcd1_abi::env::CONSOLE_OFFSET)
        .filter(|&object| object != 0)
    else {
        return false;
    };
    mem::read_u8(object + CONSOLE_OPEN_OFFSET).is_some_and(|flag| flag != 0)
}

/// `PrintLine` 钩子地址（函数项到整数的转换只在这里发生）。
fn print_line_hook_address() -> usize {
    print_line_hook as *const () as usize
}

/// 去掉结尾的 CR/LF：引擎传进来的文本常带换行，而它自己入缓冲前也会裁掉
/// （`RE_FINDINGS` §2.2）。不裁的话 `equals` 规则永远匹配不上。
fn trim_line(bytes: &[u8]) -> &[u8] {
    match bytes
        .iter()
        .rposition(|byte| *byte != b'\n' && *byte != b'\r')
    {
        Some(last) => &bytes[..=last],
        None => bytes,
    }
}

/// 引擎每打一行控制台文本就走这里。
///
/// 引擎传入 NUL 结尾文本。
unsafe extern "system" fn print_line_hook(this: *mut c_void, text: *const c_char) {
    let original = PRINT_LINE_ORIGINAL.load(Ordering::SeqCst);
    // 钩子自己必须兜住 panic：`guard::catch` 只包了 FFI 入口，panic 从
    // `extern "system"` 逸出会直接 abort 进程。兜住之后一律 fail-open（放行这一行）。
    let swallow = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if text.is_null() {
            return false;
        }
        // SAFETY: 引擎按 `const char*` 传行文本，调用方保证 NUL 结尾。
        let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
        !matches!(filter::decide(trim_line(bytes)), filter::Outcome::Pass)
    }))
    .unwrap_or(false);
    if swallow || original == 0 {
        return;
    }
    // SAFETY: `original` 是安装时从同一槽位读出的引擎函数地址，签名一致。
    let forward: PrintLineFn = unsafe { core::mem::transmute(original) };
    // SAFETY: 转发是原样调用引擎函数：`this`/`text` 就是本钩子收到的实参，
    // 签名与安装时读出的槽位值一致（`void(*)(IConsole*, const char*)`）。
    unsafe { forward(this, text) };
}

// Win64 的第三个参数在 r8。传入调用者的返回地址以识别命令回显，
// 尾跳保留原有的栈、前两个参数和返回地址。
#[unsafe(naked)]
unsafe extern "system" fn print_line_body_hook(_this: *mut c_void, _text: *const c_char) {
    core::arch::naked_asm!("mov r8, [rsp]", "jmp {}", sym dispatch_print_line);
}

unsafe extern "system" fn dispatch_print_line(
    this: *mut c_void,
    text: *const c_char,
    caller: usize,
) {
    let base = ECHO_MODULE_BASE.load(Ordering::Acquire);
    if base != 0 && ECHO_CALL_SITES.iter().any(|site| caller == base + site + 5) && !text.is_null()
    {
        let suppressed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: PrintLine 接收调用者持有的 NUL 结尾文本。
            let bytes = trim_line(unsafe { CStr::from_ptr(text) }.to_bytes());
            filter::matches_command(bytes)
        }))
        .unwrap_or(false);
        if suppressed {
            crate::status::count_command_silenced();
            return;
        }
    }
    let trampoline = PRINT_LINE_TRAMPOLINE.load(Ordering::Acquire);
    // SAFETY: 入口补丁生效前已发布同签名的原函数跳板。
    let forward: PrintLineFn = unsafe { core::mem::transmute(trampoline) };
    // SAFETY: 对象和文本与引擎调用 PrintLine 时的参数一致。
    unsafe { forward(this, text) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Action, MatchKind, Rule, Rules};

    core::arch::global_asm!(
        ".globl test_command_echo",
        ".globl test_command_echo_return",
        ".seh_proc test_command_echo",
        "test_command_echo:",
        "sub rsp, 0x28",
        ".seh_stackalloc 0x28",
        ".seh_endprologue",
        "call {hook}",
        "test_command_echo_return:",
        "add rsp, 0x28",
        "ret",
        ".seh_endproc",
        hook = sym print_line_body_hook,
    );

    extern "system" {
        fn test_command_echo(this: *mut c_void, text: *const c_char);
        fn test_command_echo_return();
    }

    unsafe extern "system" fn count_prints(this: *mut c_void, _text: *const c_char) {
        // SAFETY: The test passes a valid pointer to its local counter.
        unsafe { *this.cast::<usize>() += 1 };
    }

    #[test]
    fn only_matching_command_echoes_are_suppressed() {
        let _serial = filter::serial();
        let rule = Rule::new(1, MatchKind::Contains, Action::Drop, "lut", None).expect("rule");
        filter::publish(Rules {
            rules: vec![std::sync::Arc::new(rule)],
            ..Rules::default()
        });
        let echo = test_command_echo_return as *const () as usize;
        let base = echo - ECHO_CALL_SITES[0] - 5;
        ECHO_MODULE_BASE.store(base, Ordering::Release);
        PRINT_LINE_TRAMPOLINE.store(count_prints as *const () as usize, Ordering::Release);

        let mut prints = 0usize;
        let console = core::ptr::addr_of_mut!(prints).cast();
        // SAFETY: The forwarding stub and dispatch receive the same counter and NUL strings.
        unsafe {
            test_command_echo(console, c"set lut".as_ptr());
            test_command_echo(console, c"other command".as_ptr());
            dispatch_print_line(console, c"query result for lut".as_ptr(), echo + 1);
        }

        PRINT_LINE_TRAMPOLINE.store(0, Ordering::Release);
        ECHO_MODULE_BASE.store(0, Ordering::Release);
        filter::publish(Rules::default());
        assert_eq!(prints, 2);
    }
}
