//! x86-64 inline hook 与指针补丁。
//!
//! 机制：从目标入口偷 `STEAL`（默认 7）个字节到可执行跳板，入口改成
//! `E9` 跳到**近块**（在目标 ±2 GB 内新分配），近块用绝对间接跳转进入本 crate
//! 的静态存根；存根保存参数寄存器、调用 Rust 处理器、然后尾跳进跳板（同样在
//! 近块内），跳板重放被偷指令并 `E9` 回 `entry+steal`，原函数照常执行。
//!
//! 可达性是硬约束：`E9` 只能表达 rel32。本 crate 的静态存根随 DLL 加载在任意
//! 地址——DLL 与游戏模块相距可超过 2 GB（实测一次注入相距 3.87 GB，入口直接
//! `E9` 到存根会让位移截断、游戏跳到垃圾地址 NX 崩溃），因此入口与回跳一律只
//! 指向近块；近块与静态存根之间走绝对寻址。安装前逐项校验可达性，越界即
//! fail-closed 拒绝安装。
//!
//! 契约（§6.4/§5.7）：
//! - 每个补丁都记录原始字节，[`HookGuard`] 或 [`restore_all`] 可以逐字节恢复；
//! - 每个存根对应一个补丁；入口字节必须能原样搬到跳板。

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use iced_x86::{Decoder, DecoderOptions, OpKind};

use crate::log;
use crate::win::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT_RESERVE, MEM_RELEASE,
    PAGE_EXECUTE_READWRITE,
};

/// 3 参数处理器（rcx/rdx/r8）。
pub type Handler3 = extern "system" fn(usize, usize, usize);
/// 4 参数处理器（rcx/rdx/r8/r9）。
pub type Handler4 = extern "system" fn(usize, usize, usize, usize);

/// 窃取字节数：等号入口前两条指令是 3 + 4 字节，正好可整取。
pub const STEAL: usize = 7;

// 存根经这些槽位间接调用已安装的处理器。
static HANDLER3: AtomicUsize = AtomicUsize::new(0);
static HANDLER4: AtomicUsize = AtomicUsize::new(0);
static HANDLER4B: AtomicUsize = AtomicUsize::new(0);
static HANDLER_EQ: AtomicUsize = AtomicUsize::new(0);
static HANDLER_SAVE: AtomicUsize = AtomicUsize::new(0);

// 跳板地址（0 = 未安装）。
static TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static TRAMPOLINE4: AtomicUsize = AtomicUsize::new(0);
static TRAMPOLINE4B: AtomicUsize = AtomicUsize::new(0);
static TRAMPOLINE_EQ: AtomicUsize = AtomicUsize::new(0);
static TRAMPOLINE_SAVE: AtomicUsize = AtomicUsize::new(0);

core::arch::global_asm!(
    ".globl kcd2_hook_stub3",
    ".p2align 4",
    "kcd2_hook_stub3:",
    "push rcx",
    "push rdx",
    "push r8",
    "push r9",
    "sub rsp, 0x28",
    "mov rcx, [rsp+0x40]",
    "mov rdx, [rsp+0x38]",
    "mov r8, [rsp+0x30]",
    "lea rax, [rip + {handler}]",
    "mov rax, [rax]",
    "call rax",
    "add rsp, 0x28",
    "pop r9",
    "pop r8",
    "pop rdx",
    "pop rcx",
    "jmp qword ptr [rip + {tramp}]",
    handler = sym HANDLER3,
    tramp = sym TRAMPOLINE,
);

core::arch::global_asm!(
    ".globl kcd2_hook_stub4",
    ".p2align 4",
    "kcd2_hook_stub4:",
    "push rcx",
    "push rdx",
    "push r8",
    "push r9",
    "sub rsp, 0x28",
    "mov rcx, [rsp+0x40]",
    "mov rdx, [rsp+0x38]",
    "mov r8, [rsp+0x30]",
    "mov r9, [rsp+0x28]",
    "lea rax, [rip + {handler}]",
    "mov rax, [rax]",
    "call rax",
    "add rsp, 0x28",
    "pop r9",
    "pop r8",
    "pop rdx",
    "pop rcx",
    "jmp qword ptr [rip + {tramp}]",
    handler = sym HANDLER4,
    tramp = sym TRAMPOLINE4,
);

// 第二个独立的 4 参数存根：一次探针可以同时观察两个引擎函数。
core::arch::global_asm!(
    ".globl kcd2_hook_stub4b",
    ".p2align 4",
    "kcd2_hook_stub4b:",
    "push rcx",
    "push rdx",
    "push r8",
    "push r9",
    "sub rsp, 0x28",
    "mov rcx, [rsp+0x40]",
    "mov rdx, [rsp+0x38]",
    "mov r8, [rsp+0x30]",
    "mov r9, [rsp+0x28]",
    "lea rax, [rip + {handler}]",
    "mov rax, [rax]",
    "call rax",
    "add rsp, 0x28",
    "pop r9",
    "pop r8",
    "pop rdx",
    "pop rcx",
    "jmp qword ptr [rip + {tramp}]",
    handler = sym HANDLER4B,
    tramp = sym TRAMPOLINE4B,
);

// 存档观察存根（产品持久化专用槽位）：处理器读存档记录的 SaveId 与 playline。
core::arch::global_asm!(
    ".globl kcd2_hook_stub_save",
    ".p2align 4",
    "kcd2_hook_stub_save:",
    "push rcx",
    "push rdx",
    "push r8",
    "push r9",
    "sub rsp, 0x28",
    "mov rcx, [rsp+0x40]",
    "mov rdx, [rsp+0x38]",
    "mov r8, [rsp+0x30]",
    "mov r9, [rsp+0x28]",
    "lea rax, [rip + {handler}]",
    "mov rax, [rax]",
    "call rax",
    "add rsp, 0x28",
    "pop r9",
    "pop r8",
    "pop rdx",
    "pop rcx",
    "jmp qword ptr [rip + {tramp}]",
    handler = sym HANDLER_SAVE,
    tramp = sym TRAMPOLINE_SAVE,
);

// worker 追踪存根：额外捕获调用者的返回地址（原 `[rsp]`），
// 这样一份 golden sample 能回答"是哪个引擎函数发起了这次 equip/unequip"。
core::arch::global_asm!(
    ".globl kcd2_hook_stub_eq",
    ".p2align 4",
    "kcd2_hook_stub_eq:",
    "push rcx",
    "push rdx",
    "push r8",
    "push r9",
    "sub rsp, 0x28",
    "mov rcx, [rsp+0x40]",
    "mov rdx, [rsp+0x38]",
    "mov r8, [rsp+0x30]",
    "mov r9, [rsp+0x48]",
    "lea rax, [rip + {handler}]",
    "mov rax, [rax]",
    "call rax",
    "add rsp, 0x28",
    "pop r9",
    "pop r8",
    "pop rdx",
    "pop rcx",
    "jmp qword ptr [rip + {tramp}]",
    handler = sym HANDLER_EQ,
    tramp = sym TRAMPOLINE_EQ,
);

extern "C" {
    fn kcd2_hook_stub3();
    fn kcd2_hook_stub4();
    fn kcd2_hook_stub4b();
    fn kcd2_hook_stub_eq();
    fn kcd2_hook_stub_save();
}

/// 每个存根槽位。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StubKind {
    Three,
    Four,
    FourB,
    EquipWorker,
    SaveObserver,
}

struct PatchRecord {
    id: usize,
    kind: StubKind,
    entry: usize,
    length: usize,
    original: [u8; 15],
}

static NEXT_PATCH_ID: AtomicUsize = AtomicUsize::new(1);
static PATCHES: std::sync::Mutex<Vec<PatchRecord>> = std::sync::Mutex::new(Vec::new());
static TRAMPOLINES: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

fn handler_slot(kind: StubKind) -> &'static AtomicUsize {
    match kind {
        StubKind::Three => &HANDLER3,
        StubKind::Four => &HANDLER4,
        StubKind::FourB => &HANDLER4B,
        StubKind::EquipWorker => &HANDLER_EQ,
        StubKind::SaveObserver => &HANDLER_SAVE,
    }
}

/// 安装 3 参数追踪钩子。
///
/// # Safety
/// The caller must keep the function mapped and ensure it is idle during installation
/// and restoration. The copied span must contain whole, position-independent instructions.
pub unsafe fn install_trace3(entry: usize, handler: Handler3) -> Result<HookGuard, &'static str> {
    install_inner(
        entry,
        STEAL,
        kcd2_hook_stub3 as *const c_void,
        StubKind::Three,
        handler as usize,
    )
}

/// 安装可定制窃取长度的 4 参数追踪钩子（跳板回跳到 `entry + steal`，长度必须
/// 落在指令边界上；允许 5..=15）。
///
/// # Safety
/// 同 [`install_trace3`]（槽位 1）。
pub unsafe fn install_trace4(
    entry: usize,
    steal: usize,
    handler: Handler4,
) -> Result<HookGuard, &'static str> {
    install_inner(
        entry,
        steal,
        kcd2_hook_stub4 as *const c_void,
        StubKind::Four,
        handler as usize,
    )
}

/// 第二个 4 参数追踪槽（槽位 2）。
///
/// # Safety
/// 同 [`install_trace4`]。
pub unsafe fn install_trace4b(
    entry: usize,
    steal: usize,
    handler: Handler4,
) -> Result<HookGuard, &'static str> {
    install_inner(
        entry,
        steal,
        kcd2_hook_stub4b as *const c_void,
        StubKind::FourB,
        handler as usize,
    )
}

/// equip worker 追踪（槽位 3；处理器的第 4 个参数是调用者返回地址）。
///
/// # Safety
/// 同 [`install_trace4`]。
pub unsafe fn install_equip_trace(
    entry: usize,
    steal: usize,
    handler: Handler4,
) -> Result<HookGuard, &'static str> {
    install_inner(
        entry,
        steal,
        kcd2_hook_stub_eq as *const c_void,
        StubKind::EquipWorker,
        handler as usize,
    )
}

/// 安装存档观察钩子（槽位 4，产品持久化专用；与诊断槽位隔离）。
///
/// # Safety
/// 同 [`install_trace4`]：`entry` 必须是函数入口，`steal`（5..=15）落在指令边界上。
pub unsafe fn install_save_observer(
    entry: usize,
    steal: usize,
    handler: Handler4,
) -> Result<HookGuard, &'static str> {
    install_inner(
        entry,
        steal,
        kcd2_hook_stub_save as *const c_void,
        StubKind::SaveObserver,
        handler as usize,
    )
}

/// 已探针的目标 `(入口, 窃取长度)`（审计日志用）。
pub fn patched_sites() -> Vec<(usize, usize)> {
    let patches = PATCHES.lock().unwrap_or_else(|err| err.into_inner());
    patches
        .iter()
        .map(|record| (record.entry, record.length))
        .collect()
}

/// 恢复全部探针入口并释放跳板；返回人类可读的审计文本。
pub fn restore_all() -> String {
    let mut out = String::new();
    let mut patches = PATCHES.lock().unwrap_or_else(|err| err.into_inner());
    patches.retain(|record| match restore_entry(record) {
        Ok(message) => {
            out.push_str(&message);
            false
        }
        Err(message) => {
            out.push_str(&message);
            true
        }
    });
    if !patches.is_empty() {
        return out;
    }
    let trampolines: Vec<usize> = {
        let mut list = TRAMPOLINES.lock().unwrap_or_else(|err| err.into_inner());
        std::mem::take(&mut *list)
    };
    for trampoline in trampolines {
        // SAFETY: 跳板由 `VirtualAlloc` 分配、已不再被引用。
        unsafe { VirtualFree(trampoline as *mut c_void, 0, MEM_RELEASE) };
    }
    for slot in [
        &TRAMPOLINE,
        &TRAMPOLINE4,
        &TRAMPOLINE4B,
        &TRAMPOLINE_EQ,
        &TRAMPOLINE_SAVE,
    ] {
        slot.store(0, Ordering::SeqCst);
    }
    out
}

fn restore_entry(record: &PatchRecord) -> Result<String, String> {
    let mut old = 0u32;
    // SAFETY: 入口点来自已安装的补丁记录，长度 5..=15；恢复的是我们改写前的字节。
    let protect_ok = unsafe {
        VirtualProtect(
            record.entry as *mut c_void,
            record.length,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
    } != 0;
    if !protect_ok {
        return Err(format!(
            "FAILED to restore 0x{:X} (VirtualProtect)\n",
            record.entry
        ));
    }
    // SAFETY: 目标是本进程已加载代码页，`original` 是原字节副本。
    unsafe {
        core::ptr::copy_nonoverlapping(
            record.original.as_ptr(),
            record.entry as *mut u8,
            record.length,
        );
    }
    let mut restored = 0u32;
    // SAFETY: 恢复原保护属性。
    unsafe {
        VirtualProtect(
            record.entry as *mut c_void,
            record.length,
            old,
            &mut restored,
        );
    }
    crate::win::flush_code(record.entry, record.length);
    Ok(format!(
        "restored inline patch at 0x{:X} ({} bytes)\n",
        record.entry, record.length
    ))
}

/// 补丁的 RAII 句柄：`Drop` 时恢复入口（§5.7 把"忘记恢复"降级为不可发生）。
#[must_use = "drop 该句柄即恢复补丁；忘记持有等于补丁悬空"]
pub struct HookGuard {
    id: usize,
    entry: usize,
    armed: bool,
}

impl HookGuard {
    /// 被补丁的入口地址。
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }

    /// 显式恢复（等价于 `drop`，但返回审计文本）。
    #[must_use]
    pub fn restore(mut self) -> String {
        let text = self.restore_inner();
        self.armed = false;
        text
    }

    fn restore_inner(&mut self) -> String {
        let mut patches = PATCHES.lock().unwrap_or_else(|err| err.into_inner());
        let Some(index) = patches.iter().position(|record| record.id == self.id) else {
            return String::new();
        };
        match restore_entry(&patches[index]) {
            Ok(text) => {
                patches.remove(index);
                text
            }
            Err(text) => text,
        }
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            let _ = self.restore_inner();
        }
    }
}

/// 该入口是否已被 `E9` 补丁（另一个实例/上次注入）——重复挂钩会叠跳板。
///
/// # Safety
/// `entry` 必须指向已加载代码（调用方保证）。
#[must_use]
pub unsafe fn is_patched(entry: usize) -> bool {
    // SAFETY: 调用方保证 entry 是代码地址。
    unsafe { *(entry as *const u8) == 0xE9 }
}

/// rel32 相对跳转的安全窗（留余量；`E9` 实际极限是 ±2 GiB）。
const NEAR_LIMIT: usize = 0x7000_0000;

/// 编码 `E9 rel32`（从 `op` 跳到 `to`）；超出 rel32 可达范围返回 `None`。
///
/// fail-closed 的唯一入口：位移越界绝不允许截断成错误地址（历史上这样把游戏
/// 跳到过 0x7FFD7D8010C0 的 NX 页）。
fn encode_e9(op: usize, to: usize) -> Option<[u8; 5]> {
    let rel = to as i64 - (op as i64 + 5);
    let rel32 = i32::try_from(rel).ok()?;
    let mut bytes = [0u8; 5];
    bytes[0] = 0xE9;
    bytes[1..].copy_from_slice(&rel32.to_le_bytes());
    Some(bytes)
}

/// 编码近跳块：`jmp qword ptr [rip+0]` + 8 字节绝对目标（对任意距离可达）。
fn encode_indirect_jump(target: usize) -> [u8; 14] {
    let mut bytes = [0u8; 14];
    bytes[..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    bytes[6..].copy_from_slice(&(target as u64).to_le_bytes());
    bytes
}

/// 在离 `entry` ±[`NEAR_LIMIT`] 内分配一页可执行内存；找不到返回 `None`。
fn allocate_near(entry: usize) -> Option<*mut c_void> {
    let mut delta = 0x10000usize;
    while delta < NEAR_LIMIT {
        for candidate in [entry.wrapping_sub(delta), entry.wrapping_add(delta)] {
            // SAFETY: 申请一页可执行内存；失败返回 null。
            let allocated = unsafe {
                VirtualAlloc(
                    candidate as *mut c_void,
                    0x1000,
                    MEM_COMMIT_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if !allocated.is_null() {
                let distance = (allocated as i64 - entry as i64).unsigned_abs() as usize;
                if distance < NEAR_LIMIT {
                    return Some(allocated);
                }
                // SAFETY: 刚分配、未被引用。
                unsafe { VirtualFree(allocated, 0, MEM_RELEASE) };
            }
        }
        delta <<= 1;
    }
    None
}

/// 用一个对齐的 8 字节写入替换函数入口处的一条 5 字节指令。
#[must_use]
pub struct EntryDetour {
    entry: usize,
    original: u64,
    patched: u64,
    page: usize,
    trampoline: &'static AtomicUsize,
}

impl EntryDetour {
    /// 安装入口跳转，并在它生效前发布可调用的原函数跳板。
    ///
    /// # Safety
    /// `entry` 必须是已加载模块中 8 字节对齐的函数入口。`expected` 的前 5 字节须为
    /// 一条完整且可原样搬移的指令。`target` 的签名须与原函数相符，调用方独占 `trampoline`
    /// 并确保入口及跳转目标在补丁存续期间有效。
    pub unsafe fn install(
        entry: usize,
        expected: [u8; 8],
        target: usize,
        trampoline: &'static AtomicUsize,
    ) -> Result<Self, &'static str> {
        let original = u64::from_le_bytes(expected);
        if !entry.is_multiple_of(8) || crate::mem::read_u64(entry) != Some(original) {
            return Err("unexpected function entry");
        }
        validate_stolen_bytes(&expected[..5])?;
        let page = allocate_near(entry).ok_or("no near detour allocation")? as usize;
        let Some(jump) = encode_e9(entry, page) else {
            // SAFETY: 页刚分配，尚未发布。
            unsafe { VirtualFree(page as *mut c_void, 0, MEM_RELEASE) };
            return Err("detour out of rel32 range");
        };
        let resume = page + 16;
        let target_jump = encode_indirect_jump(target);
        let resume_jump = encode_indirect_jump(entry + 5);
        // SAFETY: 页是本函数刚分配的 RWX 页，各段互不重叠，写入范围在页内。
        unsafe {
            core::ptr::copy_nonoverlapping(
                target_jump.as_ptr(),
                page as *mut u8,
                target_jump.len(),
            );
            core::ptr::copy_nonoverlapping(expected.as_ptr(), resume as *mut u8, 5);
            core::ptr::copy_nonoverlapping(
                resume_jump.as_ptr(),
                (resume + 5) as *mut u8,
                resume_jump.len(),
            );
        }
        crate::win::flush_code(page, 16 + 5 + resume_jump.len());
        let mut patched = expected;
        patched[..5].copy_from_slice(&jump);
        let detour = Self {
            entry,
            original,
            patched: u64::from_le_bytes(patched),
            page,
            trampoline,
        };
        trampoline.store(resume, Ordering::Release);
        if !detour.reinstall() {
            trampoline.store(0, Ordering::Release);
            // SAFETY: 入口补丁未写入，新分配的页没有被游戏引用。
            unsafe { VirtualFree(page as *mut c_void, 0, MEM_RELEASE) };
            return Err("could not patch function entry");
        }
        Ok(detour)
    }

    /// 检查函数入口是否仍指向本跳转。
    #[must_use]
    pub fn is_installed(&self) -> bool {
        crate::mem::read_u64(self.entry) == Some(self.patched)
    }

    /// 在入口已恢复为原指令时重新装回跳转。
    #[must_use]
    pub fn reinstall(&self) -> bool {
        self.is_installed() || self.replace(self.original, self.patched)
    }

    /// 恢复本补丁并释放跳板。
    ///
    /// # Safety
    /// 恢复时引擎不得正在执行本跳转、处理函数或跳板。
    #[must_use]
    pub unsafe fn restore(self) -> bool {
        if self.is_installed() && !self.replace(self.patched, self.original) {
            return false;
        }
        self.trampoline.store(0, Ordering::Release);
        // SAFETY: 调用方已确保没有执行中的调用，入口也已离开本跳转。
        unsafe { VirtualFree(self.page as *mut c_void, 0, MEM_RELEASE) };
        true
    }

    fn replace(&self, from: u64, to: u64) -> bool {
        let address = self.entry as *mut c_void;
        let mut previous = 0;
        // SAFETY: 安装时已经验证入口为已映射、对齐的 8 字节范围。
        if unsafe { VirtualProtect(address, 8, PAGE_EXECUTE_READWRITE, &mut previous) } == 0 {
            return false;
        }
        // SAFETY: 已验证 8 字节对齐且当前可写。指令获取只能看到完整的入口替换。
        let replaced = unsafe { AtomicU64::from_ptr(address.cast()) }
            .compare_exchange(from, to, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if replaced {
            crate::win::flush_code(self.entry, 8);
        }
        let mut ignored = 0;
        // SAFETY: 同一映射范围，恢复首次 VirtualProtect 返回的页权限。
        unsafe { VirtualProtect(address, 8, previous, &mut ignored) };
        replaced
    }
}

fn validate_stolen_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err("invalid or incomplete instruction span");
        }
        if instruction.is_ip_rel_memory_operand()
            || instruction.op_kinds().any(|kind| {
                matches!(
                    kind,
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
            })
        {
            return Err("instruction span requires relocation");
        }
    }
    Ok(())
}

fn install_inner(
    entry: usize,
    steal: usize,
    stub: *const c_void,
    kind: StubKind,
    handler: usize,
) -> Result<HookGuard, &'static str> {
    if entry == 0 || !(5..=15).contains(&steal) {
        return Err("bad entry");
    }
    let mut patches = PATCHES.lock().unwrap_or_else(|err| err.into_inner());
    if patches.iter().any(|record| record.kind == kind) {
        return Err("hook slot occupied");
    }
    if patches.iter().any(|record| record.entry == entry) {
        return Err("function entry already hooked");
    }
    let mut original = [0u8; 15];
    if !crate::mem::read_bytes(entry, &mut original[..steal]) {
        return Err("unreadable function entry");
    }
    validate_stolen_bytes(&original[..steal])?;

    // 分配一个离入口 ±2 GB 内（rel32 窗口）的可执行块，供近跳块与跳板共用。
    let Some(page) = allocate_near(entry) else {
        return Err("no near trampoline allocation");
    };
    let page = page as *mut u8;
    // 布局：[0..14) 近跳块（`jmp qword ptr [rip]` + 8B 绝对地址）；[0x10..)
    // 跳板（被偷字节 + `jmp entry+steal`）。两段都在同一近页内，入口只依赖
    // 本页可达；到静态存根的距离不再有任何约束。
    let near_jump = page;
    let trampoline = (page as usize + 0x10) as *mut u8;

    // 近跳块 -> 静态存根（绝对寻址）。
    let block = encode_indirect_jump(stub as usize);
    // SAFETY: 新分配页（RWX）内的 14 字节写入；目标区间不重叠。
    unsafe {
        core::ptr::copy_nonoverlapping(block.as_ptr(), near_jump, block.len());
    }

    // 跳板：重放被偷字节 + `jmp entry+steal`（rel32；分配窗口保证可达）。
    let resume = entry + steal;
    let Some(resume_jump) = encode_e9(trampoline as usize + steal, resume) else {
        // SAFETY: 刚分配、未被引用。
        unsafe { VirtualFree(page as *mut c_void, 0, MEM_RELEASE) };
        return Err("resume jump out of rel32 range");
    };
    // SAFETY: 拷贝入口处的 steal 个字节到新分配的可执行页（两段内存互不重叠），
    // 页容量 0x1000 > 0x10 + steal + 5。
    unsafe {
        core::ptr::copy_nonoverlapping(original.as_ptr(), trampoline, steal);
        core::ptr::copy_nonoverlapping(
            resume_jump.as_ptr(),
            trampoline.add(steal),
            resume_jump.len(),
        );
    }
    // 改写入口：`jmp near_jump` + NOP 填充（可达性再次显式校验，越界即拒绝）。
    let Some(entry_jump) = encode_e9(entry, near_jump as usize) else {
        // SAFETY: 页刚分配、未被入口引用，可直接回收。
        unsafe { VirtualFree(page as *mut c_void, 0, MEM_RELEASE) };
        return Err("near jump block out of rel32 range");
    };
    let mut old = 0u32;
    // SAFETY: 入口是代码页；`steal` 字节落在两条完整指令上（调用方保证）。
    let protect_ok = unsafe {
        VirtualProtect(
            entry as *mut c_void,
            steal,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
    } != 0;
    if !protect_ok {
        // SAFETY: 入口尚未引用该页。
        unsafe { VirtualFree(page as *mut c_void, 0, MEM_RELEASE) };
        return Err("VirtualProtect (entry) failed");
    }
    crate::win::flush_code(page as usize, 0x10 + steal + resume_jump.len());
    handler_slot(kind).store(handler, Ordering::SeqCst);
    trampoline_slot(kind).store(trampoline as usize, Ordering::SeqCst);
    let id = NEXT_PATCH_ID.fetch_add(1, Ordering::Relaxed);
    patches.push(PatchRecord {
        id,
        kind,
        entry,
        length: steal,
        original,
    });
    TRAMPOLINES
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .push(page as usize);
    let stub_address = stub as usize;
    // SAFETY: 同上的代码页改写。
    unsafe {
        core::ptr::copy_nonoverlapping(entry_jump.as_ptr(), entry as *mut u8, entry_jump.len());
        for index in 5..steal {
            *((entry + index) as *mut u8) = 0x90;
        }
    }
    let mut restored = 0u32;
    // SAFETY: 恢复原保护。
    unsafe {
        VirtualProtect(entry as *mut c_void, steal, old, &mut restored);
    }
    log::info(&format!(
        "hook: installed at 0x{entry:X} -> near 0x{near:X} -> stub 0x{stub_address:X} \
         (trampoline 0x{trampoline:X})",
        near = near_jump as usize,
        trampoline = trampoline as usize
    ));
    crate::win::flush_code(entry, steal);
    Ok(HookGuard {
        id,
        entry,
        armed: true,
    })
}

fn trampoline_slot(kind: StubKind) -> &'static AtomicUsize {
    match kind {
        StubKind::Three => &TRAMPOLINE,
        StubKind::Four => &TRAMPOLINE4,
        StubKind::FourB => &TRAMPOLINE4B,
        StubKind::EquipWorker => &TRAMPOLINE_EQ,
        StubKind::SaveObserver => &TRAMPOLINE_SAVE,
    }
}

/// 把 vtable 的一个槽位指针换成新值；返回原值（数据补丁，不改指令）。
///
/// ```text
/// slot = *(vtable_address + slot_index * 8)
/// ```
///
/// # Safety
/// `slot_address` 必须指向一个 8 字节对齐、位于可写页（或可改保护页）的槽位。
#[must_use]
pub unsafe fn patch_pointer(slot_address: usize, replacement: usize) -> Option<usize> {
    let mut previous = 0u32;
    // SAFETY: 调用方保证槽位地址/对齐；只改一页保护，随即恢复。
    let protect_ok = unsafe {
        VirtualProtect(
            slot_address as *mut c_void,
            core::mem::size_of::<usize>(),
            PAGE_EXECUTE_READWRITE,
            &mut previous,
        )
    } != 0;
    if !protect_ok {
        return None;
    }
    // SAFETY: 调用方保证槽位可写且对齐。
    let original = unsafe { *(slot_address as *mut usize) };
    // SAFETY: 同上。
    unsafe {
        *(slot_address as *mut usize) = replacement;
    }
    let mut restored = 0u32;
    // SAFETY: 恢复原保护。
    unsafe {
        VirtualProtect(
            slot_address as *mut c_void,
            core::mem::size_of::<usize>(),
            previous,
            &mut restored,
        );
    }
    Some(original)
}

#[cfg(test)]
mod tests {
    //! 跳板安装、E9 编码与指针槽补丁的往返测试。

    core::arch::global_asm!(
        ".globl test_detour_entry",
        ".p2align 3",
        "test_detour_entry:",
        "mov eax, 7",
        ".byte 0x01, 0xc8", // add eax, ecx
        "ret",
    );

    extern "system" {
        fn test_detour_entry(value: i32) -> i32;
    }

    static TEST_TRAMPOLINE: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    extern "system" fn test_detour_target(value: i32) -> i32 {
        let address = TEST_TRAMPOLINE.load(core::sync::atomic::Ordering::Acquire);
        // SAFETY: The test calls this function through the installed, same-signature detour.
        let original: extern "system" fn(i32) -> i32 = unsafe { core::mem::transmute(address) };
        original(value) * 2
    }

    static DETOUR_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn aligned_detour_calls_the_original_prologue_and_restores_it() {
        let _serial = DETOUR_TEST.lock().unwrap();
        // SAFETY: The assembly defines an aligned entry starting with a relocatable 5-byte MOV.
        let detour = unsafe {
            super::EntryDetour::install(
                test_detour_entry as *const () as usize,
                [0xb8, 7, 0, 0, 0, 0x01, 0xc8, 0xc3],
                test_detour_target as *const () as usize,
                &TEST_TRAMPOLINE,
            )
        }
        .expect("test entry can be patched");
        // SAFETY: The test entry and detour share the declared Win64 signature.
        assert_eq!(unsafe { test_detour_entry(3) }, 20);
        // SAFETY: This test owns the entry and has returned from its only call.
        assert!(unsafe { detour.restore() });
        // SAFETY: This is the original assembly function.
        assert_eq!(unsafe { test_detour_entry(3) }, 10);
    }

    use super::{
        encode_e9, encode_indirect_jump, install_trace4, is_patched, patch_pointer, Handler4,
    };

    extern "system" fn dummy4(_: usize, _: usize, _: usize, _: usize) {}

    #[test]
    fn e9_detection_matches_only_the_patch_opcode() {
        let patched = [0xE9u8, 0, 0, 0, 0];
        let untouched = [0x48u8, 0x8B, 0x01, 0xC3, 0x90];
        // SAFETY: 只读测试内联缓冲区的首字节。
        assert!(unsafe { is_patched(patched.as_ptr() as usize) });
        // SAFETY: 同上，只读测试内联缓冲区的首字节。
        assert!(!unsafe { is_patched(untouched.as_ptr() as usize) });
    }

    #[test]
    fn stolen_span_rejects_relative_and_incomplete_instructions() {
        use super::validate_stolen_bytes;
        assert_eq!(
            validate_stolen_bytes(&[0x48, 0x89, 0x5c, 0x24, 0x10]),
            Ok(())
        );
        assert_eq!(
            validate_stolen_bytes(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]),
            Err("instruction span requires relocation")
        );
        assert_eq!(
            validate_stolen_bytes(&[0xe9, 0, 0, 0, 0]),
            Err("instruction span requires relocation")
        );
        assert_eq!(
            validate_stolen_bytes(&[0x48, 0x8b, 0x05, 0, 0]),
            Err("invalid or incomplete instruction span")
        );
    }

    #[test]
    fn occupied_slot_rejects_another_installation() {
        let entry = test_detour_entry as *const () as usize;
        let _serial = DETOUR_TEST.lock().unwrap();
        // SAFETY: The fixture is idle and the test lock gives exclusive access.
        let hook = unsafe { install_trace4(entry, 5, dummy4) }.expect("first hook");
        // SAFETY: The slot check runs before the installer reads the second entry.
        let second = unsafe { install_trace4(entry + 16, 5, dummy4) };
        assert_eq!(second.err(), Some("hook slot occupied"));
        drop(hook);
    }

    #[test]
    fn bad_steal_is_rejected_before_touching_memory() {
        // SAFETY: entry=0 与越界 steal 在任何内存操作之前返回 Err。
        let result = unsafe { install_trace4(0, 4, dummy4 as Handler4) };
        assert_eq!(result.err(), Some("bad entry"));
    }

    #[test]
    fn patch_pointer_swaps_and_restores() {
        let mut slot: usize = 0x1122_3344_5566_7788;
        let address = &mut slot as *mut usize as usize;
        // SAFETY: 指向测试内对齐的局部变量；patch_pointer 只改一个指针宽度并恢复页保护。
        let first = unsafe { patch_pointer(address, 0xDEAD_BEEF) };
        assert_eq!(first, Some(0x1122_3344_5566_7788));
        assert_eq!(slot, 0xDEAD_BEEF);
        // SAFETY: 同上。
        let second = unsafe { patch_pointer(address, 0x1122_3344_5566_7788) };
        assert_eq!(second, Some(0xDEAD_BEEF));
        assert_eq!(slot, 0x1122_3344_5566_7788);
    }

    #[test]
    fn e9_encoding_rejects_out_of_rel32_range() {
        // 历史缺陷的值：入口 0x7FFD968FDA54 曾直接跳到 0x7FFE7D8010C0（相距
        // 3.87 GB），位移 as i32 截断后游戏跳到 0x7FFD7D8010C0 的 NX 页。
        assert!(
            encode_e9(0x7FFD_968F_DA54, 0x7FFE_7D80_10C0).is_none(),
            "越界位移必须被拒绝，不允许截断"
        );
        // 边界内（+1.75 GB）可编码且可逆解。
        let op = 0x1000_0000usize;
        let to = op + 0x7000_0000 - 0x10;
        let bytes = encode_e9(op, to).expect("near jump must encode");
        assert_eq!(bytes[0], 0xE9);
        let rel = i32::from_le_bytes(bytes[1..].try_into().unwrap()) as i64;
        assert_eq!(op as i64 + 5 + rel, to as i64);
        // 边界外（+2 GiB 以上）拒绝（0x8000_0000-5 仍在 i32 正区间内，用留量值）。
        assert!(encode_e9(op, op + 0x8000_1000).is_none());
    }

    #[test]
    fn indirect_block_carries_the_absolute_target() {
        let target = 0x7FFE_7D80_10C0usize;
        let bytes = encode_indirect_jump(target);
        assert_eq!(&bytes[..6], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        let decoded = u64::from_le_bytes(bytes[6..].try_into().unwrap());
        assert_eq!(decoded, target as u64);
    }
}
