//! KCD1 CryEngine bindings for the ConsoleSilence Lua API.

use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};

use kcd1_abi::{log, mem, module::Module};

use crate::overlay;
use crate::rules::{Action, MatchKind};

const TABLE_NAME: &str = "ConsoleSilence";
static REGISTERED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_EXECUTE_FILE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// ---------------------------------------------------------------- 引擎类型（最小镜像）

#[repr(C)]
struct ScriptSystem {
    vtable: *const *const c_void,
}

#[repr(C)]
struct ScriptTable {
    vtable: *const *const c_void,
}

#[repr(C)]
struct FunctionHandler {
    vtable: *const *const c_void,
}

#[repr(C)]
union AnyData {
    boolean: bool,
    number: f32,
    string: *const c_char,
    table: *mut ScriptTable,
    storage: [usize; 2],
}

#[repr(C)]
struct AnyValue {
    value_type: i32,
    data: AnyData,
}

const ANY_ANY: i32 = 0;
const ANY_BOOL: i32 = 2;
const ANY_NUMBER: i32 = 4;
const ANY_STRING: i32 = 5;
const ANY_TABLE: i32 = 6;

impl AnyValue {
    /// `GetParamAny` 是**按类型定向**读的：输出值必须先写成 `ANY_ANY` 表示"什么都收"，
    /// 写成 `Nil` 会让每个参数读取都失败。
    fn any() -> AnyValue {
        AnyValue {
            value_type: ANY_ANY,
            data: AnyData { number: 0.0 },
        }
    }

    fn number(value: f32) -> AnyValue {
        AnyValue {
            value_type: ANY_NUMBER,
            data: AnyData { number: value },
        }
    }

    fn boolean(value: bool) -> AnyValue {
        AnyValue {
            value_type: ANY_BOOL,
            data: AnyData { boolean: value },
        }
    }

    fn string(value: *const c_char) -> AnyValue {
        AnyValue {
            value_type: ANY_STRING,
            data: AnyData { string: value },
        }
    }

    fn table(value: *mut ScriptTable) -> AnyValue {
        AnyValue {
            value_type: ANY_TABLE,
            data: AnyData { table: value },
        }
    }
}

type UserFunction = Option<extern "system" fn(*mut FunctionHandler, *mut c_void, i32) -> i32>;

/// `SUserFunctionDesc`：32 字节的 `Functor1wRet` 占位 + 函数指针。
#[repr(C)]
struct UserFunctionDesc {
    function_name: *const c_char,
    function_params: *const c_char,
    global_name: *const c_char,
    functor: [u8; 32],
    param_id_offset: i8,
    user_data_func: UserFunction,
    data_buffer: *mut c_void,
    data_size: i32,
}

impl UserFunctionDesc {
    fn new(
        function_name: &CString,
        function_params: &CString,
        global_name: &CString,
        user_data_func: UserFunction,
    ) -> UserFunctionDesc {
        UserFunctionDesc {
            function_name: function_name.as_ptr(),
            function_params: function_params.as_ptr(),
            global_name: global_name.as_ptr(),
            functor: [0u8; 32],
            param_id_offset: 0,
            user_data_func,
            data_buffer: core::ptr::null_mut(),
            data_size: 0,
        }
    }
}

// KCD1 Steam BuildID 22623230.
const SCRIPT_EXECUTE_FILE: usize = 5;
const SCRIPT_EXECUTE_BUFFER: usize = 6;
const SCRIPT_CREATE_TABLE: usize = 13;
const SCRIPT_SET_GLOBAL_ANY: usize = 30;
const SCRIPT_VTABLE_RVA: usize = 0x027d_2488;
const TABLE_ADD_REF: usize = 3;
const TABLE_RELEASE: usize = 4;
const TABLE_SET_VALUE_ANY: usize = 7;
const TABLE_SET_AT_ANY: usize = 13;
const TABLE_ADD_FUNCTION: usize = 22;
const HANDLER_GET_PARAM_ANY: usize = 7;
const HANDLER_END_FUNCTION_ANY: usize = 10;
const HANDLER_END_FUNCTION: usize = 11;

fn entry(vtable: *const *const c_void, index: usize) -> Option<usize> {
    if vtable.is_null() {
        return None;
    }
    mem::read_pointer(vtable as usize + index * core::mem::size_of::<usize>())
}

// ---------------------------------------------------------------- 注册

/// Register on the engine thread immediately before CCryAction loads scripts/main.lua.
pub fn install() -> bool {
    let Some(game) = Module::named(crate::console::GAME_MODULE) else {
        return false;
    };
    let vtable = game.base().get() + SCRIPT_VTABLE_RVA;
    let slot = vtable + SCRIPT_EXECUTE_FILE * core::mem::size_of::<usize>();
    let Some(original) = mem::read_pointer(slot) else {
        return false;
    };
    if original != game.base().get() + 0x0213_aa70 {
        return false;
    }
    ORIGINAL_EXECUTE_FILE.store(original, Ordering::Release);
    mem::write_pointer(slot, execute_file_hook as *const () as usize)
}

/// 注册全局表；只在游戏线程的 VM 边界调用。
fn register_now(system: *mut ScriptSystem, vtable: *const *const c_void) -> bool {
    let name = match CString::new(TABLE_NAME) {
        Ok(value) => value,
        Err(_) => return false,
    };
    // SAFETY: 槽位在 `install` 里校验过；调用约定与引擎一致（`extern "system"`）。
    let table = unsafe {
        let create: extern "system" fn(*mut ScriptSystem, bool) -> *mut ScriptTable =
            core::mem::transmute(entry(vtable, SCRIPT_CREATE_TABLE).unwrap_or(0));
        create(system, false)
    };
    if table.is_null() {
        log::warn("CreateTable(ConsoleSilence) returned null");
        return false;
    }
    let table_vtable = match mem::read_pointer(table as usize) {
        Some(value) => value as *const *const c_void,
        None => return false,
    };
    // SAFETY: create returned a live CScriptTable.
    let _reference = unsafe { TableReference::acquire(table) };
    let functions: [(&str, &str, UserFunction); 9] = [
        ("mute_raw", "s,s,s,s,n", Some(handler_mute)),
        ("unmute_raw", "n", Some(handler_unmute)),
        ("clear_raw", "b,s", Some(handler_clear)),
        ("list_raw", "", Some(handler_list)),
        ("stats_raw", "", Some(handler_stats)),
        ("which_raw", "s", Some(handler_which)),
        ("enabled_raw", "b", Some(handler_enabled)),
        ("observe_raw", "b", Some(handler_observe)),
        ("fold_raw", "b", Some(handler_fold)),
    ];
    let mut registered = 0usize;
    for (function_name, params, user_data) in functions {
        let (Ok(function_name), Ok(function_params)) =
            (CString::new(function_name), CString::new(params))
        else {
            continue;
        };
        let mut description =
            UserFunctionDesc::new(&function_name, &function_params, &name, user_data);
        // SAFETY: 表与描述符都在本函数栈上、调用期间有效；槽位已校验。
        let ok = unsafe {
            let add: extern "system" fn(*mut ScriptTable, *mut UserFunctionDesc) -> bool =
                core::mem::transmute(entry(table_vtable, TABLE_ADD_FUNCTION).unwrap_or(0));
            add(table, &mut description)
        };
        if ok {
            registered += 1;
        } else {
            log::warn(&format!("AddFunction({function_name:?}) failed"));
        }
    }
    if registered != functions.len() {
        return false;
    }
    // SAFETY: 同上；`AnyValue::table` 只是把指针包成脚本值。
    unsafe {
        let set_global: extern "system" fn(*mut ScriptSystem, *const c_char, *const AnyValue) =
            core::mem::transmute(entry(vtable, SCRIPT_SET_GLOBAL_ANY).unwrap_or(0));
        let value = AnyValue::table(table);
        set_global(system, name.as_ptr(), &value);
    }
    if !run_shim(system, vtable) {
        log::warn("Lua shim failed");
        return false;
    }
    REGISTERED.store(true, Ordering::Release);
    log::info("Lua API registered: ConsoleSilence.{mute,unmute,clear,list,stats,which,enabled,observe,fold}");
    true
}

type ExecuteFile =
    extern "system" fn(*mut ScriptSystem, *const c_char, bool, bool, *mut ScriptTable) -> bool;

extern "system" fn execute_file_hook(
    system: *mut ScriptSystem,
    name: *const c_char,
    raise_error: bool,
    force_reload: bool,
    table: *mut ScriptTable,
) -> bool {
    // SAFETY: the engine supplies a live script system and a NUL-terminated filename.
    let is_main = !name.is_null()
        && unsafe { std::ffi::CStr::from_ptr(name) }
            .to_bytes()
            .eq_ignore_ascii_case(b"scripts/main.lua");
    if is_main && !REGISTERED.load(Ordering::Acquire) {
        kcd1_abi::guard::catch("Lua registration", (), || {
            SCRIPT_SYSTEM.store(system as usize, Ordering::Relaxed);
            if let Some(vtable) = mem::read_pointer(system as usize) {
                register_now(system, vtable as *const *const c_void);
            }
        });
    }
    // SAFETY: install checked the original ExecuteFile entry on this build.
    let forward: ExecuteFile =
        unsafe { core::mem::transmute(ORIGINAL_EXECUTE_FILE.load(Ordering::Acquire)) };
    forward(system, name, raise_error, force_reload, table)
}

fn run_shim(system: *mut ScriptSystem, vtable: *const *const c_void) -> bool {
    let source = include_str!("shim.lua");
    let Some(address) = entry(vtable, SCRIPT_EXECUTE_BUFFER) else {
        return false;
    };
    // SAFETY: the pinned CScriptSystem ExecuteBuffer slot takes a byte slice and a C string.
    let execute: extern "system" fn(
        *mut ScriptSystem,
        *const u8,
        usize,
        *const c_char,
        *mut ScriptTable,
    ) -> bool = unsafe { core::mem::transmute(address) };
    execute(
        system,
        source.as_ptr(),
        source.len(),
        c"ConsoleSilence/shim.lua".as_ptr(),
        core::ptr::null_mut(),
    )
}

// ---------------------------------------------------------------- 参数与返回

struct Params {
    handler: *mut FunctionHandler,
    /// 字符串参数的 `CString` 必须在 `EndFunction` 之前活着。
    owned: Vec<CString>,
}

impl Params {
    fn string(&mut self, index: i32) -> Option<String> {
        // SAFETY: 处理器指针由引擎在本次调用内给出。
        unsafe {
            let mut value = AnyValue::any();
            let get: extern "system" fn(*mut FunctionHandler, i32, *mut AnyValue) -> bool =
                core::mem::transmute(entry((*(self.handler)).vtable, HANDLER_GET_PARAM_ANY)?);
            if !get(self.handler, index, &mut value) || value.value_type != ANY_STRING {
                return None;
            }
            let pointer = value.data.string;
            if pointer.is_null() {
                return None;
            }
            let text = std::ffi::CStr::from_ptr(pointer)
                .to_string_lossy()
                .into_owned();
            self.owned.push(CString::new(text.clone()).ok()?);
            Some(text)
        }
    }

    fn number(&self, index: i32) -> Option<f64> {
        // SAFETY: 同上。
        unsafe {
            let mut value = AnyValue::any();
            let get: extern "system" fn(*mut FunctionHandler, i32, *mut AnyValue) -> bool =
                core::mem::transmute(entry((*(self.handler)).vtable, HANDLER_GET_PARAM_ANY)?);
            if !get(self.handler, index, &mut value) || value.value_type != ANY_NUMBER {
                return None;
            }
            Some(f64::from(value.data.number))
        }
    }

    fn boolean(&self, index: i32) -> Option<bool> {
        // SAFETY: 处理器指针由引擎在本次调用内给出；槽位已校验。
        unsafe {
            let mut value = AnyValue::any();
            let get: extern "system" fn(*mut FunctionHandler, i32, *mut AnyValue) -> bool =
                core::mem::transmute(entry((*(self.handler)).vtable, HANDLER_GET_PARAM_ANY)?);
            if !get(self.handler, index, &mut value) || value.value_type != ANY_BOOL {
                return None;
            }
            Some(value.data.boolean)
        }
    }

    fn return_number(self, value: f64) -> i32 {
        // SAFETY: 同上；返回后引擎不再读我们的栈。
        unsafe {
            let Some(entry) = entry((*(self.handler)).vtable, HANDLER_END_FUNCTION_ANY) else {
                return 0;
            };
            let end: extern "system" fn(*mut FunctionHandler, *const AnyValue) -> i32 =
                core::mem::transmute(entry);
            let payload = AnyValue::number(value as f32);
            end(self.handler, &payload)
        }
    }

    fn return_bool(self, value: bool) -> i32 {
        // SAFETY: 同上。
        unsafe {
            let Some(entry) = entry((*(self.handler)).vtable, HANDLER_END_FUNCTION_ANY) else {
                return 0;
            };
            let end: extern "system" fn(*mut FunctionHandler, *const AnyValue) -> i32 =
                core::mem::transmute(entry);
            let payload = AnyValue::boolean(value);
            end(self.handler, &payload)
        }
    }

    fn return_string(self, value: &str) -> i32 {
        let Ok(text) = CString::new(value) else {
            return self.return_nil();
        };
        // SAFETY: 同上；`text` 活到 `end` 返回之后（本函数栈帧）。
        unsafe {
            let Some(entry) = entry((*(self.handler)).vtable, HANDLER_END_FUNCTION_ANY) else {
                return 0;
            };
            let end: extern "system" fn(*mut FunctionHandler, *const AnyValue) -> i32 =
                core::mem::transmute(entry);
            let payload = AnyValue::string(text.as_ptr());
            end(self.handler, &payload)
        }
    }

    fn return_table(self, table: *mut ScriptTable) -> i32 {
        if table.is_null() {
            return self.return_nil();
        }
        // SAFETY: 同上。
        unsafe {
            let Some(entry) = entry((*(self.handler)).vtable, HANDLER_END_FUNCTION_ANY) else {
                return 0;
            };
            let end: extern "system" fn(*mut FunctionHandler, *const AnyValue) -> i32 =
                core::mem::transmute(entry);
            let _reference = TableReference::acquire(table);
            let payload = AnyValue::table(table);
            end(self.handler, &payload)
        }
    }

    fn return_nil(self) -> i32 {
        // SAFETY: 同上。
        unsafe {
            let Some(entry) = entry((*(self.handler)).vtable, HANDLER_END_FUNCTION) else {
                return 0;
            };
            let end: extern "system" fn(*mut FunctionHandler) -> i32 = core::mem::transmute(entry);
            end(self.handler)
        }
    }
}

fn params(handler: *mut FunctionHandler) -> Option<Params> {
    if handler.is_null() {
        return None;
    }
    Some(Params {
        handler,
        owned: Vec::new(),
    })
}

// ---------------------------------------------------------------- 处理函数

fn guard<F>(name: &'static str, fallback: impl FnOnce() -> i32, body: F) -> i32
where
    F: FnOnce() -> i32,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => {
            log::error(&format!("panic in Lua handler {name}"));
            fallback()
        }
    }
}

extern "system" fn handler_mute(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "mute",
        || {
            params(handler)
                .map(|params| params.return_string("internal error"))
                .unwrap_or(0)
        },
        || {
            let Some(mut p) = params(handler) else {
                return 0;
            };
            let kind = p.string(1).unwrap_or_else(|| "contains".to_string());
            let pattern = p.string(2).unwrap_or_default();
            let action = p.string(3).unwrap_or_else(|| "drop".to_string());
            let owner = p.string(4).unwrap_or_default();
            let ttl = p.number(5).unwrap_or(0.0).max(0.0) as u64;

            let Some(kind) = MatchKind::parse(&kind) else {
                return p.return_string(&format!("unknown kind '{kind}'"));
            };
            let Some(action) = Action::parse(&action) else {
                return p.return_string(&format!("unknown action '{action}'"));
            };
            if pattern.is_empty() {
                return p.return_string("empty pattern");
            }
            let spec = crate::spec::RuleSpec::new(kind, action, &pattern, None, &owner, ttl);
            match overlay::add(spec) {
                Ok(id) => p.return_number(f64::from(id)),
                Err(reason) => p.return_string(&reason),
            }
        },
    )
}

extern "system" fn handler_unmute(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "unmute",
        || 0,
        || {
            let Some(p) = params(handler) else { return 0 };
            let id = p.number(1).unwrap_or(0.0) as u32;
            let removed = overlay::remove(id);
            p.return_bool(removed)
        },
    )
}

extern "system" fn handler_clear(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "clear",
        || 0,
        || {
            let Some(mut p) = params(handler) else {
                return 0;
            };
            let owner = if p.boolean(1) == Some(true) {
                None
            } else if let Some(owner) = p.string(2) {
                Some(owner)
            } else {
                return p.return_number(0.0);
            };
            let removed = overlay::clear(owner.as_deref());
            p.return_number(removed as f64)
        },
    )
}

extern "system" fn handler_which(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "which",
        || 0,
        || {
            let Some(mut p) = params(handler) else {
                return 0;
            };
            match p.string(1).and_then(|line| overlay::which(&line)) {
                Some(id) => p.return_number(f64::from(id)),
                None => p.return_nil(),
            }
        },
    )
}

extern "system" fn handler_enabled(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "enabled",
        || 0,
        || {
            let Some(p) = params(handler) else { return 0 };
            let on = p.boolean(1).unwrap_or(true);
            overlay::set_enabled(on);
            p.return_bool(on)
        },
    )
}

extern "system" fn handler_observe(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "observe",
        || 0,
        || {
            let Some(p) = params(handler) else { return 0 };
            let on = p.boolean(1).unwrap_or(false);
            overlay::set_observe(on);
            p.return_bool(on)
        },
    )
}

extern "system" fn handler_fold(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "fold",
        || 0,
        || {
            let Some(p) = params(handler) else { return 0 };
            let on = p.boolean(1).unwrap_or(true);
            overlay::set_fold(on);
            p.return_bool(on)
        },
    )
}

extern "system" fn handler_stats(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "stats",
        || params(handler).map(Params::return_nil).unwrap_or(0),
        || {
            let Some(p) = params(handler) else { return 0 };
            let snapshot = crate::status::snapshot();
            let runtime = overlay::count();
            let mut strings: Vec<CString> = Vec::new();
            let Some(table) = new_table() else {
                return p.return_nil();
            };
            let fields: [(&str, f64); 6] = [
                ("seen", snapshot.seen as f64),
                ("dropped", snapshot.dropped as f64),
                ("passed", snapshot.passed as f64),
                ("repeatSuppressed", snapshot.repeat_suppressed as f64),
                ("commandsSilenced", snapshot.commands_silenced as f64),
                ("rules", runtime as f64),
            ];
            for (key, value) in fields {
                set_number(&mut strings, table, |text| text.to_string(), key, value);
            }
            p.return_table(table)
        },
    )
}

extern "system" fn handler_list(
    handler: *mut FunctionHandler,
    _data: *mut c_void,
    _offset: i32,
) -> i32 {
    guard(
        "list",
        || params(handler).map(Params::return_nil).unwrap_or(0),
        || {
            let Some(p) = params(handler) else { return 0 };
            let Some(array) = new_table() else {
                return p.return_nil();
            };
            let mut strings: Vec<CString> = Vec::new();
            for (index, row) in overlay::list().into_iter().enumerate() {
                let Some(row_table) = new_table() else {
                    break;
                };
                set_number(
                    &mut strings,
                    row_table,
                    |text| text.to_string(),
                    "id",
                    f64::from(row.id),
                );
                set_number(
                    &mut strings,
                    row_table,
                    |text| text.to_string(),
                    "hits",
                    row.hits as f64,
                );
                set_number(
                    &mut strings,
                    row_table,
                    |text| text.to_string(),
                    "ttlMs",
                    row.ttl_ms as f64,
                );
                set_string(&mut strings, row_table, "kind", row.kind);
                set_string(&mut strings, row_table, "action", &row.action);
                set_string(&mut strings, row_table, "pattern", &row.pattern);
                set_string(&mut strings, row_table, "label", &row.label);
                set_string(&mut strings, row_table, "owner", &row.owner);
                set_at(&mut strings, array, index as i32 + 1, row_table);
            }
            p.return_table(array)
        },
    )
}

struct TableReference(*mut ScriptTable);

impl TableReference {
    unsafe fn acquire(table: *mut ScriptTable) -> Self {
        // SAFETY: callers pass a live CScriptTable created by the engine.
        unsafe { Self::call(table, TABLE_ADD_REF) };
        Self(table)
    }

    unsafe fn call(table: *mut ScriptTable, slot: usize) {
        // SAFETY: slot is AddRef or Release on the live CScriptTable vtable.
        unsafe {
            let function: extern "system" fn(*mut ScriptTable) =
                core::mem::transmute(*(*table).vtable.add(slot));
            function(table);
        }
    }
}

impl Drop for TableReference {
    fn drop(&mut self) {
        // SAFETY: the reference acquired in the constructor is still held.
        unsafe { Self::call(self.0, TABLE_RELEASE) };
    }
}

// ---------------------------------------------------------------- 建表小工具

fn new_table() -> Option<*mut ScriptTable> {
    let script = current_script()?;
    let vtable = mem::read_pointer(script as usize)? as *const *const c_void;
    // SAFETY: 槽位在 `register` 里校验过；这里只创建空表。
    unsafe {
        let create: extern "system" fn(*mut ScriptSystem, bool) -> *mut ScriptTable =
            core::mem::transmute(entry(vtable, SCRIPT_CREATE_TABLE)?);
        let table = create(script as *mut ScriptSystem, false);
        (!table.is_null()).then_some(table)
    }
}

static SCRIPT_SYSTEM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn current_script() -> Option<*mut c_void> {
    let value = SCRIPT_SYSTEM.load(core::sync::atomic::Ordering::Relaxed);
    (value != 0).then_some(value as *mut c_void)
}

fn set_number(
    _strings: &mut [CString],
    table: *mut ScriptTable,
    _render: impl FnOnce(&str) -> String,
    key: &str,
    value: f64,
) {
    let Ok(key) = CString::new(key) else { return };
    let vtable = match mem::read_pointer(table as usize) {
        Some(value) => value as *const *const c_void,
        None => return,
    };
    // SAFETY: 槽位已校验；`key` 在本函数内有效，数字直接按值传。
    unsafe {
        let Some(entry) = entry(vtable, TABLE_SET_VALUE_ANY) else {
            return;
        };
        let set: extern "system" fn(*mut ScriptTable, *const c_char, *const AnyValue, bool) =
            core::mem::transmute(entry);
        let payload = AnyValue::number(value as f32);
        set(table, key.as_ptr(), &payload, false);
    }
}

fn set_string(strings: &mut Vec<CString>, table: *mut ScriptTable, key: &str, value: &str) {
    let (Ok(key), Ok(value)) = (CString::new(key), CString::new(value)) else {
        return;
    };
    let vtable = match mem::read_pointer(table as usize) {
        Some(pointer) => pointer as *const *const c_void,
        None => return,
    };
    // SAFETY: `TABLE_SET_VALUE_ANY` 槽位在 `register` 里校验过指向游戏代码段；
    // `table` 由引擎创建，`key` 在本函数内有效，字符串值挂到调用期的 `strings` 上，
    // 活到处理器返回之后（`EndFunction` 早已返回）。
    unsafe {
        let Some(entry) = entry(vtable, TABLE_SET_VALUE_ANY) else {
            return;
        };
        let set: extern "system" fn(*mut ScriptTable, *const c_char, *const AnyValue, bool) =
            core::mem::transmute(entry);
        let leaked = strings.len();
        strings.push(value);
        let payload = AnyValue::string(strings[leaked].as_ptr());
        set(table, key.as_ptr(), &payload, false);
    }
}

fn set_at(_strings: &mut [CString], array: *mut ScriptTable, index: i32, row: *mut ScriptTable) {
    let vtable = match mem::read_pointer(array as usize) {
        Some(value) => value as *const *const c_void,
        None => return,
    };
    // SAFETY: 槽位已校验；`row` 由本处理器创建。
    unsafe {
        let Some(entry) = entry(vtable, TABLE_SET_AT_ANY) else {
            return;
        };
        let set: extern "system" fn(*mut ScriptTable, i32, *const AnyValue) =
            core::mem::transmute(entry);
        let _reference = TableReference::acquire(row);
        let payload = AnyValue::table(row);
        set(array, index, &payload);
    }
}
