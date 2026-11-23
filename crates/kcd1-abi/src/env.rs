//! Pinned global-environment layout for KCD1 Steam BuildID 22623230.

use core::ffi::c_void;

use crate::{mem, win};

const GAME_MODULE: &str = "WHGame.DLL";
const IMAGE_TIMESTAMP: u32 = 0x69cc_d815;
const IMAGE_SIZE: usize = 0x039e_b000;
const ENV_RVA: usize = 0x029d_16c0;

/// Console pointer offset within the global environment.
pub const CONSOLE_OFFSET: usize = 0xa8;

/// Wait for WHGame.dll to load.
#[must_use]
pub fn wait_for_module(timeout_ms: u32) -> Option<(usize, usize)> {
    for _ in 0..=timeout_ms / 50 {
        if let Some(range) = win::module_range(GAME_MODULE) {
            return Some(range);
        }
        win::sleep_ms(50);
    }
    None
}

/// Return the environment address for the supported image.
#[must_use]
pub fn locate(base: usize, size: usize) -> Option<*mut c_void> {
    if size != IMAGE_SIZE {
        return None;
    }
    let pe = base + mem::read_u32(base + 0x3c)? as usize;
    if mem::read_u32(pe + 8)? != IMAGE_TIMESTAMP {
        return None;
    }
    Some((base + ENV_RVA) as *mut c_void)
}
