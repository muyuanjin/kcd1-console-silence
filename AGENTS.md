# Repository Guidelines

## Project Structure

- `crates/console-silence/src/` contains the ASI plugin, including console filtering, rules, diagnostics, and the Lua bridge. Edit `shim.lua` here when changing Lua option handling.
- `crates/kcd1-abi/src/` contains the Win64 engine bindings, guarded memory access, and hook infrastructure.
- `docs/` contains the Lua API reference, mod author guide, and design notes. Windows CI lives in `.github/workflows/ci.yml`.

## Build and Development Commands

Use stable Rust and the MSVC x64 toolchain. Run these commands from the workspace root in PowerShell.

- `rustup target add x86_64-pc-windows-msvc` installs the Rust target.
- `cargo build --locked --release --target x86_64-pc-windows-msvc` builds the plugin DLL.
- `cargo test --locked --release --target x86_64-pc-windows-msvc` runs workspace unit tests.
- `cargo clippy --release --target x86_64-pc-windows-msvc --all-targets -- -D warnings` runs the CI lint check.
- `cargo fmt --check` checks Rust formatting. Run `cargo fmt` to apply it.

Copy `target/x86_64-pc-windows-msvc/release/console_silence.dll` as `ConsoleSilence.asi` into the game’s `Bin/Win64` alongside `KingdomCome.exe` and the x64 Ultimate ASI Loader (`dinput8.dll`). Restart the game. The supported Steam BuildID is `22623230`.

## Coding Style

Use Rust 2021 and rustfmt defaults, including four-space indentation. Use `snake_case` for modules and functions and `UpperCamelCase` for types. Document the safety assumptions of unsafe blocks with `// SAFETY:` comments. Keep the console print path free of locks and allocations, and preserve command execution and normal `kcd.log` output. Update `docs/LUA_API.md` when changing the public Lua API.

## Testing

Place unit tests beside the implementation in `#[cfg(test)]` modules. Name tests for the behavior they verify, such as `disabled_snapshot_passes_everything`. CI uses passing unit tests as its test gate. For changes to hooks or Lua registration, verify plugin loading, rule application, and command execution in the supported game build.

## Commits and Pull Requests

Prefer short, imperative commit subjects. In pull requests, describe the behavior change and list the checks run. Link relevant issues and include the game build and observed result for in-game verification.
