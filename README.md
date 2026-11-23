# ConsoleSilence for Kingdom Come: Deliverance

ConsoleSilence lets Lua mods filter messages and command echoes in the in-game console. Commands still run and the game's `kcd.log` retains the messages it normally records. Rules start empty at launch and last for the current session.

## Install

Windows x64 Steam build `1.9.8-404-504czj4` (BuildID `22623230`) is supported. Download and extract ConsoleSilence.zip, then put `ConsoleSilence.asi` and the x64 Ultimate ASI Loader (`dinput8.dll`) beside `KingdomCome.exe` in `Bin/Win64`, then restart the game. [GitHub Releases](https://github.com/muyuanjin/kcd1-console-silence/releases/latest)

## Use from Lua

```lua
if ConsoleSilence then
    ConsoleSilence.mute("[MyMod] status", { owner = "MyMod", action = "throttle:5000" })
end
```

This lets the first matching line through in each five-second window. See the [Lua API](docs/LUA_API.md) and [mod author guide](docs/FOR_MOD_AUTHORS.md) for rule options. `consolesilence.log` and `ConsoleSilence.status.json` are written beside the plugin.

## Build

Use stable Rust and the MSVC x64 toolchain.

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --locked --release --target x86_64-pc-windows-msvc
cargo test --locked --release --target x86_64-pc-windows-msvc
```

## Package

Run `pwsh -File scripts/package.ps1` to build `dist/ConsoleSilence.zip`. The script remaps local build paths and bundles the ASI with the dependency license notices. Windows CI uploads the archive. Pushing a version tag publishes the archive to GitHub Releases after the Windows checks pass.

KCD1 port of [kcd2-console-silence](https://github.com/muyuanjin/kcd2-console-silence).
