$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$target = 'x86_64-pc-windows-msvc'
$previousFlags = $env:CARGO_ENCODED_RUSTFLAGS
Push-Location -LiteralPath $repo
try {
    $sysroot = rustc --print sysroot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not locate the Rust toolchain.'
    }
    $cargoDir = $env:CARGO_HOME ?? (Join-Path $env:USERPROFILE '.cargo')
    $remaps = [ordered]@{
        $repo = '/workspace'
        $cargoDir = '/cargo'
        $sysroot = '/rust'
    }
    $rustFlags = foreach ($entry in $remaps.GetEnumerator()) {
        "--remap-path-prefix=$($entry.Key)=$($entry.Value)"
        "--remap-path-prefix=$($entry.Key.Replace('\', '/'))=$($entry.Value)"
    }
    $env:CARGO_ENCODED_RUSTFLAGS = $rustFlags -join [char]31

    cargo build --locked --release --target $target --target-dir target
    if ($LASTEXITCODE -ne 0) {
        throw 'ConsoleSilence build failed.'
    }
    $metadata = cargo metadata --locked --format-version 1 --filter-platform $target
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read the locked dependency list.'
    }
    $dependencies = ($metadata | ConvertFrom-Json).packages | Where-Object source

    $files = [ordered]@{
        'ConsoleSilence.asi' = Join-Path $repo "target/$target/release/console_silence.dll"
        'LICENSE' = Join-Path $repo 'LICENSE'
        'licenses/rust/COPYRIGHT-library.html' = Join-Path $sysroot 'share/doc/rust/COPYRIGHT-library.html'
    }
    foreach ($package in $dependencies) {
        $directory = Split-Path -Parent $package.manifest_path
        $notices = @(Get-ChildItem -LiteralPath $directory -File | Where-Object {
            $_.Name -match '^(licen[sc]e|copying|copyright|notice|unlicense)([-_.]|$)'
        } | Select-Object -ExpandProperty FullName)
        if ($package.license_file) {
            $notices += Join-Path $directory $package.license_file
        }
        if (!$notices) {
            $bundled = Join-Path $repo "licenses/$($package.name)-$($package.version)"
            if (Test-Path -LiteralPath $bundled -PathType Container) {
                $notices = @(Get-ChildItem -LiteralPath $bundled -File | Select-Object -ExpandProperty FullName)
            }
        }
        if (!$notices) {
            throw "Could not find license notices for $($package.name) $($package.version)."
        }
        foreach ($notice in $notices) {
            $files["licenses/$($package.name)-$($package.version)/$(Split-Path -Leaf $notice)"] = $notice
        }
    }

    $output = Join-Path $repo 'dist'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $temporaryZip = Join-Path $output ([IO.Path]::GetRandomFileName())
    try {
        $zip = [IO.Compression.ZipFile]::Open($temporaryZip, 'Create')
        try {
            foreach ($file in $files.GetEnumerator()) {
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip, $file.Value, $file.Key
                ) | Out-Null
            }
        } finally {
            $zip.Dispose()
        }
        Move-Item -LiteralPath $temporaryZip -Destination (Join-Path $output 'ConsoleSilence.zip') -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryZip) {
            Remove-Item -LiteralPath $temporaryZip
        }
    }
} finally {
    $env:CARGO_ENCODED_RUSTFLAGS = $previousFlags
    Pop-Location
}
