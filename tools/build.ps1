[CmdletBinding()]
param(
    [switch]$FullClean,
    [switch]$PlanOnly,
    [switch]$NoFrontend,
    [switch]$Test,
    [string]$Preset = 'ninja-msvc-release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logDir = Join-Path $env:TEMP "slop-build-$stamp"
New-Item -ItemType Directory -Path $logDir | Out-Null

$vsRoot = $null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere) {
    $vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
foreach ($candidate in @('E:\PRODUCT VS22')) {
    if (-not $vsRoot -and (Test-Path -LiteralPath (Join-Path $candidate 'VC\Auxiliary\Build\vcvars64.bat'))) {
        $vsRoot = $candidate
        break
    }
}
if (-not $vsRoot) { throw 'Visual Studio 2022 with C++ tools not found' }

$vsCMake = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$vsNinja = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'

Write-Host "==> repo:     $repoRoot"
Write-Host "==> vs root:  $vsRoot"
Write-Host "==> logs:     $logDir"

cmd /c "call `"$vcvars`" > NUL 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
    }
}

if (Test-Path -LiteralPath $vsNinja) {
    $env:path = "$(Split-Path -Parent $vsNinja);$env:path"
}

if ($FullClean -and (Test-Path -LiteralPath (Join-Path $repoRoot 'build'))) {
    Write-Host '==> removing build directory'
    Remove-Item -LiteralPath (Join-Path $repoRoot 'build') -Recurse -Force
}

Write-Host "==> configuring preset '$Preset'"
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $vsCMake --preset $Preset -S $repoRoot 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $logDir 'configure.log')
Get-Content -LiteralPath (Join-Path $logDir 'configure.log') | Write-Host
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -ne 0) { throw "configure failed (exit $LASTEXITCODE), log: $(Join-Path $logDir 'configure.log')" }

if ($PlanOnly) {
    Write-Host '==> plan only, stopping before build'
    exit 0
}

Write-Host "==> building preset '$Preset'"
$ErrorActionPreference = 'Continue'
# `--build --preset` resolves CMakePresets.json from the *current* directory,
# which breaks when the script runs from anywhere but the repo root, build by
# binary dir instead (same dir the preset expands to, works from anywhere)
& $vsCMake --build (Join-Path $repoRoot 'build') 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $logDir 'build.log')
Get-Content -LiteralPath (Join-Path $logDir 'build.log') | Write-Host
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE), log: $(Join-Path $logDir 'build.log')" }

if ($Test) {
    Write-Host '==> running tests'
    & $vsCMake --build (Join-Path $repoRoot 'build') --target test
    if ($LASTEXITCODE -ne 0) { throw "tests failed (exit $LASTEXITCODE)" }
}

$summary = [ordered]@{
    preset   = $Preset
    config   = 'Release'
    result   = 'success'
    logDir   = $logDir
    binary   = Join-Path $repoRoot 'build\src\app\reverse-slop.exe'
    engine   = Join-Path $repoRoot 'build\src\engine\reverse-slop-engine.exe'
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logDir 'summary.json')

Write-Host '==> build succeeded'
Write-Host "==> binary: $($summary.binary)"
Write-Host "==> engine: $($summary.engine)"

# Tauri front end (the app)
# The Tauri UI is the shipped app; reverse-slop.exe (ImGui) is the legacy shell
# -NoFrontend skips this for a fast C++-only loop (the web build needs the Rust
# toolchain and node_modules, neither of which the engine or the ImGui shell
# depend on). The engine must already be built, tauri.conf.json bundles it as a
# resource from build\src\engine
if (-not $NoFrontend) {
    # The driver needs the WDK, which is not installed on every dev box. Build
    # it when possible; the tauri resource filter below skips it when absent
    & powershell -NoProfile -File (Join-Path $PSScriptRoot 'build_slopdrvr.ps1')
    if ($LASTEXITCODE -ne 0) {
        Write-Host '==> driver build failed (WDK missing?), bundling app without driver' -ForegroundColor Yellow
    }

    # Magicmida (Themida/WinLicense unpacker). The engine resolves it next to
    # itself (engine\tools\magicmida\<version>) before falling back to
    # %LOCALAPPDATA%. Keep the LOCALAPPDATA install as the source of truth
    # (tests and dev runs use it), then mirror it into build\ so the tauri
    # resource map can reference a repo-relative path
    $magicmidaVersion = '2026-05-14' # sync with kVersion (magicmida.cpp) and $release (install_magicmida.ps1)
    & powershell -NoProfile -File (Join-Path $PSScriptRoot 'install_magicmida.ps1')
    if ($LASTEXITCODE -ne 0) {
        Write-Host '==> magicmida install failed (offline?), bundling without the unpacker' -ForegroundColor Yellow
    }
    $magicmidaLocal = Join-Path $env:LOCALAPPDATA "reverse-slop\tools\magicmida\$magicmidaVersion"
    $magicmidaStaged = Join-Path $repoRoot 'build\tools\magicmida'
    if (Test-Path -LiteralPath $magicmidaLocal) {
        if (Test-Path -LiteralPath $magicmidaStaged) { Remove-Item -LiteralPath $magicmidaStaged -Recurse -Force }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $magicmidaStaged) | Out-Null
        Copy-Item -LiteralPath $magicmidaLocal -Destination $magicmidaStaged -Recurse
        Write-Host "==> magicmida staged: $magicmidaStaged"
    } else {
        Write-Host '==> magicmida not installed, bundling without the unpacker' -ForegroundColor Yellow
    }

    $appDir = Join-Path $repoRoot 'app'
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo not found, install the Rust toolchain (https://rustup.rs) to build the Tauri front end'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $appDir 'node_modules'))) {
        Write-Host '==> installing frontend dependencies'
        # npm chats on stderr; under ErrorActionPreference=Stop PowerShell 5.1
        # turns the first stderr line into a terminating error, flatten the
        # streams like the cmake calls below
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        Push-Location $appDir
        try {
            & npm install --no-audit --no-fund 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (Join-Path $logDir 'npm-install.log')
            $npmExit = $LASTEXITCODE
        } finally { Pop-Location }
        $ErrorActionPreference = $prevEap
        if ($npmExit -ne 0) { throw "npm install failed (exit $npmExit), log: $(Join-Path $logDir 'npm-install.log')" }
    }
    Write-Host '==> building tauri bundle'
    Push-Location $appDir
    # node + tauri.js directly: `npm run tauri -- build` loses the `--` to
    # PowerShell, and npx needs a node_modules/.bin shim npm does not always write
    $tauriCli = Join-Path $appDir 'node_modules\@tauri-apps\cli\tauri.js'
    try {
        # tauri hard-fails on missing resource files, so filter the bundle map
        # to what exists (e.g. slopdrvr.sys without the WDK). The override
        # carries the complete filtered resources map; the committed
        # tauri.conf.json stays authoritative for WDK machines
        $confPath = Join-Path $appDir 'src-tauri\tauri.conf.json'
        $conf = Get-Content -LiteralPath $confPath -Raw | ConvertFrom-Json
        $resources = [ordered]@{}
        foreach ($prop in $conf.bundle.resources.PSObject.Properties) {
            $src = Join-Path $repoRoot ($prop.Name -replace '^(\.\./)+', '')
            if (Test-Path -LiteralPath $src) { $resources[$prop.Name] = $prop.Value }
            else { Write-Host "==> resource missing, skipping: $($prop.Name)" }
        }
        # The driver stays out of tauri.conf.json (tauri-build hard-fails on
        # missing resource files and not every box has the WDK); add it back
        # through the override whenever it did build
        $driverSys = Join-Path $repoRoot 'build\driver\slopdrvr.sys'
        if (Test-Path -LiteralPath $driverSys) {
            $resources['../../build/driver/slopdrvr.sys'] = 'engine/slopdrvr.sys'
        } else {
            Write-Host '==> slopdrvr.sys absent, bundling without kernel driver'
        }
        if (Test-Path -LiteralPath $magicmidaStaged) {
            $resources['../../build/tools/magicmida'] = 'engine/tools/magicmida'
        } else {
            Write-Host '==> magicmida absent, bundling without the Themida unpacker'
        }
        $override = @{ bundle = @{ resources = $resources } }
        $overridePath = Join-Path $appDir 'src-tauri\tauri.build.conf.json'
        $override | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $overridePath
        # The tauri CLI logs its progress to stderr, which under
        # ErrorActionPreference=Stop kills PowerShell 5.1 as a NativeCommandError  
        # same flattening as the cmake/npm calls
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & node $tauriCli build --config $overridePath 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (Join-Path $logDir 'tauri.log')
        $tauriExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($tauriExit -ne 0) { throw "tauri build failed (exit $tauriExit), log: $(Join-Path $logDir 'tauri.log')" }
    } finally { Pop-Location }
    Write-Host "==> installer: $(Join-Path $appDir 'src-tauri\target\release\bundle')"

    # Portable layout: the exe plus the engine\ resource dir it looks for next to
    # itself, so the app runs off a copied folder with no installer and no build
    # tree. ponytail: a straight copy, Tauri has no portable bundle target
    $release = Join-Path $appDir 'src-tauri\target\release'
    $portable = Join-Path $repoRoot 'dist\reverse-slop'
    if (Test-Path -LiteralPath $portable) { Remove-Item -LiteralPath $portable -Recurse -Force }
    New-Item -ItemType Directory -Path $portable | Out-Null
    Copy-Item -LiteralPath (Join-Path $release 'reverse-slop-ui.exe') -Destination (Join-Path $portable 'reverse-slop.exe')
    Copy-Item -LiteralPath (Join-Path $release 'engine') -Destination $portable -Recurse
    Write-Host "==> portable: $(Join-Path $portable 'reverse-slop.exe')"
    Write-Host '==> portable manifest:'
    Get-ChildItem -LiteralPath $portable -Recurse -File |
        ForEach-Object { "    $($_.FullName.Substring($portable.Length + 1)) ($('{0:N1}' -f ($_.Length / 1KB)) KB)" } |
        Write-Host
}
