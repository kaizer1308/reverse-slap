[CmdletBinding()]
param(
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$appDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'app'
Push-Location $appDir
try {
    # Replace the resource map with an empty array (not an empty map, which
    # JSON merge-patch would merge). Sidecars arrive only in the packaging job.
    # All runtime settings, permissions, icons and embedded web assets stay intact.
    $config = Join-Path $appDir 'src-tauri\tauri.build.conf.json'
    @{ bundle = @{ resources = @() } } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $config
    if (-not (Test-Path 'node_modules')) {
        & npm ci --prefer-offline --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    }
    # CI: tests run in their own parallel lane, never on the compile path
    if (-not $SkipTests) {
        & npm test
        if ($LASTEXITCODE -ne 0) { throw 'frontend tests failed' }
    }
    & node node_modules/@tauri-apps/cli/tauri.js build --no-bundle --config $config -- --locked
    if ($LASTEXITCODE -ne 0) { throw 'frontend compilation failed' }
    if (-not (Test-Path 'src-tauri/target/release/reverse-slop-ui.exe')) {
        throw 'frontend binary missing after compilation'
    }
} finally { Pop-Location }
