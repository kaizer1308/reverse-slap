[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'reverse-slop\tools\magicmida\2026-05-14'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$release = '2026-05-14'
$packages = @(
    @{
        Arch = 'x86'
        Url = "https://github.com/Hendi48/Magicmida/releases/download/$release/Magicmida.zip"
        Sha256 = 'efe8e676efd5920c6e1636a1b8f9847513986433959e429eebecf8e8f5ab5146'
    },
    @{
        Arch = 'x64'
        Url = "https://github.com/Hendi48/Magicmida/releases/download/$release/Magicmida64.zip"
        Sha256 = '6ec3262a6632218513dcaaf1cdd17b4d131bbbbc9ad349e4a0c28789ca92070c'
    }
)

if (-not $env:LOCALAPPDATA -and -not $PSBoundParameters.ContainsKey('InstallRoot')) {
    throw 'LOCALAPPDATA is not set; pass -InstallRoot explicitly'
}

$tempRoot = Join-Path $env:TEMP "reverse-slop-magicmida-$PID"
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($package in $packages) {
        $destination = Join-Path $InstallRoot $package.Arch
        if ((Test-Path -LiteralPath (Join-Path $destination 'Magicmida.exe')) -and -not $Force) {
            Write-Host "==> $($package.Arch) already installed: $destination"
            continue
        }

        $archive = Join-Path $tempRoot "$($package.Arch).zip"
        Write-Host "==> downloading Magicmida $($package.Arch) $release"
        Invoke-WebRequest -Uri $package.Url -OutFile $archive -UseBasicParsing
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $package.Sha256) {
            throw "SHA-256 mismatch for $($package.Arch): expected $($package.Sha256), got $actual"
        }

        if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force
        }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
        Write-Host "==> installed $($package.Arch): $destination"
    }

    $sourceNotice = @(
        "Magicmida $release is GPLv3 software maintained at:",
        'https://github.com/Hendi48/Magicmida',
        '',
        'The downloaded x64 package contains ScyllaHide components:',
        'https://github.com/x64dbg/ScyllaHide',
        '',
        'Use the corresponding tagged source when redistributing these binaries.'
    )
    Set-Content -LiteralPath (Join-Path $InstallRoot 'SOURCE.txt') -Value $sourceNotice -Encoding ASCII
    Write-Host "==> Magicmida ready: $InstallRoot"
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
