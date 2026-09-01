[CmdletBinding()]
param(
    [string]$WdkVersion = '10.0.26100.0',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$srcRoot  = Join-Path $repoRoot 'driver\slopdrvr\src'
$wdkInc = "C:\Program Files (x86)\Windows Kits\10\Include\$WdkVersion"
$wdkLib = "C:\Program Files (x86)\Windows Kits\10\Lib\$WdkVersion"

$requiredWdk = @(
    (Join-Path $wdkInc 'km\ntifs.h'),
    (Join-Path $wdkInc 'shared\ntdef.h'),
    (Join-Path $wdkLib 'km\x64\ntoskrnl.lib'),
    (Join-Path $wdkLib 'km\x64\libcntpr.lib'),
    (Join-Path $wdkLib 'um\x64\ntdll.lib')
)
foreach ($p in $requiredWdk) {
    if (-not (Test-Path -LiteralPath $p)) {
        throw "WDK driver component missing: $p"
    }
}

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

$cl  = Join-Path $vsRoot 'VC\Tools\MSVC'
$clVer = (Get-ChildItem $cl | Sort-Object Name -Descending | Select-Object -First 1).Name
$binDir  = Join-Path $cl "$clVer\bin\Hostx64\x64"
$incDirs = @(
    (Join-Path $cl "$clVer\include"),
    (Join-Path $wdkInc 'km'),
    (Join-Path $wdkInc 'shared'),
    (Join-Path $wdkInc 'ucrt'),
    $srcRoot
)
$libDirs = @(
    (Join-Path $cl "$clVer\lib\x64"),
    (Join-Path $wdkLib 'km\x64'),
    (Join-Path $wdkLib 'um\x64')
)

$outDir = Join-Path $repoRoot 'build\driver'
if ($Clean -and (Test-Path $outDir)) {
    Remove-Item -Recurse -Force $outDir
}
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$incs = ($incDirs | ForEach-Object { "/I`"$_`"" }) -join ' '
$libs = ($libDirs | ForEach-Object { "/LIBPATH:`"$_`"" }) -join ' '

$sources = Get-ChildItem $srcRoot -Recurse -Filter '*.cpp' |
           ForEach-Object { $_.FullName }
if (-not $sources) { throw "no sources found under $srcRoot" }

$objs = @()
foreach ($src in $sources) {
    $obj = Join-Path $outDir ([IO.Path]::GetFileNameWithoutExtension($src) + '.obj')
    if (Test-Path $obj) {
        if ((Get-Item $src).LastWriteTime -le (Get-Item $obj).LastWriteTime) {
            Write-Host "== skip $(Split-Path -Leaf $src) (up to date)"
            $objs += $obj
            continue
        }
    }
    $objs += $obj
    Write-Host "==> cl $(Split-Path -Leaf $src)"
    & cmd /c "`"$binDir\cl.exe`" /nologo /c /kernel /std:c++20 /W3 /O2 /GS- /guard:cf /Zc:__cplusplus /FS /D_AMD64_ /DAMD64 /DWIN32 /D_NO_CRT_STDIO_INLINE /DPOOL_NX_OPTIN_AUTO /DSLOP_NET_DEBUG /Zp8 $incs /Fo`"$obj`" `"$(Resolve-Path -LiteralPath $src)`"" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $src" }
}

$rsp = Join-Path $outDir 'slopdrvr_link.rsp'
@(
    '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/INCREMENTAL:NO',
    '/MACHINE:X64', '/ENTRY:DriverEntry', "/OUT:`"$outDir\slopdrvr.sys`""
) + ($libDirs | ForEach-Object { "/LIBPATH:`"$_`"" }) +
    @('ntoskrnl.lib', 'hal.lib', 'libcntpr.lib') +
    ($objs | ForEach-Object { "`"$_`"" }) |
    Set-Content -LiteralPath $rsp -Encoding ascii

Write-Host '==> link slopdrvr.sys'
& cmd /c "`"$binDir\link.exe`" @`"$rsp`"" 2>&1
if ($LASTEXITCODE -ne 0) { throw 'link failed' }

$sys = Get-Item (Join-Path $outDir 'slopdrvr.sys')
Write-Host "==> built $($sys.FullName) ($('{0:N0}' -f $sys.Length) bytes)"
