# SiktirGitDPI - WinDivert SDK indirme scripti.
#
# Bu script https://github.com/basil00/WinDivert/releases adresindeki en son
# WinDivert sürümünü indirip third_party/windivert/ altına açar. CMake bu
# dizini bekliyor.

[CmdletBinding()]
param(
    [string] $Version = '2.2.2',
    [string] $RepoRoot = '',
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve repo root after parameter binding so PSScriptRoot is reliably set.
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

$Dest = Join-Path $RepoRoot 'third_party\windivert'

if ((Test-Path $Dest) -and (-not $Force)) {
    if (Test-Path (Join-Path $Dest 'include\windivert.h')) {
        Write-Host "[ok] WinDivert already present at $Dest" -ForegroundColor Green
        Write-Host "     (re-run with -Force to redownload)"
        exit 0
    }
}

$ZipName = "WinDivert-$Version-A.zip"
$Url     = "https://github.com/basil00/WinDivert/releases/download/v$Version/$ZipName"
$Tmp     = Join-Path $env:TEMP $ZipName

Write-Host "[..] Downloading $Url"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $Tmp -UseBasicParsing
} catch {
    Write-Host "[!!] Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "     Tarayicinla $Url adresini ac, .zip dosyasini indir,"
    Write-Host "     icindeki klasoru third_party/windivert/ olarak kopyala."
    exit 1
}

if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
$ParentTmp = Join-Path $env:TEMP "wd_extract_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $ParentTmp | Out-Null
Expand-Archive -Path $Tmp -DestinationPath $ParentTmp -Force

# Releases extract to a directory like 'WinDivert-2.2.2-A'. Move the
# contents up so we land at third_party/windivert/{include,x64,...}.
$inner = Get-ChildItem -Path $ParentTmp -Directory | Select-Object -First 1
if (-not $inner) {
    Write-Host "[!!] Unexpected zip layout - no top-level directory" -ForegroundColor Red
    exit 1
}
New-Item -ItemType Directory -Path $Dest | Out-Null
Get-ChildItem -Path $inner.FullName | Move-Item -Destination $Dest

Remove-Item -Recurse -Force $ParentTmp
Remove-Item -Force $Tmp

# Sanity check.
if (-not (Test-Path (Join-Path $Dest 'include\windivert.h'))) {
    Write-Host "[!!] include/windivert.h missing - extract layout unexpected" -ForegroundColor Red
    exit 1
}
Write-Host "[ok] WinDivert SDK installed at $Dest" -ForegroundColor Green
