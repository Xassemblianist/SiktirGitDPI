# SiktirGitDPI - Release paketleyici.
#
# Yapilan isler:
#   1) MinGW ile statik sgdpi.exe ve testleri build et
#   2) Testleri calistir, basarisizsa cik
#   3) releases/x64/ icindeki tum .cmd ve .txt'leri staging'e kopyala
#   4) sgdpi.exe + WinDivert.dll/sys + presets/'i staging'e kopyala
#   5) staging'i sgdpi-vX.Y.Z-win64.zip olarak ZIP'le
#   6) SHA256 hash'ini yazdir
#
# Kullanim:
#   powershell -ExecutionPolicy Bypass -File scripts\package.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Version 0.2.0
#   powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -SkipBuild   # mevcut binary'yi kullan

[CmdletBinding()]
param(
    [string] $Version   = '0.2.0',
    [switch] $SkipBuild,
    [switch] $SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir   = Join-Path $RepoRoot 'build\mingw'
$StagingDir = Join-Path $RepoRoot ('build\release\sgdpi-v{0}-win64' -f $Version)
$ZipFile    = Join-Path $RepoRoot ('build\release\sgdpi-v{0}-win64.zip' -f $Version)

function Step([string]$msg) { Write-Host "[..] $msg" -ForegroundColor Cyan }
function Ok  ([string]$msg) { Write-Host "[ok] $msg" -ForegroundColor Green }
function Die ([string]$msg) { Write-Host "[!!] $msg" -ForegroundColor Red; exit 1 }

# ----- 1) Build ------------------------------------------------------------
if (-not $SkipBuild) {
    Step "Building (MinGW + WinDivert)..."
    Push-Location $RepoRoot
    try {
        $bash = "C:\Program Files\Git\bin\bash.exe"
        if (-not (Test-Path $bash)) { $bash = "C:\msys64\usr\bin\bash.exe" }
        if (-not (Test-Path $bash)) { $bash = "bash" }
        # Wrap bash in a cmd /c with chcp 65001 so the OS+toolchain agree
        # on UTF-8 for the cwd path. PowerShell-direct bash launches end up
        # with a legacy code page that mangles "Masaüstü" -> "Masa?st?".
        $cwd = (Get-Location).Path
        $cmdLine = "chcp 65001 >nul && cd /d `"$cwd`" && `"$bash`" -c `"./scripts/build-mingw.sh`""
        cmd /c $cmdLine
        if ($LASTEXITCODE -ne 0) { Die "Build failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
} else {
    if (-not (Test-Path (Join-Path $BuildDir 'sgdpi.exe'))) {
        Die "sgdpi.exe not found at $BuildDir - drop -SkipBuild or build manually."
    }
    Step "Skipping build, using existing binary."
}

# ----- 2) Tests -----------------------------------------------------------
if (-not $SkipTests) {
    Step "Running unit tests..."
    $TestExe = Join-Path $BuildDir 'sgdpi_tests.exe'
    if (Test-Path $TestExe) {
        & $TestExe
        if ($LASTEXITCODE -ne 0) { Die "Tests failed (exit $LASTEXITCODE)" }
        Ok "All tests passed."
    } else {
        Write-Host "[..] sgdpi_tests.exe not found - skipping" -ForegroundColor Yellow
    }
}

# ----- 3) Staging ---------------------------------------------------------
Step "Staging at $StagingDir"
if (Test-Path $StagingDir) { Remove-Item -Recurse -Force $StagingDir }
New-Item -ItemType Directory -Path $StagingDir | Out-Null

# Copy launchers + readme.
Copy-Item -Path (Join-Path $RepoRoot 'releases\x64\*') -Destination $StagingDir -Recurse

# Copy binaries + DLL/sys.
Copy-Item -Path (Join-Path $BuildDir 'sgdpi.exe')      -Destination $StagingDir
Copy-Item -Path (Join-Path $BuildDir 'WinDivert.dll')  -Destination $StagingDir
Copy-Item -Path (Join-Path $BuildDir 'WinDivert64.sys') -Destination $StagingDir

# Copy presets.
Copy-Item -Path (Join-Path $RepoRoot 'presets')        -Destination $StagingDir -Recurse

# Copy LICENSE + top-level README at repo root.
Copy-Item -Path (Join-Path $RepoRoot 'LICENSE')        -Destination (Join-Path $StagingDir 'LICENSE.txt')
Copy-Item -Path (Join-Path $RepoRoot 'README.md')      -Destination (Join-Path $StagingDir 'README.md')

# Drop a build manifest with version and contents hash list.
$manifest = "SiktirGitDPI v$Version`r`nBuilt: $(Get-Date -Format 'u')`r`n`r`nFiles:`r`n"
Get-ChildItem -Path $StagingDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($StagingDir.Length + 1)
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower()
    $manifest += ("  {0,-50} {1}`r`n" -f $rel, $hash)
}
Set-Content -LiteralPath (Join-Path $StagingDir 'MANIFEST.txt') -Value $manifest -Encoding utf8

Ok ("Staged {0} files" -f (Get-ChildItem -Recurse -File $StagingDir).Count)

# ----- 4) Zip -------------------------------------------------------------
Step "Compressing to $ZipFile"
if (Test-Path $ZipFile) { Remove-Item -Force $ZipFile }
Compress-Archive -Path (Join-Path $StagingDir '*') -DestinationPath $ZipFile -CompressionLevel Optimal
$zipSize = [math]::Round((Get-Item $ZipFile).Length / 1KB, 1)
$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipFile).Hash.ToLower()

Ok ("Created {0}  ({1} KB)" -f $ZipFile, $zipSize)
Write-Host "      SHA256: $zipHash" -ForegroundColor DarkGray

# ----- 5) Summary ---------------------------------------------------------
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "  Release pakedi hazir." -ForegroundColor Yellow
Write-Host "  Dosya:  $ZipFile"
Write-Host "  GitHub'a yuklemek icin:  gh release create v$Version `"$ZipFile`""
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
