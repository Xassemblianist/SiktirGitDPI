# gui.ps1'in XAML'i ve yapisini admin haklari olmadan smoke-test eder.
# Pencere ACILMAZ - sadece yukleyebiliyor muyuz, butun control'lar bulunabiliyor mu kontrol.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$gui = Join-Path $PSScriptRoot '..\releases\x64\gui.ps1'
if (-not (Test-Path $gui)) { Write-Host "gui.ps1 not found at $gui" -ForegroundColor Red; exit 1 }

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$src = Get-Content -Raw -LiteralPath $gui

# Sadece XAML kismini cek.
$re = [regex]'(?ms)\[xml\]\$xaml = @''(.+?)''@'
$m = $re.Match($src)
if (-not $m.Success) { Write-Host "XAML literal not found" -ForegroundColor Red; exit 1 }
$xamlText = $m.Groups[1].Value

[xml]$xaml = $xamlText
try {
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-Host "XAML load failed: $_" -ForegroundColor Red
    exit 1
}

$expected = @(
    'ProfileCombo','AutoBtn','EditPresetBtn','DnsCheckBox','StatsCheckBox','FlowCheckBox',
    'StatsBox','InRate','ModRate','OutRate','TlsTotal','HttpTotal','LogBox','StartStopBtn',
    'ClearLogBtn','ServiceInstallBtn','ServiceUninstallBtn','StatusDot','StatusText',
    'StrategyHits'
)
$missing = @()
foreach ($n in $expected) {
    if ($null -eq $window.FindName($n)) { $missing += $n }
}
if ($missing.Count -gt 0) {
    Write-Host "Missing controls in XAML: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host "[ok] XAML parsed, all $($expected.Count) named controls present." -ForegroundColor Green
Write-Host "[ok] Window dimensions: $($window.Width) x $($window.Height)" -ForegroundColor Green

# Quick lint of the powershell syntax (parse the rest of the file).
$tokens = $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($gui, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    Write-Host "Parse errors:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host ("  L{0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
    exit 1
}

Write-Host "[ok] PowerShell parse: $($ast.EndBlock.Statements.Count) top-level statements, no errors." -ForegroundColor Green
