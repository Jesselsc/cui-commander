Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "== MSTechAlpine Fleet Commander Bootstrap (Windows) ==" -ForegroundColor Cyan

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$VenvDir    = Join-Path $RepoRoot ".venv"
$RequirementsPath = Join-Path $RepoRoot "requirements.txt"
$EvidenceDir = Join-Path $RepoRoot "evidence"
$AssetTagsPath = Join-Path $EvidenceDir "asset-tags.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-Tool {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PythonCommand {
    if (Test-Tool "py")     { return @("py", "-3") }
    if (Test-Tool "python") { return @("python") }
    Write-Host ""
    Write-Host "ERROR: Python 3.10+ not found." -ForegroundColor Red
    Write-Host "  Install from: https://python.org/downloads"
    Write-Host "  Tick 'Add Python to PATH' during install, then rerun this script."
    exit 1
}

function Install-Tool {
    param([string]$WingetId, [string]$ChocoId, [string]$FallbackUrl)
    if (Test-Tool "winget") {
        Write-Host "  Trying winget..."
        winget install --id $WingetId --silent --accept-package-agreements --accept-source-agreements 2>$null
        return
    }
    if (Test-Tool "choco") {
        Write-Host "  Trying Chocolatey..."
        choco install $ChocoId -y 2>$null
        return
    }
    Write-Host "  Auto-install unavailable. Download manually from: $FallbackUrl" -ForegroundColor Yellow
    Write-Host "  Network discovery will be skipped until nmap is installed."
    Write-Host "  Local diagnostic checks still run without it."
}

# ---------------------------------------------------------------------------
# Execution policy check — must pass before venv activation
# ---------------------------------------------------------------------------

$policy = Get-ExecutionPolicy -Scope CurrentUser
if ($policy -eq "Restricted" -or $policy -eq "Undefined") {
    Write-Host ""
    Write-Host "ERROR: PowerShell execution policy blocks script activation." -ForegroundColor Red
    Write-Host "  Run this once in PowerShell (as your normal user, not admin):"
    Write-Host "  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned" -ForegroundColor Cyan
    Write-Host "  Then rerun this script."
    exit 1
}

# ---------------------------------------------------------------------------
# Python venv setup
# ---------------------------------------------------------------------------

$pythonCmd = Get-PythonCommand

if (!(Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment..."
    if ($pythonCmd.Length -gt 1) {
        & $pythonCmd[0] $pythonCmd[1] -m venv $VenvDir
    } else {
        & $pythonCmd[0] -m venv $VenvDir
    }
}

$ActivateScript = Join-Path $VenvDir "Scripts\Activate.ps1"
if (!(Test-Path $ActivateScript)) {
    Write-Host "ERROR: venv activation script missing at $ActivateScript" -ForegroundColor Red
    exit 1
}
& $ActivateScript

Write-Host "Upgrading pip..."
python -m pip install --upgrade pip | Out-Null

if (Test-Path $RequirementsPath) {
    Write-Host "Installing Python dependencies..."
    pip install -r $RequirementsPath | Out-Null
}
pip install -e $RepoRoot | Out-Null

# ---------------------------------------------------------------------------
# Optional tools — try to auto-install, warn gracefully if not possible
# ---------------------------------------------------------------------------

if (!(Test-Tool "ssh") -or !(Test-Tool "scp")) {
    Write-Host "OpenSSH Client not found. Attempting to enable via Windows Optional Features..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
        Write-Host "  OpenSSH Client installed." -ForegroundColor Green
    } catch {
        Write-Host "  Could not auto-install OpenSSH Client (may need admin)." -ForegroundColor Yellow
        Write-Host "  Enable manually: Settings > System > Optional Features > OpenSSH Client"
        Write-Host "  Fleet SSH orchestration will not work until this is installed."
    }
}

if (!(Test-Tool "nmap")) {
    Write-Host "nmap not found. Attempting auto-install..." -ForegroundColor Yellow
    Install-Tool -WingetId "Insecure.Nmap" -ChocoId "nmap" -FallbackUrl "https://nmap.org/download"
    # Refresh PATH in current session
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")
}

if (!(Test-Tool "dot")) {
    Write-Host "Graphviz not found. Attempting auto-install..." -ForegroundColor Yellow
    Install-Tool -WingetId "Graphviz.Graphviz" -ChocoId "graphviz" -FallbackUrl "https://graphviz.org/download"
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")
}

if (!(Test-Path $EvidenceDir)) {
    New-Item -ItemType Directory -Path $EvidenceDir | Out-Null
}

if (!(Test-Path $AssetTagsPath)) {
    @'{
  "192.168.1.10": "CUI Asset",
  "192.168.1.20": "Security Protection Asset",
  "192.168.1.30": "Contractor Risk Managed Asset",
  "192.168.1.40": "Out-of-Scope"
}
'@ | Set-Content -Path $AssetTagsPath -Encoding UTF8
}

Write-Host ""
Write-Host "Environment ready." -ForegroundColor Green
Write-Host "Python : $(python --version)"
Write-Host "Venv   : $VenvDir"
if (Test-Tool "nmap") { Write-Host "nmap   : $((Get-Command nmap).Source)" -ForegroundColor Green }
else                  { Write-Host "nmap   : not installed — network discovery unavailable" -ForegroundColor Yellow }
if (Test-Tool "dot")  { Write-Host "dot    : $((Get-Command dot).Source)" -ForegroundColor Green }
else                  { Write-Host "dot    : not installed — SVG diagram unavailable" -ForegroundColor Yellow }
if (Test-Tool "ssh")  { Write-Host "ssh    : $((Get-Command ssh).Source)" -ForegroundColor Green }
else                  { Write-Host "ssh    : not installed — fleet SSH orchestration unavailable" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Hub security checks — run before processing any CUI-adjacent data
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "-- Hub Security Checks --" -ForegroundColor Cyan

# FIPS mode check (CM.L2-3.4.1 / SC.L2-3.13.8)
# This machine is a Security Protection Asset when running fleet diagnostics.
# FIPS mode should be enabled before processing CUI metadata.
try {
    $fipsKey = Get-ItemProperty `
        -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" `
        -Name Enabled -ErrorAction Stop
    if ($fipsKey.Enabled -eq 1) {
        Write-Host "  [GREEN ] FIPS mode: enabled on this hub." -ForegroundColor Green
    } else {
        Write-Host "  [YELLOW] FIPS mode: DISABLED. Enable via Group Policy or:" -ForegroundColor Yellow
        Write-Host "           Set-ItemProperty -Path 'HKLM:\...\FipsAlgorithmPolicy' -Name Enabled -Value 1" -ForegroundColor Yellow
        Write-Host "           (Requires reboot. Required for CUI-adjacent hub operations in 2026.)"
    }
} catch {
    Write-Host "  [YELLOW] FIPS mode: Could not read registry key. Verify manually." -ForegroundColor Yellow
}

# Unauthorized remote-access tool check (AC.L2-3.1.3)
# These tools create persistent unmanaged access paths — a C3PAO finding if undocumented.
$shadowTools = @{
    "TeamViewer"  = "C:\Program Files\TeamViewer\TeamViewer.exe"
    "AnyDesk"     = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
    "LogMeIn"     = "C:\Program Files (x86)\LogMeIn\x64\LogMeIn.exe"
    "GoToMyPC"    = "C:\Program Files (x86)\Citrix\GoToMyPC\g2svc.exe"
    "ScreenConnect" = "C:\Program Files (x86)\ScreenConnect Client*"
    "Splashtop"   = "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRService.exe"
    "Zoho Assist" = "C:\Program Files (x86)\ZohoMeeting\ZohoMeetingService.exe"
}
$foundShadow = @()
foreach ($tool in $shadowTools.GetEnumerator()) {
    if (Test-Path $tool.Value) {
        $foundShadow += $tool.Key
    }
}
# Also check running processes by name
$shadowProcs = @("teamviewer", "anydesk", "logmein", "screenconnect", "splashtop", "zohoassist")
foreach ($proc in $shadowProcs) {
    $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($running -and ($foundShadow -notcontains $proc)) {
        $foundShadow += "$proc (process running)"
    }
}
if ($foundShadow.Count -gt 0) {
    Write-Host "  [RED   ] Unauthorized remote-access tools detected: $($foundShadow -join ', ')" -ForegroundColor Red
    Write-Host "           Document in SSP or remove before C3PAO assessment. AC.L2-3.1.3 finding." -ForegroundColor Red
} else {
    Write-Host "  [GREEN ] No known unauthorized remote-access tools detected on this hub." -ForegroundColor Green
}
Write-Host ""

Write-Host "  1) Local diagnostic (this machine)"
Write-Host "  2) Full C3PAO evidence package — auto-detect subnet (recommended)"
Write-Host "  3) Discovery scan — specify CIDR manually"
Write-Host "  4) Discovery + fleet orchestration"
Write-Host "  5) Exit"
$choice = Read-Host "Selection [1-5]"
if ([string]::IsNullOrWhiteSpace($choice)) {
    $choice = "5"
}

switch ($choice) {
    "1" {
        fleet-commander --json-output (Join-Path $EvidenceDir "diagnostic.json")
    }
    "2" {
        fleet-commander `
            --discover-network auto `
            --auto-tag `
            --asset-tags $AssetTagsPath `
            --discovery-output (Join-Path $EvidenceDir "fleet-discovery.json") `
            --diagram-output (Join-Path $EvidenceDir "network-architecture.svg") `
            --sbom-output (Join-Path $EvidenceDir "sbom.json") `
            --srm (Join-Path $EvidenceDir "srm.xlsx") `
            --vuln-scan `
            --vuln-output (Join-Path $EvidenceDir "vulns.json") `
            --html-output (Join-Path $EvidenceDir "report.html") `
            --cloud-api `
            --sanitize `
            --json-output (Join-Path $EvidenceDir "diagnostic-c3pao.json")
    }
    "3" {
        $target = Read-Host "Enter CIDR/range (example 192.168.1.0/24)"
        if ([string]::IsNullOrWhiteSpace($target)) {
            Write-Host "No target provided. Exit."
            exit 0
        }
        fleet-commander `
            --discover-network $target `
            --auto-tag `
            --asset-tags $AssetTagsPath `
            --discovery-output (Join-Path $EvidenceDir "fleet-discovery.json") `
            --diagram-output (Join-Path $EvidenceDir "network-architecture.svg") `
            --json-output (Join-Path $EvidenceDir "diagnostic.json")
    }
    "4" {
        $target = Read-Host "Enter CIDR/range (example 192.168.1.0/24)"
        $fleetUser = Read-Host "Fleet SSH user"
        $fleetKey = Read-Host "SSH key path (blank for default key agent)"

        if ([string]::IsNullOrWhiteSpace($target) -or [string]::IsNullOrWhiteSpace($fleetUser)) {
            Write-Host "Target and fleet user are required. Exit."
            exit 0
        }

        $cmdArgs = @(
            "--discover-network", $target,
            "--auto-tag",
            "--asset-tags", $AssetTagsPath,
            "--discovery-output", (Join-Path $EvidenceDir "fleet-discovery.json"),
            "--diagram-output", (Join-Path $EvidenceDir "network-architecture.svg"),
            "--fleet-run",
            "--fleet-user", $fleetUser,
            "--json-output", (Join-Path $EvidenceDir "diagnostic.json")
        )

        if (![string]::IsNullOrWhiteSpace($fleetKey)) {
            $cmdArgs += @("--fleet-ssh-key", $fleetKey)
        }

        fleet-commander @cmdArgs
    }
    default {
        Write-Host "Exit."
    }
}

Write-Host ""
Write-Host "Done. Evidence artifacts are in $EvidenceDir"
