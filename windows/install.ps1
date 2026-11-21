# AgentWatch – installation på Windows
# Kør fra repo-mappen (eller dobbeltklik install.bat):
#   powershell -ExecutionPolicy Bypass -File windows\install.ps1
#
# Scriptet:
#  1. installerer Python 3.12 og nmap via winget, hvis de mangler
#  2. laver et virtuelt miljø i %LOCALAPPDATA%\AgentWatch og installerer AgentWatch dér
#  3. opretter config (~\.agentwatch\config.yaml) med dit lokale netværk
#  4. laver genveje på skrivebordet: "AgentWatch" og "AgentWatch (administrator)"

param(
    [switch]$SkipNmap,
    [switch]$NoShortcuts
)
$ErrorActionPreference = "Stop"
$RepoRoot   = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA "AgentWatch"
$VenvDir    = Join-Path $InstallDir "venv"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

if (-not (Test-Path (Join-Path $RepoRoot "pyproject.toml"))) {
    throw "Kør scriptet fra AgentWatch-repoet (windows\install.ps1). Fandt ikke pyproject.toml i $RepoRoot"
}

# ---------- Python ----------
Step "Tjekker Python"
function Find-Python {
    foreach ($c in @("py -3.13", "py -3.12", "py -3.11", "python")) {
        $parts = $c.Split(" ")
        $extra = @()
        if ($parts.Length -gt 1) { $extra = $parts[1..($parts.Length-1)] }
        if (-not (Have $parts[0])) { continue }
        try {
            $v = & $parts[0] @extra -c "import sys; print(sys.version_info >= (3, 11))" 2>$null
            if ($v -eq "True") { return $c }
        } catch {}
    }
    foreach ($p in @("$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
                     "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")) {
        if (Test-Path $p) { return "`"$p`"" }
    }
    return $null
}
$py = Find-Python
if (-not $py) {
    if (-not (Have winget)) { throw "Python 3.11+ mangler, og winget findes ikke. Installer Python fra python.org og kør scriptet igen." }
    Write-Host "Installerer Python 3.12 (bruger-installation) ..."
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
    $py = Find-Python
    if (-not $py) { throw "Python blev installeret, men blev ikke fundet. Åbn et nyt PowerShell-vindue og kør scriptet igen." }
}
Write-Host "Bruger: $py"

# ---------- nmap ----------
if (-not $SkipNmap) {
    Step "Tjekker nmap"
    $nmapPaths = @("${env:ProgramFiles(x86)}\Nmap\nmap.exe", "$env:ProgramFiles\Nmap\nmap.exe")
    $nmap = (Get-Command nmap -ErrorAction SilentlyContinue).Source
    if (-not $nmap) { $nmap = $nmapPaths | Where-Object { Test-Path $_ } | Select-Object -First 1 }
    if ($nmap) {
        Write-Host "Fundet: $nmap"
    } elseif (Have winget) {
        Write-Host "Installerer nmap (kræver administrator – godkend UAC-dialogen; Npcap-installeren kan spørge undervejs) ..."
        winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
    } else {
        Write-Warning "nmap mangler. Hent installeren fra https://nmap.org/download.html (inkl. Npcap)."
    }
}

# ---------- virtuelt miljø + AgentWatch ----------
Step "Installerer AgentWatch i $VenvDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    Invoke-Expression "& $py -m venv `"$VenvDir`""
}
$vpy = Join-Path $VenvDir "Scripts\python.exe"
& $vpy -m pip install --upgrade pip --quiet
& $vpy -m pip install "$RepoRoot[all]" --quiet
if ($LASTEXITCODE -ne 0) { throw "pip install fejlede" }
$aw = Join-Path $VenvDir "Scripts\agentwatch.exe"

# ---------- config ----------
Step "Opretter config"
$cfg = Join-Path $env:USERPROFILE ".agentwatch\config.yaml"
if (Test-Path $cfg) { Write-Host "Findes allerede: $cfg" } else { & $aw init }

# ---------- genveje ----------
if (-not $NoShortcuts) {
    Step "Laver genveje på skrivebordet"
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shell = New-Object -ComObject WScript.Shell
    function New-Shortcut($name, $admin) {
        $path = Join-Path $desktop "$name.lnk"
        $s = $shell.CreateShortcut($path)
        $s.TargetPath = $aw
        $s.Arguments = "gui --open"
        $s.WorkingDirectory = $InstallDir
        $s.Description = "AgentWatch netværksinventar"
        $s.Save()
        if ($admin) {
            # Sæt "Kør som administrator"-flaget i .lnk-filen (byte 0x15, bit 0x20)
            $bytes = [IO.File]::ReadAllBytes($path)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [IO.File]::WriteAllBytes($path, $bytes)
        }
    }
    New-Shortcut "AgentWatch" $false
    New-Shortcut "AgentWatch (administrator)" $true
}

Step "Færdig"
Write-Host @"
Start GUI'en:        dobbeltklik 'AgentWatch' på skrivebordet  (eller: $aw gui --open)
Fuld scanning:       brug 'AgentWatch (administrator)' – giver OS-detektion og UDP
Kommandolinje:       $aw scan | devices | export -f cyclonedx -o inv.json | analyze
Config:              $cfg   (tjek 'networks' og 'dns')

Første gang spørger Windows Firewall måske om Python må bruge netværket –
tillad på 'Private netværk', ellers virker mDNS/SSDP-discovery ikke.
"@
