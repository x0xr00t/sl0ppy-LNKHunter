<#
.SYNOPSIS
    sl0ppy-LNKHunter – Scanner for abusable executables and LOLBins on Windows systems.

.DESCRIPTION
    This script scans common system and user directories to find vulnerable executables
    that can be abused for privilege escalation, or living-off-the-land attacks.
    Ideal for red teams and penetration testers seeking post-exploitation vectors.
    
.PARAMETER silentMode
    When specified, limits output to essential information only.

.AUTHOR
    P. Hoogeveen (@x0xr00t) – Sl0ppyRoot Team

.VERSION
    20251805

.TOOLNAME
    sl0ppy-LNKHunter

.IMPACT
    Privilege Escalation · Execution Vector Discovery · LOLBin Enumeration

.METHODS
    File System Enumeration · Executable Search in Key System Paths

.LICENSE
    Sl0ppyRed™ CyberOps Arsenal – Authorized Red Team Use Only

.NOTES
    Use responsibly and ensure all actions comply with applicable laws and policies.
#>

param (
    [switch]$silentMode
)

# Scanner to detect vulnerable executables in common directories
function Scan-Executable {
    param (
        [string]$pattern
    )

    # Common search paths for executables
    $searchPaths = @(
        "C:\Windows\System32", 
        "C:\Windows\SysWOW64", 
        "C:\Program Files", 
        "C:\Program Files (x86)", 
        "$env:USERPROFILE"
    )

    foreach ($path in $searchPaths) {
        try {
            # Perform directory search for vulnerable executables
            $found = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                Write-Host "  [+] Found vulnerable executable: $($found.FullName)" -ForegroundColor Yellow
                return $found.FullName
            }
        } catch {
            Write-Host "  [-] Error accessing path: $path - $_" -ForegroundColor Red
        }
    }

    Write-Host "  [-] No vulnerable executables found for pattern '$pattern'." -ForegroundColor Red
    return $null
}

# Function to find vulnerable executables based on search patterns
function Find-VulnerableExecutables {
    $vulnerablePatterns = @(
        "notepad.exe", "calc.exe", "mshta.exe", "certutil.exe", 
        "powershell.exe", "wscript.exe", "cscript.exe", 
        "schtasks.exe", "cmd.exe", "at.exe", "taskkill.exe",
        "powershell_ise.exe", "wmic.exe", "rundll32.exe", 
        "msiexec.exe", "explorer.exe", "net.exe", "ftp.exe", 
        "curl.exe", "wget.exe"
    )

    $foundExecutables = @()

    foreach ($pattern in $vulnerablePatterns) {
        $executable = Scan-Executable -pattern $pattern
        if ($executable) {
            $foundExecutables += $executable
        }
    }

    return $foundExecutables
}

# Output Header
Write-Host "======================" -ForegroundColor Cyan
Write-Host "Vulnerable Executable Scanner" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan

# Scan for vulnerable executables
$vulnerableExecutables = Find-VulnerableExecutables

if ($vulnerableExecutables.Count -gt 0) {
    Write-Host "  [+] Vulnerable Executables Found:" -ForegroundColor Green
    $vulnerableExecutables | ForEach-Object { 
        Write-Host "    -> $_" -ForegroundColor Yellow 
    }

    if ($silentMode) {
        Write-Host "  [*] Silent Mode: Only essential output is shown." -ForegroundColor Blue
    }
} else {
    Write-Host "  [-] No vulnerable executables found." -ForegroundColor Red
}

Write-Host ""
Write-Host "======================" -ForegroundColor Cyan
Write-Host "Disclaimer: Use this tool responsibly. Ensure compliance with laws and regulations." -ForegroundColor Yellow
Write-Host "======================" -ForegroundColor Cyan
Write-Host "Faithfully yours," -ForegroundColor White
Write-Host "~x0xr00t~" -ForegroundColor Red
Write-Host "======================" -ForegroundColor Cyan
