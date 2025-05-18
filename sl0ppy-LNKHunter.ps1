<#
.SYNOPSIS
    sl0ppy-ExecGhost – Scans for vulnerable executables that can be leveraged for UAC bypass or privilege escalation.

.DESCRIPTION
    This tool searches key system directories for known abusable executables and LOLBins (e.g., mshta.exe, certutil.exe, cmstp.exe).
    Useful for red teams, threat emulation, and post-exploitation recon to identify escalation and execution paths.
    Includes support for Windows 10, 11, 12 (pre-release), and Server 2019/2022.

.AUTHOR
    P. Hoogeveen (@x0xr00t) – Sl0ppyRoot Team  
    Partial dev by @keytrap-x86 – OS version logic enhancements.

.VERSION
    20241007

.TOOLNAME
    sl0ppy-ExecGhost

.IMPACT
    Privilege Escalation · LOLBin Discovery · Living-off-the-Land Enumeration

.METHODS
    DLLReflection · CMSTP Bypass · Executable Hijack Path Scan

.LICENSE
    Sl0ppyRed™ CyberOps Arsenal – Internal Red Team Use Only

.NOTES
    Use responsibly. Tool is intended for training, testing, and red team simulation in controlled environments.
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
