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
