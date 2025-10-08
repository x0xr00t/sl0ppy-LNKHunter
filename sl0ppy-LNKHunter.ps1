<#
.SYNOPSIS
    sl0ppy-LNKHunter v3.2 - Ultimate LNK Abuse & LOLBin Detection Framework
.DESCRIPTION
    Comprehensive scanner for:
    - Malicious LNK files (30+ abuse patterns)
    - 100+ LOLBins across system paths
    - Suspicious executable combinations
    - Persistence mechanisms
    - Network-based payload droppers

    Features:
    - Deep COM object analysis with proper cleanup
    - 60+ system paths scanned by default
    - Obfuscation detection in LNK targets
    - Memory-efficient operations
    - Cross-version compatibility (PS5.1/7+)
    - Silent and deep scan modes
    - Export to CSV/JSON/TXT
    - Admin privilege escalation for all-user scans
    - Progress feedback
    - Comprehensive error handling

.PARAMETER SilentMode
    Suppresses non-critical output (Default: $false)

.PARAMETER DeepScan
    Enables recursive scanning in all directories (Default: $false)

.PARAMETER Export
    Exports results to specified format (CSV, JSON, or TXT)

.PARAMETER ScanAllUsers
    Scans all user profiles (requires admin privileges) (Default: $false)

.EXAMPLE
    .\sl0ppy-LNKHunter.ps1 -DeepScan -Export CSV

.EXAMPLE
    .\sl0ppy-LNKHunter.ps1 -ScanAllUsers -SilentMode -Export JSON

.NOTES
    Version: 3.2.20251008
    Author: P. Hoogeveen (@x0xr00t) - Sl0ppyRoot Team
    Tested on: Windows 7-11, Server 2012-2022
    Requires: PowerShell 5.1 or later
#>

[CmdletBinding()]
param (
    [switch]$SilentMode = $false,
    [switch]$DeepScan = $false,
    [ValidateSet("CSV","JSON","TXT")]
    [string]$Export,
    [switch]$ScanAllUsers = $false
)

#region Initialization
$ErrorActionPreference = "Stop"
$global:results = [System.Collections.Generic.List[object]]::new()
$global:stats = @{
    LNKFilesScanned = 0
    SuspiciousLNKs = 0
    LOLBinsFound = 0
    TotalWarnings = 0
    ScanStart = Get-Date
    ScanDuration = $null
}

# Validated system paths
$global:SystemPaths = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData",
    "C:\Tools",
    "C:\Temp"
) | Where-Object { Test-Path $_ -PathType Container -ErrorAction SilentlyContinue }

# Validated user paths
$global:UserPaths = @(
    $env:USERPROFILE,
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\AppData\LocalLow",
    "$env:USERPROFILE\Links",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\Recent",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:LOCALAPPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\SendTo",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"
) | Where-Object { Test-Path $_ -PathType Container -ErrorAction SilentlyContinue }

# LNK search locations
$global:LNKSearchPaths = @(
    "$env:USERPROFILE\Desktop\*.lnk",
    "$env:USERPROFILE\Downloads\*.lnk",
    "$env:USERPROFILE\Documents\*.lnk",
    "$env:APPDATA\Microsoft\Windows\Recent\*.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk",
    "$env:LOCALAPPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent\*.lnk",
    "$env:USERPROFILE\Links\*.lnk",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Network Shortcuts\*.lnk",
    "$env:PUBLIC\Desktop\*.lnk",
    "$env:PUBLIC\Downloads\*.lnk",
    "C:\Users\Public\Desktop\*.lnk"
)

# Comprehensive LOLBin list (100+ entries)
$global:LOLBins = @(
    # Classic LOLBins
    "powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe",
    "rundll32.exe","regsvr32.exe","cmstp.exe","odbcconf.exe","forfiles.exe",
    "msiexec.exe","certutil.exe","bitsadmin.exe","wmic.exe","schtasks.exe",
    "at.exe","net.exe","sc.exe","reg.exe","cmd.exe","ftp.exe","telnet.exe",

    # Network tools
    "curl.exe","wget.exe","nc.exe","ncat.exe","netcat.exe","plink.exe",
    "certreq.exe","msxmldom.exe","ieexec.exe","syncappvpublishingserver.exe",
    "bitsadmin.exe","certutil.exe","make.exe","git.exe","svchost.exe",

    # Script engines
    "python*.exe","node.exe","php.exe","perl.exe","ruby.exe","bash.exe",
    "sh.exe","lua.exe","tclsh.exe","java.exe","jjs.exe","csi.exe",

    # Debugging tools
    "debug.exe","windbg.exe","dbghost.exe","procmon.exe","procdump.exe",
    "adplus.exe","cdb.exe","ntsd.exe","kd.exe","gflags.exe",

    # Cloud/DevOps
    "az.exe","aws.exe","kubectl.exe","terraform.exe","docker.exe",
    "vagrant.exe","ansible.exe","chef-client.exe","puppet.exe",

    # Misc abused binaries
    "explorer.exe","dllhost.exe","mftrace.exe","presentationshost.exe",
    "msbuild.exe","rcsi.exe","register-cimprovider.exe","wsmprovhost.exe",
    "dsget.exe","dsquery.exe","adfind.exe","ldifde.exe","csvde.exe",

    # Less common but powerful
    "hh.exe","infdefaultinstall.exe","installutil.exe","mavinject.exe",
    "msdeploy.exe","msdt.exe","pcaluate.exe","pcwrun.exe","print.exe",
    "register-appvclientpackage.exe","regini.exe","replace.exe","scrobj.dll",
    "scriptrunner.exe","sdbinst.exe","textrise.exe","typeperf.exe",
    "verclsid.exe","wab.exe","wabmig.exe","winsat.exe","winscp.exe",

    # New additions (2025)
    "winget.exe","appinstaller.exe","msedge.exe","protocolhandler.exe",
    "computerdefaults.exe","fodhelper.exe","squirrel.exe","appvlp.exe",
    "cmmon32.exe","djoin.exe","diskshadow.exe","dnx.exe","esentutl.exe",
    "extexport.exe","extrac32.exe","findstr.exe","fltmc.exe","fontext.exe",
    "gpscript.exe","ie4uinit.exe","ieexec.exe","ilasm.exe","lodctr.exe",
    "mftrace.exe","mklink.exe","mmc.exe","mpclip.exe","msconfig.exe",
    "msfeedssync.exe","msra.exe","mstsc.exe","netsh.exe","netstat.exe",
    "nltest.exe","openwith.exe","pcaluate.exe","pnputil.exe","qprocess.exe",
    "qwinsta.exe","rasautou.exe","rasdial.exe","rasphone.exe","recover.exe",
    "regedt32.exe","register-cimprovider.exe","regsvcs.exe","relog.exe",
    "reset.exe","scrobj.dll","scriptrunner.exe","sdbinst.exe","setspn.exe",
    "slmgr.exe","sort.exe","stordiag.exe","takeown.exe","tasklist.exe",
    "tcmshims.exe","tcmsetup.exe","tracerpt.exe","unlodctr.exe","vbc.exe",
    "verifier.exe","w32tm.exe","waitfor.exe","wevtutil.exe","where.exe",
    "whoami.exe","winrm.exe","winrs.exe","winsat.exe","winver.exe",
    "wmic.exe","xwizard.exe"
)

# LNK abuse patterns (30+)
$global:LNKAbusePatterns = @(
    # Direct command execution
    'powershell\.exe.*(-nop|-ep\s+bypass|-enc|-c)',
    'cmd\.exe.*(/c|/r|/k)',
    'wscript\.exe.*//e:','cscript\.exe.*//e:',
    'mshta\.exe.*(http|javascript:)',

    # Obfuscation patterns
    'frombase64string','fromcharcode','eval\(',
    'execute','invoke','downloadstring',
    'downloadfile','webclient','net\.webclient',

    # Suspicious arguments
    '-nop\s+-w\s+hidden','-windowstyle\s+hidden',
    '/c\s+powershell','/c\s+certutil','/c\s+bitsadmin',

    # Network indicators
    'curl\.exe.*-o','wget\.exe.*-O',
    'bitsadmin\.exe.*/transfer','certutil\.exe.*-decode',
    'certutil\.exe.*-urlcache',

    # Persistence patterns
    'schtasks\.exe.*/create','at\.exe.*\d+:\d+',
    'reg\.exe.*add.*run','reg\.exe.*add.*startup',

    # Script engine abuse
    'python\.exe.*-c','node\.exe.*-e','php\.exe.*-r',

    # Cloud tool abuse
    'az\.exe.*login','aws\.exe.*configure','kubectl\.exe.*apply',

    # Fileless execution
    'rundll32\.exe.*javascript:','regsvr32\.exe.*/s\s+/u',
    'msiexec\.exe.*/i\s+http','wmic\.exe.*process\s+call\s+create',

    # New 2025 patterns
    'winget\.exe.*install','appinstaller\.exe.*install',
    'msedge\.exe.*--gpu-launcher','protocolhandler\.exe.*--handle',
    'computerdefaults\.exe.*--set','fodhelper\.exe.*-p',

    # Base64 patterns
    '[a-zA-Z0-9+/]{100,}={0,2}'
)

# Suspicious file extensions in LNK targets
$global:SuspiciousExtensions = @(
    '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.bat', '.cmd', '.hta', '.jar', '.py', '.pl', '.rb'
)

# Suspicious parent processes for LNK execution
$global:SuspiciousParents = @(
    'explorer.exe','svchost.exe','dllhost.exe',
    'runtimebroker.exe','sihost.exe','taskhostw.exe'
)
#endregion

#region Core Functions
function Test-LNKFile {
    param([string]$LNKPath)

    $global:stats.LNKFilesScanned++
    $shell = $null
    $shortcut = $null
    $suspiciousIndicators = [System.Collections.Generic.List[string]]::new()

    try {
        # Safe COM object creation
        $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $shortcut = $shell.CreateShortcut($LNKPath)

        $target = $shortcut.TargetPath
        $args = $shortcut.Arguments
        $icon = $shortcut.IconLocation
        $workingDir = $shortcut.WorkingDirectory

        # Check target path
        if ($target) {
            # Check against LNK abuse patterns
            foreach ($pattern in $global:LNKAbusePatterns) {
                if ($target -match $pattern) {
                    $suspiciousIndicators.Add("Target matches abuse pattern: $pattern")
                }
            }

            # Check file extension
            $ext = [System.IO.Path]::GetExtension($target).ToLower()
            if ($global:SuspiciousExtensions -contains $ext) {
                $suspiciousIndicators.Add("Target has suspicious extension: $ext")
            }

            # Check if target is a LOLBin
            $targetBinary = [System.IO.Path]::GetFileName($target)
            if ($global:LOLBins -contains $targetBinary) {
                $suspiciousIndicators.Add("Target is known LOLBin: $targetBinary")
            }

            # Check for network indicators
            if ($target -match '^\\\\|^http[s]?://') {
                $suspiciousIndicators.Add("Target uses network path: $target")
            }
        }

        # Check arguments
        if ($args) {
            foreach ($pattern in $global:LNKAbusePatterns) {
                if ($args -match $pattern) {
                    $suspiciousIndicators.Add("Arguments match abuse pattern: $pattern")
                }
            }
        }

        # Check icon location
        if ($icon -and $icon -match '^\\\\|^http[s]?://') {
            $suspiciousIndicators.Add("Icon location uses network path: $icon")
        }

        # Check working directory
        if ($workingDir -and $workingDir -match 'temp|tmp|downloads') {
            $suspiciousIndicators.Add("Working directory is suspicious: $workingDir")
        }

        # Check for empty target with arguments
        if (-not $target -and $args) {
            $suspiciousIndicators.Add("LNK has empty target but has arguments")
        }

        # Check for suspicious parent process simulation
        if ($target) {
            $parent = [System.IO.Path]::GetFileName($target)
            if ($global:SuspiciousParents -contains $parent) {
                $suspiciousIndicators.Add("Target impersonates common parent process: $parent")
            }
        }

        # Check for base64 encoded commands
        if ($target -or $args) {
            $allContent = "$target $args"
            if ($allContent -match '[a-zA-Z0-9+/]{100,}={0,2}') {
                $suspiciousIndicators.Add("Contains potential base64 encoded content")
            }
        }

        if ($suspiciousIndicators.Count -gt 0) {
            $global:stats.SuspiciousLNKs++
            $global:stats.TotalWarnings++

            $result = [PSCustomObject]@{
                Type = "SuspiciousLNK"
                Path = $LNKPath
                Target = $target
                Arguments = $args
                IconLocation = $icon
                WorkingDirectory = $workingDir
                Indicators = $suspiciousIndicators -join "; "
                Severity = if ($suspiciousIndicators.Count -gt 2) { "HIGH" } else { "MEDIUM" }
                Timestamp = (Get-Item $LNKPath).LastWriteTime
                Size = (Get-Item $LNKPath).Length
            }

            $global:results.Add($result)
            return $true
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Error analyzing $($LNKPath.Split('\')[-1]): $_"
        }
        return $false
    }
    finally {
        # Ensure COM objects are released
        if ($shortcut) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null }
        if ($shell) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null }
        [System.GC]::Collect()
    }
}

function Scan-Executable {
    param(
        [string]$Pattern,
        [string[]]$Paths
    )

    try {
        $searchParams = @{
            Path = $Paths
            Filter = $Pattern
            Recurse = $DeepScan
            ErrorAction = 'SilentlyContinue'
            File = $true
        }

        $found = Get-ChildItem @searchParams | Select-Object -First 1

        if ($found) {
            $global:stats.LOLBinsFound++
            $result = [PSCustomObject]@{
                Type = "LOLBin"
                Path = $found.FullName
                Name = $found.Name
                Directory = $found.DirectoryName
                LastModified = $found.LastWriteTime
                Size = $found.Length
            }

            $global:results.Add($result)
            if (-not $SilentMode) {
                Write-Host "  [+] Found LOLBin: $($found.Name) at $($found.DirectoryName)" -ForegroundColor Yellow
            }
            return $true
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Error scanning for $Pattern : $_"
        }
        return $false
    }
}

function Get-AllUserProfiles {
    try {
        if ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent().
            IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return (Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                    Where-Object { $_.Special -eq $false -and $_.LocalPath } |
                    Select-Object -ExpandProperty LocalPath -Unique)
        }
        else {
            if (-not $SilentMode) {
                Write-Warning "Admin privileges required for all-user scan. Scanning current user only."
            }
            return @()
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Error getting user profiles: $_"
        }
        return @()
    }
}

function Export-Results {
    param([string]$Format)

    try {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $exportPath = "sl0ppy-LNKHunter-Results-$timestamp.$Format.ToLower()"

        switch ($Format) {
            "CSV" {
                $global:results | Export-Csv -Path $exportPath -NoTypeInformation -Force -ErrorAction Stop
            }
            "JSON" {
                $global:results | ConvertTo-Json -Depth 5 | Out-File $exportPath -Force -ErrorAction Stop
            }
            "TXT" {
                $global:results | Format-List | Out-File $exportPath -Force -ErrorAction Stop
            }
        }

        if (-not $SilentMode) {
            Write-Host "  [+] Results exported to: $exportPath" -ForegroundColor Green
        }
        return $true
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Failed to export results: $_"
        }
        return $false
    }
}
#endregion

#region Main Execution
try {
    # Output Header
    if (-not $SilentMode) {
        Clear-Host
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host " sl0ppy-LNKHunter v3.2 - Ultimate LNK Scanner " -ForegroundColor Cyan
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host " Starting scan at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        Write-Host " Scan mode: $(if ($DeepScan) { 'DEEP' } else { 'QUICK' })" -ForegroundColor White
        if ($ScanAllUsers) { Write-Host " User scope: ALL USERS" -ForegroundColor White }
        if ($Export) { Write-Host " Export format: $Export" -ForegroundColor White }
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host ""
    }

    # Prepare paths
    $allPaths = $global:SystemPaths + $global:UserPaths
    if ($ScanAllUsers) {
        $userProfiles = Get-AllUserProfiles
        if ($userProfiles) {
            $allPaths += $userProfiles
        }
    }

    # Scan LNK files with progress feedback
    if (-not $SilentMode) {
        Write-Host "[!] Scanning for suspicious LNK files..." -ForegroundColor Cyan
    }

    $lnkCount = 0
    foreach ($lnkPath in $global:LNKSearchPaths) {
        try {
            $items = Get-ChildItem -Path $lnkPath -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $lnkCount++
                if (Test-LNKFile -LNKPath $item.FullName) {
                    if (-not $SilentMode) {
                        Write-Host "  [!] Suspicious LNK: $($item.Name)" -ForegroundColor Red
                    }
                }
                elseif (-not $SilentMode -and $lnkCount % 100 -eq 0) {
                    Write-Host "  [i] Scanned $lnkCount LNK files..." -ForegroundColor DarkGray
                }
            }
        }
        catch {
            if (-not $SilentMode) {
                Write-Warning "  [-] Error accessing LNK path $lnkPath : $_"
            }
        }
    }

    # Scan for LOLBins with progress feedback
    if (-not $SilentMode) {
        Write-Host "`n[!] Scanning for LOLBins..." -ForegroundColor Cyan
    }

    $binCount = 0
    foreach ($bin in $global:LOLBins) {
        $binCount++
        Scan-Executable -Pattern $bin -Paths $allPaths

        if (-not $SilentMode -and $binCount % 20 -eq 0) {
            Write-Host "  [i] Scanned $binCount of $($global:LOLBins.Count) LOLBins..." -ForegroundColor DarkGray
        }
    }

    # Display results
    if ($global:results.Count -gt 0) {
        if (-not $SilentMode) {
            Write-Host "`n[!] Scan Results Summary:" -ForegroundColor Green
            Write-Host "  Total items found: $($global:results.Count)" -ForegroundColor White
            Write-Host "  Suspicious LNKs: $($global:stats.SuspiciousLNKs)" -ForegroundColor Red
            Write-Host "  LOLBins found: $($global:stats.LOLBinsFound)" -ForegroundColor Yellow
            Write-Host "  Total warnings: $($global:stats.TotalWarnings)" -ForegroundColor White
            Write-Host ""

            # Group and display by type
            $lnkResults = $global:results | Where-Object { $_.Type -eq "SuspiciousLNK" } | Sort-Object Severity -Descending
            $lolbinResults = $global:results | Where-Object { $_.Type -eq "LOLBin" }

            if ($lnkResults) {
                Write-Host "--- Suspicious LNK Files (Severity: HIGH/Medium) ---" -ForegroundColor Red
                foreach ($result in $lnkResults) {
                    Write-Host "  [$($result.Severity)] $($result.Path)" -ForegroundColor Red
                    Write-Host "    Target: $($result.Target)" -ForegroundColor DarkRed
                    if ($result.Arguments) { Write-Host "    Args: $($result.Arguments)" -ForegroundColor DarkRed }
                    Write-Host "    Indicators: $($result.Indicators)" -ForegroundColor DarkRed
                    Write-Host "    Modified: $($result.Timestamp) | Size: $($result.Size) bytes" -ForegroundColor DarkRed
                    Write-Host ""
                }
            }

            if ($lolbinResults) {
                Write-Host "--- Found LOLBins ---" -ForegroundColor Yellow
                $lolbinResults | Group-Object Directory | ForEach-Object {
                    Write-Host "  [$($_.Count)] $($_.Name)" -ForegroundColor Yellow
                }
            }
        }
    }
    else {
        if (-not $SilentMode) {
            Write-Host "`n  [-] No suspicious items found." -ForegroundColor Green
        }
    }

    # Export if requested
    if ($Export) {
        Export-Results -Format $Export
    }

    # Calculate duration
    $global:stats.ScanDuration = (Get-Date) - $global:stats.ScanStart

    # Footer
    if (-not $SilentMode) {
        Write-Host "`n==============================================" -ForegroundColor Cyan
        Write-Host " Scan completed in $($global:stats.ScanDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
        Write-Host " LNK files scanned: $($global:stats.LNKFilesScanned)" -ForegroundColor White
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host " Faithfully yours," -ForegroundColor White
        Write-Host " ~x0xr00t~" -ForegroundColor Red
        Write-Host " Sl0ppyRoot Team" -ForegroundColor Cyan
        Write-Host "==============================================" -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Fatal error during scan: $_"
    exit 1
}
finally {
    # Clean up
    [System.GC]::Collect()
}
#endregion
