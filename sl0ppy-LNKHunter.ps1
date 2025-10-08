<#
.SYNOPSIS
    sl0ppy-LNKHunter v3.3 - LNK Abuse & LOLBin Detection Framework (improved)
.NOTES
    Version: 3.3.20251008
    Author: P. Hoogeveen (@x0xr00t) - Sl0ppyRoot Team (patched)
    Compatibility: PowerShell 5.1+ and PowerShell 7+
.DESCRIPTION
    Improvements over v3.2:
    - Fixed Get-ChildItem usage in Scan-Executable
    - Deduped/cleaned LOLBin list
    - Safer base64 detection (context-aware)
    - Export path, debug logging, allowlist, parallel scanning, hybrid C# fast enumeration
    - Better error handling and reporting
#>

[CmdletBinding()]
param (
    [switch]$SilentMode = $false,
    [switch]$DeepScan = $false,
    [ValidateSet("CSV","JSON","TXT")]
    [string]$Export,
    [switch]$ScanAllUsers = $false,

    # New options
    [string]$OutputPath = ".",
    [switch]$DebugLog = $false,
    [string[]]$AllowlistPaths = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)"),
    [int]$Parallel = 1,                # >1 uses ForEach-Object -Parallel on PS7
    [switch]$UseHybrid = $false        # embed C# enumerator for faster enumeration
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

# Ensure OutputPath exists
try {
    $OutputPathFull = [System.IO.Path]::GetFullPath($OutputPath)
    if (-not (Test-Path -Path $OutputPathFull)) {
        New-Item -Path $OutputPathFull -ItemType Directory -Force | Out-Null
    }
}
catch {
    Write-Error "Invalid OutputPath specified: $_"
    exit 1
}

# Debug logfile
if ($DebugLog) {
    $logTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $global:DebugLogFile = Join-Path -Path $OutputPathFull -ChildPath "sl0ppy-LNKHunter-debug-$logTimestamp.log"
    "Debug log started at $(Get-Date)" | Out-File -FilePath $global:DebugLogFile -Encoding UTF8
}
function Log-Debug {
    param($msg)
    if ($DebugLog) {
        $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
        $entry | Out-File -FilePath $global:DebugLogFile -Append -Encoding UTF8
    }
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

# Comprehensive LOLBin list (sanitized + deduped)
$rawLOLBins = @(
    "powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe",
    "rundll32.exe","regsvr32.exe","cmstp.exe","odbcconf.exe","forfiles.exe",
    "msiexec.exe","certutil.exe","bitsadmin.exe","wmic.exe","schtasks.exe",
    "at.exe","net.exe","sc.exe","reg.exe","cmd.exe","ftp.exe","telnet.exe",
    "curl.exe","wget.exe","nc.exe","ncat.exe","netcat.exe","plink.exe",
    "certreq.exe","msxmldom.exe","ieexec.exe","syncappvpublishingserver.exe",
    "make.exe","git.exe","svchost.exe","python.exe","python*.exe","node.exe",
    "php.exe","perl.exe","ruby.exe","bash.exe","sh.exe","lua.exe","tclsh.exe",
    "java.exe","jjs.exe","csi.exe","debug.exe","windbg.exe","dbghost.exe",
    "procmon.exe","procdump.exe","adplus.exe","cdb.exe","ntsd.exe","kd.exe",
    "gflags.exe","az.exe","aws.exe","kubectl.exe","terraform.exe","docker.exe",
    "vagrant.exe","ansible.exe","chef-client.exe","puppet.exe","explorer.exe",
    "dllhost.exe","presentationshost.exe","msbuild.exe","rcsi.exe",
    "register-cimprovider.exe","wsmprovhost.exe","dsget.exe","dsquery.exe",
    "adfind.exe","ldifde.exe","csvde.exe","hh.exe","infdefaultinstall.exe",
    "installutil.exe","msdeploy.exe","msdt.exe","pcwrun.exe","print.exe",
    "register-appvclientpackage.exe","regini.exe","replace.exe","scrobj.dll",
    "scriptrunner.exe","sdbinst.exe","typeperf.exe","verclsid.exe","wab.exe",
    "wabmig.exe","winsat.exe","winscp.exe","winget.exe","appinstaller.exe",
    "msedge.exe","protocolhandler.exe","computerdefaults.exe","fodhelper.exe",
    "squirrel.exe","diskshadow.exe","dnx.exe","esentutl.exe","findstr.exe",
    "fltmc.exe","mklink.exe","mmc.exe","mpclip.exe","msconfig.exe",
    "msfeedssync.exe","msra.exe","mstsc.exe","netsh.exe","netstat.exe",
    "nltest.exe","openwith.exe","pnputil.exe","qprocess.exe","qwinsta.exe",
    "rasdial.exe","rasphone.exe","recover.exe","regedt32.exe","regsvcs.exe",
    "relog.exe","reset.exe","setspn.exe","slmgr.exe","sort.exe","takeown.exe",
    "tasklist.exe","tracerpt.exe","unlodctr.exe","vbc.exe","verifier.exe",
    "w32tm.exe","waitfor.exe","wevtutil.exe","where.exe","whoami.exe",
    "winrm.exe","winrs.exe","winver.exe","xwizard.exe"
)

# sanitize & dedupe
$global:LOLBins = $rawLOLBins | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique

# LNK abuse patterns (kept but tuned)
$global:LNKAbusePatterns = @(
    'powershell\.exe.*(-nop|-ep\s+bypass|-enc\b|-EncodedCommand|-c\b)',
    'cmd\.exe.*(/c|/r|/k)',
    'wscript\.exe.*//e:','cscript\.exe.*//e:',
    'mshta\.exe.*(http|javascript:)',
    'frombase64string','fromcharcode','eval\(','invoke-?expression',
    'downloadstring','downloadfile','net\.webclient',
    '-nop\s+-w\s+hidden','-windowstyle\s+hidden',
    '/c\s+powershell','/c\s+certutil','/c\s+bitsadmin',
    'curl\.exe.*-o','wget\.exe.*-O','bitsadmin\.exe.*/transfer',
    'certutil\.exe.*-decode','certutil\.exe.*-urlcache',
    'schtasks\.exe.*/create','at\.exe.*\d+:\d+','reg\.exe.*add.*run',
    'python\.exe.*-c','node\.exe.*-e','php\.exe.*-r',
    'az\.exe.*login','aws\.exe.*configure','kubectl\.exe.*apply',
    'rundll32\.exe.*javascript:','regsvr32\.exe.*/s\s+/u','msiexec\.exe.*/i\s+http',
    'wmic\.exe.*process\s+call\s+create',
    'winget\.exe.*install','appinstaller\.exe.*install',
    'msedge\.exe.*--gpu-launcher','protocolhandler\.exe.*--handle',
    'computerdefaults\.exe.*--set','fodhelper\.exe.*-p'
)

# Suspicious file extensions in LNK targets
$global:SuspiciousExtensions = @('.ps1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.bat','.cmd','.hta','.jar','.py','.pl','.rb')

# Suspicious parent process names
$global:SuspiciousParents = @('explorer.exe','svchost.exe','dllhost.exe','runtimebroker.exe','sihost.exe','taskhostw.exe')
#endregion

#region Embedded hybrid C# enumerator (optional)
if ($UseHybrid) {
    $csharp = @"
using System;
using System.Collections.Generic;
using System.IO;
public static class FastEnum {
    public static IEnumerable<string> EnumerateFiles(string path, string pattern, bool recursive) {
        try {
            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            foreach (var file in Directory.EnumerateFiles(path, pattern, option)) {
                yield return file;
            }
        } catch (Exception) {
            yield break;
        }
    }
}
"@
    try {
        Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction Stop
        Log-Debug "Hybrid C# enumerator loaded."
    }
    catch {
        Log-Debug "Failed to add C# type: $_"
        if (-not $SilentMode) { Write-Warning "Hybrid enumerator unavailable; falling back to PowerShell enumeration." }
        $UseHybrid = $false
    }
}
#endregion

#region Helper functions
function Safe-ReleaseComObject {
    param([object]$obj)
    if ($null -eq $obj) { return }
    try {
        # Release until there are no references left (safe pattern)
        while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) -gt 0) { }
    } catch {
        # ignore
    }
}

function Is-InAllowlist {
    param([string]$path)
    if (-not $path) { return $false }
    foreach ($a in $AllowlistPaths) {
        if ($path.StartsWith($a, [System.StringComparison]::InvariantCultureIgnoreCase)) { return $true }
    }
    return $false
}
#endregion

#region Core Functions
function Test-LNKFile {
    param([string]$LNKPath)

    $global:stats.LNKFilesScanned++
    $shell = $null
    $shortcut = $null
    $suspiciousIndicators = [System.Collections.Generic.List[string]]::new()

    try {
        $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        # CreateShortcut throws if path invalid
        $shortcut = $shell.CreateShortcut($LNKPath)

        $target = $shortcut.TargetPath
        $args = $shortcut.Arguments
        $icon = $shortcut.IconLocation
        $workingDir = $shortcut.WorkingDirectory

        # Normalize strings
        $target = if ($target) { $target.Trim() } else { $null }
        $args = if ($args) { $args.Trim() } else { $null }
        $icon = if ($icon) { $icon.Trim() } else { $null }
        $workingDir = if ($workingDir) { $workingDir.Trim() } else { $null }

        # Check target path patterns
        if ($target) {
            foreach ($pattern in $global:LNKAbusePatterns) {
                if ($target -match $pattern) {
                    $suspiciousIndicators.Add("Target matches abuse pattern: $pattern")
                }
            }

            # Suspicious extension
            try {
                $ext = [System.IO.Path]::GetExtension($target).ToLower()
                if ($global:SuspiciousExtensions -contains $ext) {
                    $suspiciousIndicators.Add("Target has suspicious extension: $ext")
                }
            } catch { }

            # Target binary (file name)
            try {
                $targetBinary = [System.IO.Path]::GetFileName($target)
                if ($global:LOLBins -contains $targetBinary) {
                    # If allowlisted path, mark informational instead of suspicious
                    if (Is-InAllowlist($target)) {
                        $suspiciousIndicators.Add("Target is known LOLBin (allowlisted path): $targetBinary")
                    } else {
                        $suspiciousIndicators.Add("Target is known LOLBin: $targetBinary")
                    }
                }
            } catch { }

            # network path
            if ($target -match '^\\\\|^http[s]?://') {
                $suspiciousIndicators.Add("Target uses network path: $target")
            }
        }

        # Check arguments separately (more sensitive)
        if ($args) {
            foreach ($pattern in $global:LNKAbusePatterns) {
                if ($args -match $pattern) {
                    $suspiciousIndicators.Add("Arguments match abuse pattern: $pattern")
                }
            }
        }

        # Icon network location
        if ($icon -and $icon -match '^\\\\|^http[s]?://') {
            $suspiciousIndicators.Add("Icon location uses network path: $icon")
        }

        # Suspicious working directory
        if ($workingDir -and $workingDir -match 'temp|tmp|downloads') {
            $suspiciousIndicators.Add("Working directory is suspicious: $workingDir")
        }

        # Empty target but arguments
        if (-not $target -and $args) {
            $suspiciousIndicators.Add("LNK has empty target but has arguments")
        }

        # Impersonation of parent process name
        if ($target) {
            try {
                $parent = [System.IO.Path]::GetFileName($target)
                if ($global:SuspiciousParents -contains $parent) {
                    $suspiciousIndicators.Add("Target impersonates common parent process: $parent")
                }
            } catch {}
        }

        # Context-aware base64 detection:
        # Only flag base64 if seen with powershell -enc/EncodedCommand or other explicit markers
        if ($target -or $args) {
            $allContent = "$target $args"
            if ($allContent -match '(?:-enc\b|-EncodedCommand\b|powershell\.exe).*([A-Za-z0-9+/]{80,}={0,2})') {
                $suspiciousIndicators.Add("Contains potential base64 encoded content used with encoded command")
            }
        }

        if ($suspiciousIndicators.Count -gt 0) {
            $global:stats.SuspiciousLNKs++
            $global:stats.TotalWarnings++

            # Get timestamp and size safely
            $timestamp = $null
            $size = $null
            try {
                $fi = Get-Item -LiteralPath $LNKPath -ErrorAction Stop
                $timestamp = $fi.LastWriteTime
                $size = $fi.Length
            } catch {
                $timestamp = Get-Date
                $size = 0
            }

            # Severity: weighted scoring (simple)
            $score = 0
            foreach ($ind in $suspiciousIndicators) {
                if ($ind -match 'network path|base64|EncodedCommand|powershell') { $score += 3 }
                elseif ($ind -match 'LOLBin') { $score += 1 }
                else { $score += 2 }
            }
            $severity = if ($score -ge 6) { "HIGH" } elseif ($score -ge 3) { "MEDIUM" } else { "LOW" }

            $result = [PSCustomObject]@{
                Type = "SuspiciousLNK"
                Path = $LNKPath
                Target = $target
                Arguments = $args
                IconLocation = $icon
                WorkingDirectory = $workingDir
                Indicators = $suspiciousIndicators -join "; "
                Severity = $severity
                Timestamp = $timestamp
                Size = $size
            }

            $global:results.Add($result)
            return $true
        }

        return $false
    }
    catch {
        Log-Debug "Error analyzing $LNKPath : $_"
        if (-not $SilentMode) {
            Write-Warning "Error analyzing $($LNKPath.Split('\')[-1]): $_"
        }
        return $false
    }
    finally {
        Safe-ReleaseComObject $shortcut
        Safe-ReleaseComObject $shell
        [System.GC]::Collect()
    }
}

function Scan-Executable {
    param(
        [string]$Pattern,
        [string[]]$Paths
    )
    try {
        foreach ($p in $Paths) {
            if (-not $p) { continue }
            if (-not (Test-Path $p)) { continue }

            # If using hybrid enumerator
            if ($UseHybrid -and (Get-Command -Name "FastEnum" -ErrorAction SilentlyContinue) -ne $null) {
                try {
                    $enumerable = [FastEnum]::EnumerateFiles($p, $Pattern, [bool]$DeepScan)
                    foreach ($foundPath in $enumerable) {
                        if (-not $foundPath) { continue }
                        $foundInfo = Get-Item -LiteralPath $foundPath -ErrorAction SilentlyContinue
                        if ($foundInfo) {
                            $global:stats.LOLBinsFound++
                            $result = [PSCustomObject]@{
                                Type = "LOLBin"
                                Path = $foundInfo.FullName
                                Name = $foundInfo.Name
                                Directory = $foundInfo.DirectoryName
                                LastModified = $foundInfo.LastWriteTime
                                Size = $foundInfo.Length
                            }
                            $global:results.Add($result)
                            if (-not $SilentMode) { Write-Host "  [+] Found LOLBin: $($foundInfo.Name) at $($foundInfo.DirectoryName)" -ForegroundColor Yellow }
                            return $true
                        }
                    }
                } catch {
                    Log-Debug "Hybrid scan failed for $p pattern $Pattern : $_"
                    # fallback to native enumeration below
                }
            }

            # PowerShell enumeration (works in PS5.1+)
            if ($DeepScan) {
                $gciParams = @{ Path = $p; Filter = $Pattern; Recurse = $true; ErrorAction = 'SilentlyContinue' }
            } else {
                $gciParams = @{ Path = $p; Filter = $Pattern; ErrorAction = 'SilentlyContinue' }
            }

            # prefer -File when available
            try {
                $found = Get-ChildItem @gciParams -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1
            } catch {
                # older PS may not accept -File on some wildcards; use fallback
                $found = Get-ChildItem @gciParams -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
            }

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
        return $false
    }
    catch {
        Log-Debug "Error scanning for $Pattern : $_"
        if (-not $SilentMode) {
            Write-Warning "Error scanning for $Pattern : $_"
        }
        return $false
    }
}

function Get-AllUserProfiles {
    try {
        $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return (Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                    Where-Object { $_.Special -eq $false -and $_.LocalPath -and $_.LocalPath -match 'C:\\Users\\' } |
                    Select-Object -ExpandProperty LocalPath -Unique)
        }
        else {
            if (-not $SilentMode) { Write-Warning "Admin privileges required for all-user scan. Scanning current user only." }
            return @()
        }
    }
    catch {
        Log-Debug "Error getting user profiles: $_"
        if (-not $SilentMode) { Write-Warning "Error getting user profiles: $_" }
        return @()
    }
}

function Export-Results {
    param([string]$Format)

    try {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $exportPath = Join-Path -Path $OutputPathFull -ChildPath "sl0ppy-LNKHunter-Results-$timestamp.$($Format.ToLower())"

        switch ($Format) {
            "CSV" {
                $global:results | Export-Csv -Path $exportPath -NoTypeInformation -Force -ErrorAction Stop
            }
            "JSON" {
                $global:results | ConvertTo-Json -Depth 6 | Out-File $exportPath -Force -ErrorAction Stop
            }
            "TXT" {
                $global:results | Format-List | Out-File $exportPath -Force -ErrorAction Stop
            }
        }

        if (-not $SilentMode) {
            Write-Host "  [+] Results exported to: $exportPath" -ForegroundColor Green
        }
        Log-Debug "Exported results to $exportPath"
        return $true
    }
    catch {
        Log-Debug "Failed to export results: $_"
        if (-not $SilentMode) { Write-Warning "Failed to export results: $_" }
        return $false
    }
}
#endregion

#region Main Execution
try {
    if (-not $SilentMode) {
        Clear-Host
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host " sl0ppy-LNKHunter v3.3 - Ultimate LNK Scanner " -ForegroundColor Cyan
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host " Starting scan at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        Write-Host " Scan mode: $(if ($DeepScan) { 'DEEP' } else { 'QUICK' })" -ForegroundColor White
        Write-Host " Hybrid mode: $($UseHybrid.IsPresent -or $UseHybrid)" -ForegroundColor White
        Write-Host " OutputPath: $OutputPathFull" -ForegroundColor White
        if ($ScanAllUsers) { Write-Host " User scope: ALL USERS" -ForegroundColor White }
        if ($Export) { Write-Host " Export format: $Export" -ForegroundColor White }
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host ""
    }

    # Prepare paths
    $allPaths = @()
    $allPaths += $global:SystemPaths
    $allPaths += $global:UserPaths

    if ($ScanAllUsers) {
        $userProfiles = Get-AllUserProfiles
        if ($userProfiles) {
            $allPaths += $userProfiles
        }
    }

    # Unique paths
    $allPaths = $allPaths | Where-Object { $_ } | Select-Object -Unique

    # LNK scan
    if (-not $SilentMode) { Write-Host "[!] Scanning for suspicious LNK files..." -ForegroundColor Cyan }

    $lnkCount = 0
    foreach ($lnkPath in $global:LNKSearchPaths) {
        try {
            $items = Get-ChildItem -Path $lnkPath -ErrorAction SilentlyContinue -Force
            foreach ($item in $items) {
                if (-not $item) { continue }
                $lnkCount++
                $isSuspicious = Test-LNKFile -LNKPath $item.FullName
                if ($isSuspicious) {
                    if (-not $SilentMode) { Write-Host "  [!] Suspicious LNK: $($item.Name)" -ForegroundColor Red }
                }
                elseif (-not $SilentMode -and ($lnkCount % 100 -eq 0)) {
                    Write-Host "  [i] Scanned $lnkCount LNK files..." -ForegroundColor DarkGray
                }
            }
        }
        catch {
            Log-Debug "Error accessing LNK path $lnkPath : $_"
            if (-not $SilentMode) { Write-Warning "  [-] Error accessing LNK path $lnkPath : $_" }
        }
    }

    # LOLBin scan
    if (-not $SilentMode) { Write-Host "`n[!] Scanning for LOLBins..." -ForegroundColor Cyan }

    $binCount = 0

    # If PS7+ and Parallel >1 we can run parallelized checks for each LOLBin pattern
    $canParallel = ($PSVersionTable.PSVersion.Major -ge 7) -and ($Parallel -gt 1)

    if ($canParallel) {
        # Use ForEach-Object -Parallel across LOLBins
        $scriptBlock = {
            param($bin, $allPaths, $DeepScan, $UseHybrid, $OutputPathFull)
            Import-Module Microsoft.PowerShell.Core -ErrorAction SilentlyContinue
            # copy of Scan-Executable logic (minimal)
            foreach ($p in $allPaths) {
                if (-not $p) { continue }
                if (-not (Test-Path $p)) { continue }
                try {
                    if ($DeepScan) {
                        $found = Get-ChildItem -Path $p -Filter $bin -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
                    } else {
                        $found = Get-ChildItem -Path $p -Filter $bin -File -ErrorAction SilentlyContinue | Select-Object -First 1
                    }
                } catch {
                    $found = Get-ChildItem -Path $p -Filter $bin -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
                }
                if ($found) { return $found.FullName }
            }
            return $null
        }

        $parallelResults = $global:LOLBins | ForEach-Object -Parallel {
            & $using:scriptBlock $_ $using:allPaths $using:DeepScan $using:UseHybrid $using:OutputPathFull
        } -ThrottleLimit $Parallel

        foreach ($pr in $parallelResults) {
            if ($pr) {
                $fi = Get-Item -LiteralPath $pr -ErrorAction SilentlyContinue
                if ($fi) {
                    $global:stats.LOLBinsFound++
                    $res = [PSCustomObject]@{
                        Type = "LOLBin"
                        Path = $fi.FullName
                        Name = $fi.Name
                        Directory = $fi.DirectoryName
                        LastModified = $fi.LastWriteTime
                        Size = $fi.Length
                    }
                    $global:results.Add($res)
                    if (-not $SilentMode) { Write-Host "  [+] Found LOLBin: $($fi.Name) at $($fi.DirectoryName)" -ForegroundColor Yellow }
                }
            }
        }
    }
    else {
        foreach ($bin in $global:LOLBins) {
            $binCount++
            Scan-Executable -Pattern $bin -Paths $allPaths
            if (-not $SilentMode -and ($binCount % 20 -eq 0)) {
                Write-Host "  [i] Scanned $binCount of $($global:LOLBins.Count) LOLBins..." -ForegroundColor DarkGray
            }
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
            $lnkResults = $global:results | Where-Object { $_.Type -eq "SuspiciousLNK" } | Sort-Object @{Expression = {$_.Severity}; Descending=$true}
            $lolbinResults = $global:results | Where-Object { $_.Type -eq "LOLBin" }

            if ($lnkResults) {
                Write-Host "--- Suspicious LNK Files (Severity: HIGH/MEDIUM/LOW) ---" -ForegroundColor Red
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
        if (-not $SilentMode) { Write-Host "`n  [-] No suspicious items found." -ForegroundColor Green }
    }

    # Export if requested
    if ($Export) { Export-Results -Format $Export }

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
        Write-Host " Sl0ppyRoot Team (patched v3.3)" -ForegroundColor Cyan
        Write-Host "==============================================" -ForegroundColor Cyan
    }
}
catch {
    Log-Debug "Fatal error during scan: $_"
    Write-Error "Fatal error during scan: $_"
    exit 1
}
finally {
    [System.GC]::Collect()
    Log-Debug "Scan ended at $(Get-Date). Stats: $(ConvertTo-Json $global:stats -Depth 3)"
}
#endregion
