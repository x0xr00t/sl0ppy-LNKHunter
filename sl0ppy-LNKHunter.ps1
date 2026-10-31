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

    # ==========================================================================
    # 01. POWERSHELL EXECUTION ABUSE
    # ==========================================================================

    'powershell(?:\.exe)?\s+.*(?:-nop\b|-noprofile\b)',
    'powershell(?:\.exe)?\s+.*(?:-ep\s+bypass|-executionpolicy\s+bypass)',
    'powershell(?:\.exe)?\s+.*(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,})',
    'powershell(?:\.exe)?\s+.*-windowstyle\s+(?:hidden|h)',
    'powershell(?:\.exe)?\s+.*-w\s+hidden',
    'powershell(?:\.exe)?\s+.*-noninteractive',
    'powershell(?:\.exe)?\s+.*-noni\b',
    'powershell(?:\.exe)?\s+.*-sta\b',
    'powershell(?:\.exe)?\s+.*-mta\b',
    'powershell(?:\.exe)?\s+.*-command\s+.*(?:downloadstring|invoke-expression)',
    'powershell(?:\.exe)?\s+.*(?:iex|invoke-expression)',
    'powershell(?:\.exe)?\s+.*frombase64string',
    'powershell(?:\.exe)?\s+.*fromcharcode',
    'powershell(?:\.exe)?\s+.*(?:reflection\.assembly|loadfrom|loadfile)',
    'powershell(?:\.exe)?\s+.*(?:add-mppreference|set-mppreference)',
    'powershell(?:\.exe)?\s+.*(?:disable-realtimemonitoring|exclusionpath)',
    'powershell(?:\.exe)?\s+.*(?:amsiutils|amsiinitfailed)',
    'powershell(?:\.exe)?\s+.*(?:virtualprotect|marshal\.copy)',
    'powershell(?:\.exe)?\s+.*(?:invoke-webrequest|iwr)\s+.*https?://',
    'powershell(?:\.exe)?\s+.*(?:invoke-restmethod|irm)\s+.*https?://',
    'powershell(?:\.exe)?\s+.*(?:downloadstring|downloadfile)',
    'powershell(?:\.exe)?\s+.*(?:start-bitstransfer|net\.webclient)',
    'powershell(?:\.exe)?\s+.*(?:set-executionpolicy|unrestricted)',
    'powershell(?:\.exe)?\s+.*(?:add-type|dynamicmethod)',
    'powershell(?:\.exe)?\s+.*(?:scriptblock::create|createnestedpipeline)',
    'powershell(?:\.exe)?\s+.*(?:-file\s+.*\\appdata\\|\\temp\\)',
    'powershell(?:\.exe)?\s+.*(?:-encodedarguments|-e\s+[A-Za-z0-9+/=]{20,})',

    # ==========================================================================
    # 02. POWERSHELL 7 / ALTERNATE HOSTS
    # ==========================================================================

    'pwsh(?:\.exe)?\s+.*(?:-nop\b|-noprofile\b)',
    'pwsh(?:\.exe)?\s+.*(?:-ep\s+bypass|-executionpolicy\s+bypass)',
    'pwsh(?:\.exe)?\s+.*(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,})',
    'pwsh(?:\.exe)?\s+.*(?:-w\s+hidden|-windowstyle\s+hidden)',
    'pwsh(?:\.exe)?\s+.*(?:downloadstring|downloadfile|frombase64string)',
    'powershell_ise(?:\.exe)?\s+.*(?:-file|-command)',

    # ==========================================================================
    # 03. CMD / COMMAND INTERPRETER ABUSE
    # ==========================================================================

    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:powershell|pwsh)',
    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:mshta|rundll32|regsvr32)',
    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:certutil|bitsadmin)',
    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:curl|wget)',
    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:wscript|cscript)',
    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:schtasks|reg\s+add)',
    'cmd(?:\.exe)?\s+.*(?:/c|/r|/k)\s+.*(?:\\appdata\\|\\temp\\)',
    'cmd(?:\.exe)?\s+.*(?:&&|\|\|)\s+.*(?:powershell|mshta|rundll32)',
    'cmd(?:\.exe)?\s+.*(?:>nul\s+2>&1|2>&1\s+>nul).*(?:certutil|schtasks)',
    'cmd(?:\.exe)?\s+.*(?:set\s+/p|for\s+/f).*(?:powershell|certutil)',

    # ==========================================================================
    # 04. WINDOWS SCRIPT HOST / SCRIPT EXECUTION
    # ==========================================================================

    'wscript(?:\.exe)?\s+.*(?:\.vbs|\.js|\.jse|\.vbe|\.wsf)',
    'cscript(?:\.exe)?\s+.*(?:\.vbs|\.js|\.jse|\.vbe|\.wsf)',
    '(?:wscript|cscript)(?:\.exe)?\s+.*//e:',
    '(?:wscript|cscript)(?:\.exe)?\s+.*//b.*//nologo',
    'wscript(?:\.exe)?\s+.*\\appdata\\',
    'cscript(?:\.exe)?\s+.*\\temp\\',
    'wscript(?:\.exe)?\s+.*https?://',
    'cscript(?:\.exe)?\s+.*https?://',
    'scriptcontrol.*(?:eval|execute)',
    'msscriptcontrol.*(?:eval|execute)',

    # ==========================================================================
    # 05. MSHTA / HTML APPLICATION EXECUTION
    # ==========================================================================

    'mshta(?:\.exe)?\s+.*https?://',
    'mshta(?:\.exe)?\s+.*javascript:',
    'mshta(?:\.exe)?\s+.*vbscript:',
    'mshta(?:\.exe)?\s+.*about:',
    'mshta(?:\.exe)?\s+.*(?:\.hta|\.sct)',
    'mshta(?:\.exe)?\s+.*eval\s*\(',
    'mshta(?:\.exe)?\s+.*activexobject',
    'mshta(?:\.exe)?\s+.*xmlhttp',
    'mshta(?:\.exe)?\s+.*responsebody',
    'mshta(?:\.exe)?\s+.*execscript',

    # ==========================================================================
    # 06. RUNDLL32 / REGSVR32 / DLL PROXY EXECUTION
    # ==========================================================================

    'rundll32(?:\.exe)?\s+.*javascript:',
    'rundll32(?:\.exe)?\s+.*vbscript:',
    'rundll32(?:\.exe)?\s+.*url\.dll',
    'rundll32(?:\.exe)?\s+.*shell32\.dll.*control_rundll',
    'rundll32(?:\.exe)?\s+.*(?:\\appdata\\|\\temp\\).*\.dll',
    'rundll32(?:\.exe)?\s+.*(?:javascript|mshtml|scrobj)',
    'regsvr32(?:\.exe)?\s+.*(?:/s|/i:).*(?:https?://|scrobj\.dll)',
    'regsvr32(?:\.exe)?\s+.*scrobj\.dll',
    'regsvr32(?:\.exe)?\s+.*https?://',
    'regsvr32(?:\.exe)?\s+.*\.sct',
    'regsvr32(?:\.exe)?\s+.*(?:\\temp\\|\\appdata\\)',
    'regasm(?:\.exe)?\s+.*\.dll',
    'regsvcs(?:\.exe)?\s+.*\.dll',

    # ==========================================================================
    # 07. CERTUTIL / BITSADMIN / FILE TRANSFER LOLBINS
    # ==========================================================================

    'certutil(?:\.exe)?\s+.*-urlcache',
    'certutil(?:\.exe)?\s+.*-decode',
    'certutil(?:\.exe)?\s+.*-decodehex',
    'certutil(?:\.exe)?\s+.*-encode',
    'certutil(?:\.exe)?\s+.*-split.*-f',
    'certutil(?:\.exe)?\s+.*https?://',
    'bitsadmin(?:\.exe)?\s+.*\/transfer',
    'bitsadmin(?:\.exe)?\s+.*\/download',
    'bitsadmin(?:\.exe)?\s+.*\/addfile',
    'bitsadmin(?:\.exe)?\s+.*\/setnotifycmdline',
    'bitsadmin(?:\.exe)?\s+.*https?://',
    'curl(?:\.exe)?\s+.*(?:-o|-O|--output)\s+.*',
    'curl(?:\.exe)?\s+.*(?:-k|--insecure).*(?:https?://)',
    'wget(?:\.exe)?\s+.*(?:-O|--output-document)',
    'wget(?:\.exe)?\s+.*https?://',
    'ftp(?:\.exe)?\s+.*(?:-s:|get\s+|put\s+)',
    'tftp(?:\.exe)?\s+.*(?:get|put)',
    'expand(?:\.exe)?\s+.*-r.*\.cab',
    'esentutl(?:\.exe)?\s+.*\/y.*\/d',

    # ==========================================================================
    # 08. ARCHIVE / PAYLOAD EXTRACTION
    # ==========================================================================

    'tar(?:\.exe)?\s+.*(?:-xf|-xvf).*(?:\\temp\\|\\appdata\\)',
    '7z(?:\.exe)?\s+.*(?:x|e)\s+.*(?:\\temp\\|\\appdata\\)',
    '7za(?:\.exe)?\s+.*(?:x|e)\s+',
    'expand(?:\.exe)?\s+.*\.cab.*(?:\\temp\\|\\appdata\\)',
    'makecab(?:\.exe)?\s+.*\.exe',
    'extrac32(?:\.exe)?\s+.*\.cab',
    'compact(?:\.exe)?\s+.*\/u.*\.exe',

    # ==========================================================================
    # 09. MSHTA / MSI / INSTALLER ABUSE
    # ==========================================================================

    'msiexec(?:\.exe)?\s+.*(?:\/i|\/package).*(?:https?://)',
    'msiexec(?:\.exe)?\s+.*(?:\/q|\/quiet).*(?:https?://)',
    'msiexec(?:\.exe)?\s+.*(?:\\appdata\\|\\temp\\).*\.msi',
    'msiexec(?:\.exe)?\s+.*\/z.*https?://',
    'msiexec(?:\.exe)?\s+.*\/y.*\.dll',
    'installutil(?:\.exe)?\s+.*\/logfile=.*\.exe',
    'installutil(?:\.exe)?\s+.*\/logtoconsole=false',
    'odbcconf(?:\.exe)?\s+.*\/a\s+\{regsvr',
    'dfsvc(?:\.exe)?\s+.*https?://',

    # ==========================================================================
    # 10. SCHEDULED TASK / PERSISTENCE
    # ==========================================================================

    'schtasks(?:\.exe)?\s+.*\/create',
    'schtasks(?:\.exe)?\s+.*\/change.*\/tr',
    'schtasks(?:\.exe)?\s+.*\/create.*\/sc\s+onlogon',
    'schtasks(?:\.exe)?\s+.*\/create.*\/sc\s+onstart',
    'schtasks(?:\.exe)?\s+.*\/create.*\/ru\s+system',
    'schtasks(?:\.exe)?\s+.*\/create.*(?:powershell|mshta|wscript)',
    'schtasks(?:\.exe)?\s+.*\/create.*(?:\\appdata\\|\\temp\\)',
    'at(?:\.exe)?\s+\d{1,2}:\d{2}.*(?:cmd|powershell)',
    'reg(?:\.exe)?\s+add\s+.*\\run(?:once)?',
    'reg(?:\.exe)?\s+add\s+.*\\winlogon',
    'reg(?:\.exe)?\s+add\s+.*\\image\s+file\s+execution',
    'reg(?:\.exe)?\s+add\s+.*\\appinit_dlls',
    'reg(?:\.exe)?\s+add\s+.*\\shell\\open\\command',
    'reg(?:\.exe)?\s+add\s+.*\\command\s+processor',
    'reg(?:\.exe)?\s+add\s+.*\\services\\',
    'sc(?:\.exe)?\s+create\s+.*(?:binpath|binpath=)',
    'sc(?:\.exe)?\s+config\s+.*binpath',
    'schtasks(?:\.exe)?\s+.*\/delete.*\/f',

    # ==========================================================================
    # 11. UAC BYPASS / AUTO-ELEVATION INDICATORS
    # ==========================================================================

    'fodhelper(?:\.exe)?\s+.*',
    'computerdefaults(?:\.exe)?\s+.*',
    'eventvwr(?:\.exe)?\s+.*(?:mmc|msc)',
    'sdclt(?:\.exe)?\s+.*',
    'slui(?:\.exe)?\s+.*',
    'wsreset(?:\.exe)?\s+.*',
    'computerdefaults(?:\.exe)?.*(?:\/|--)',
    'cmstp(?:\.exe)?\s+.*\.inf',
    'cmstp(?:\.exe)?\s+.*\/s',
    'consent(?:\.exe)?\s+.*',

    # ==========================================================================
    # 12. WMI / WMIC EXECUTION
    # ==========================================================================

    'wmic(?:\.exe)?\s+.*process\s+call\s+create',
    'wmic(?:\.exe)?\s+.*\/node:.*process',
    'wmic(?:\.exe)?\s+.*shadowcopy\s+delete',
    'wmic(?:\.exe)?\s+.*startup\s+create',
    'wmic(?:\.exe)?\s+.*product.*call.*uninstall',
    'wmic(?:\.exe)?\s+.*os.*get.*caption',
    'wmic(?:\.exe)?\s+.*service.*call.*create',

    # ==========================================================================
    # 13. SCRIPTING / DEVELOPMENT RUNTIME ABUSE
    # ==========================================================================

    'python(?:w)?(?:\.exe)?\s+.*-c\s+.*(?:exec|eval|compile)',
    'python(?:w)?(?:\.exe)?\s+.*-c\s+.*(?:urllib|requests|socket)',
    'python(?:w)?(?:\.exe)?\s+.*(?:base64|b64decode)',
    'python(?:w)?(?:\.exe)?\s+.*https?://.*(?:exec|eval)',
    'python(?:w)?(?:\.exe)?\s+.*(?:\\appdata\\|\\temp\\).*\.py',
    'node(?:\.exe)?\s+.*-e\s+.*(?:child_process|exec|spawn)',
    'node(?:\.exe)?\s+.*-e\s+.*(?:http|https|Buffer)',
    'node(?:\.exe)?\s+.*(?:eval|Function)\s*\(',
    'php(?:\.exe)?\s+.*-r\s+.*(?:exec|system|shell_exec)',
    'ruby(?:\.exe)?\s+.*-e\s+.*(?:exec|system|eval)',
    'perl(?:\.exe)?\s+.*-e\s+.*(?:exec|system)',
    'java(?:\.exe)?\s+.*-jar\s+.*(?:\\temp\\|\\appdata\\)',
    'java(?:\.exe)?\s+.*-javaagent:',
    'java(?:\.exe)?\s+.*(?:Runtime\.getRuntime|ProcessBuilder)',
    'dotnet(?:\.exe)?\s+.*(?:exec|tool)',
    'msbuild(?:\.exe)?\s+.*\.proj',
    'msbuild(?:\.exe)?\s+.*\.xml',
    'vbc(?:\.exe)?\s+.*\.vb',
    'csc(?:\.exe)?\s+.*\.cs',

    # ==========================================================================
    # 14. ADVANCED .NET / ASSEMBLY EXECUTION
    # ==========================================================================

    'regasm(?:\.exe)?\s+.*\/codebase',
    'regasm(?:\.exe)?\s+.*\/tlb',
    'regsvcs(?:\.exe)?\s+.*\/fc',
    'rundll32(?:\.exe)?\s+.*clr\.dll',
    'mscoree\.dll.*(?:load|execute)',
    'assembly\.load(?:from|file)?',
    'reflection\.assembly.*load',
    'system\.reflection.*assembly',
    'system\.management\.automation.*powershell',
    'system\.diagnostics\.process.*start',
    'system\.net\.webclient.*download',

    # ==========================================================================
    # 15. DEFENSE EVASION / SECURITY TAMPERING
    # ==========================================================================

    '.*(?:set-mppreference|add-mppreference).*disable',
    '.*disable-realtimemonitoring',
    '.*disablebehaviormonitoring',
    '.*disablescriptscanning',
    '.*disableioavprotection',
    '.*exclusionpath.*(?:add|set)',
    '.*exclusionprocess.*(?:add|set)',
    '.*exclusionextension.*(?:add|set)',
    'sc(?:\.exe)?\s+stop\s+(?:windefend|sense|wscsvc)',
    'net(?:\.exe)?\s+stop\s+(?:windefend|sense)',
    'taskkill(?:\.exe)?\s+.*\/f\s+\/im\s+(?:MsMpEng|SenseIR|SecurityHealthService)',
    '.*(?:tamperprotection|disableantispyware)',
    '.*(?:bcdedit).*\/set.*(?:debug|testsigning|nointegritychecks)',
    '.*wevtutil(?:\.exe)?.*cl\s+(?:security|system|application)',
    '.*clear-eventlog.*(?:security|system)',
    '.*vssadmin(?:\.exe)?\s+delete\s+shadows',
    '.*wbadmin(?:\.exe)?\s+delete\s+catalog',
    '.*reagentc(?:\.exe)?\s+\/disable',

    # ==========================================================================
    # 16. ENCODING / OBFUSCATION INDICATORS
    # ==========================================================================

    'frombase64string\s*\(',
    'fromcharcode\s*\(',
    'tobase64string\s*\(',
    'convert::frombase64string',
    'convert::tobase64string',
    'decode\s*\(\s*base64',
    'base64_decode\s*\(',
    'b64decode\s*\(',
    'gzipstream',
    'deflatestream',
    'memorystream',
    'scriptblock::create',
    'invoke-expression',
    'invoke-?expression',
    'iex\s*\(',
    'eval\s*\(',
    'new-object\s+.*net\.webclient',
    'char\s*\[\]\s*\$',
    'join\s*\(.*char',
    '\[char\]\s*\d{2,3}',
    '0x[0-9a-f]{4,}',
    '(?:\\x[0-9a-f]{2}){4,}',
    '(?:%[0-9a-f]{2}){4,}',
    'window\.atob\s*\(',
    'decodeuricomponent\s*\(',
    'unescape\s*\(',

    # ==========================================================================
    # 17. REMOTE EXECUTION / NETWORK ABUSE
    # ==========================================================================

    'psexec(?:\.exe)?\s+.*\\\\[a-z0-9.-]+',
    'paexec(?:\.exe)?\s+.*\\\\[a-z0-9.-]+',
    'winrs(?:\.exe)?\s+.*-r:',
    'winrm(?:\.vbs)?\s+.*invoke',
    'enter-pssession\s+.*-computername',
    'invoke-command\s+.*-computername',
    'invoke-command\s+.*-scriptblock',
    'mstsc(?:\.exe)?\s+.*\/v:',
    'ssh(?:\.exe)?\s+.*(?:-p\s+\d+|@)',
    'scp(?:\.exe)?\s+.*@',
    'plink(?:\.exe)?\s+.*-ssh',
    'nc(?:\.exe)?\s+.*-e\s+',
    'ncat(?:\.exe)?\s+.*-e\s+',
    'socat(?:\.exe)?\s+.*exec:',
    '.*(?:reverse_tcp|reverse_https|bind_tcp)',
    '.*(?:meterpreter|beacon\.dll|payload\.dll)',

    # ==========================================================================
    # 18. FILELESS / TEMPORARY EXECUTION LOCATIONS
    # ==========================================================================

    '.*\\users\\[^\\]+\\appdata\\local\\temp\\.*\.(?:exe|dll|bat|cmd|ps1|vbs|js)',
    '.*\\users\\[^\\]+\\appdata\\roaming\\.*\.(?:exe|dll|bat|cmd|ps1|vbs|js)',
    '.*\\programdata\\.*\.(?:exe|dll|bat|cmd|ps1|vbs)',
    '.*\\windows\\temp\\.*\.(?:exe|dll|bat|cmd|ps1|vbs)',
    '.*\\downloads\\.*\.(?:exe|dll|bat|cmd|ps1)',
    '.*\\public\\.*\.(?:exe|dll|bat|cmd|ps1)',
    '.*\\appdata\\local\\packages\\.*\.(?:exe|dll)',
    '.*\\users\\public\\.*\.(?:exe|dll|ps1)',

    # ==========================================================================
    # 19. SHORTCUT / LNK SPECIFIC INDICATORS
    # ==========================================================================

    '.*(?:targetpath|arguments).*(?:powershell|pwsh|cmd\.exe)',
    '.*(?:targetpath|arguments).*(?:mshta|rundll32|regsvr32)',
    '.*(?:targetpath|arguments).*(?:wscript|cscript)',
    '.*(?:targetpath|arguments).*(?:certutil|bitsadmin)',
    '.*(?:targetpath|arguments).*https?://',
    '.*(?:targetpath|arguments).*(?:javascript:|vbscript:)',
    '.*(?:targetpath|arguments).*(-encodedcommand|-enc\s)',
    '.*(?:targetpath|arguments).*(?:-windowstyle\s+hidden|-w\s+hidden)',
    '.*(?:targetpath|arguments).*\\appdata\\.*(?:\.exe|\.dll|\.ps1)',
    '.*(?:targetpath|arguments).*(?:/c|/r|/k)\s+.*(?:powershell|mshta)',
    '.*(?:targetpath|arguments).*(?:%comspec%|%windir%|%temp%)',
    '.*(?:targetpath|arguments).*(?:javascript:|vbscript:|about:)',

    # ==========================================================================
    # 20. CLOUD / CONTAINER / ADMIN TOOL ABUSE
    # ==========================================================================

    'az(?:\.exe)?\s+login.*--service-principal',
    'az(?:\.exe)?\s+account\s+get-access-token',
    'aws(?:\.exe)?\s+configure\s+.*--profile',
    'aws(?:\.exe)?\s+sts\s+get-caller-identity',
    'kubectl(?:\.exe)?\s+.*(?:apply|create|exec|run)',
    'docker(?:\.exe)?\s+.*(?:exec|run|mount)',
    'podman(?:\.exe)?\s+.*(?:exec|run)',
    'rclone(?:\.exe)?\s+.*(?:copy|sync).*https?://',
    'rclone(?:\.exe)?\s+.*config\s+create',
    'terraform(?:\.exe)?\s+.*(?:apply|destroy)',
    'ssh-keygen(?:\.exe)?\s+.*-f\s+.*',

    # ==========================================================================
    # 21. PROXY EXECUTION / SYSTEM UTILITIES
    # ==========================================================================

    'forfiles(?:\.exe)?\s+.*\/c\s+.*(?:cmd|powershell)',
    'pcalua(?:\.exe)?\s+.*-a\s+.*',
    'presentationhost(?:\.exe)?\s+.*\.xbap',
    'control(?:\.exe)?\s+.*\.cpl',
    'mmc(?:\.exe)?\s+.*\.msc',
    'explorer(?:\.exe)?\s+.*(?:javascript:|shell:appsfolder)',
    'dllhost(?:\.exe)?\s+.*\/processid:',
    'syncappvpublishingserver(?:\.exe)?\s+.*',
    'gpscript(?:\.exe)?\s+.*',
    'regedit(?:\.exe)?\s+.*\/s\s+.*\.reg',

    # ==========================================================================
    # 22. SUSPICIOUS COMMAND CHAINING
    # ==========================================================================

    '.*(?:&&|\|\|)\s*(?:powershell|pwsh|mshta|rundll32|regsvr32)',
    '.*(?:;|\|)\s*(?:powershell|pwsh|cmd\.exe|mshta)',
    '.*(?:&|&&)\s*certutil.*-urlcache',
    '.*(?:&|&&)\s*bitsadmin.*\/transfer',
    '.*(?:&|&&)\s*reg(?:\.exe)?\s+add.*\\run',
    '.*(?:&|&&)\s*schtasks.*\/create',
    '.*(?:&|&&)\s*curl.*(?:-o|-O)',
    '.*(?:&|&&)\s*wget.*-O',

    # ==========================================================================
    # 23. SUSPICIOUS EXECUTION FROM USER-WRITABLE LOCATIONS
    # ==========================================================================

    '(?:^|[\s"])%temp%\\.*\.(?:exe|dll|bat|cmd|ps1)',
    '(?:^|[\s"])%appdata%\\.*\.(?:exe|dll|bat|cmd|ps1)',
    '(?:^|[\s"])%localappdata%\\.*\.(?:exe|dll|bat|cmd|ps1)',
    '(?:^|[\s"])%programdata%\\.*\.(?:exe|dll|bat|cmd|ps1)',
    '.*\\users\\public\\.*\.(?:exe|dll|ps1)',
    '.*\\recycler\\.*\.(?:exe|dll|bat|cmd)',
    '.*\\$recycle\.bin\\.*\.(?:exe|dll|ps1)',

    # ==========================================================================
    # 24. SUSPICIOUS WINDOWS PROTOCOL / SHELL INVOCATION
    # ==========================================================================

    '.*(?:ms-settings|search-ms|search:|shell:).*',
    '.*(?:file|javascript|vbscript):.*(?:powershell|cmd|mshta)',
    '.*shell:startup.*(?:powershell|cmd|wscript)',
    '.*shell:common startup.*(?:powershell|cmd|wscript)',
    '.*(?:url:|https?://).*(?:\.hta|\.sct|\.js|\.jse)',
    '.*(?:ms-msdt|ms-officecmd|ms-excel).*',

    # ==========================================================================
    # 25. HIGH-CONFIDENCE PAYLOAD EXECUTION COMBINATIONS
    # ==========================================================================

    '(?:powershell|pwsh).*(?:downloadstring|downloadfile).*(?:iex|invoke-expression)',
    '(?:powershell|pwsh).*(?:frombase64string).*(?:iex|invoke-expression)',
    '(?:certutil|bitsadmin).*(?:https?://).*(?:\.exe|\.dll|\.ps1)',
    '(?:mshta|rundll32|regsvr32).*(?:https?://|javascript:|vbscript:)',
    '(?:cmd|powershell).*(?:\\appdata\\|\\temp\\).*(?:\.exe|\.dll)',
    '(?:wscript|cscript).*(?:\\appdata\\|\\temp\\).*\.(?:vbs|js|jse)',
    '(?:schtasks|reg).*(?:powershell|mshta|wscript).*(?:hidden|encoded)',
    '(?:curl|wget).*(?:https?://).*(?:\.exe|\.dll|\.ps1)',

    # ==========================================================================
    # END OF SIGNATURE DATABASE
    # ==========================================================================

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
