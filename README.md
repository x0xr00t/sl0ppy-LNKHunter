# sl0ppy-LNKHunter v2.0
**Advanced LNK Abuse & LOLBin Detection Framework**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-7%2F8%2F10%2F11%2FServer-blue)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-Sl0ppyRed-orange)](https://github.com/x0xr00t)

**Sl0ppy-LNKHunter** is a comprehensive PowerShell tool designed to detect malicious LNK files and Living-off-the-Land Binaries (LOLBins) that could be abused for privilege escalation, persistence, or lateral movement in Windows environments.

---

## 🔍 **Features**

### **LNK File Analysis**
- Detects **30+ abuse patterns** in shortcut files
- Analyzes **target paths, arguments, and icons** for suspicious indicators
- Identifies **network-based payloads** and **obfuscated commands**
- Checks for **base64-encoded payloads** and **suspicious parent processes**

### **LOLBin Detection**
- Scans for **100+ known LOLBins** (PowerShell, WMI, CertUtil, etc.)
- Covers **cloud tools** (Azure CLI, AWS CLI, Kubernetes)
- Includes **script engines** (Python, Node.js, PHP)
- Detects **debugging and diagnostic tools** often abused by attackers

### **Scan Capabilities**
- **Deep scan mode** for recursive directory searching
- **All-user scanning** (requires admin privileges)
- **Silent mode** for automation and CI/CD integration
- **Export options** (CSV, JSON, TXT)

### **Evasion Resistance**
- **COM object deep inspection** of LNK files
- **Obfuscation detection** in commands
- **Network path analysis** in targets/arguments
- **Severity classification** of findings

---

## 📋 **Installation**
```
### **Requirements**
- **PowerShell 5.1 or later**
- **Windows 7 / Server 2012 or newer**
- **Administrator privileges** (for all-user scans)
```

### **Quick Start**
```
1. **Download the script**:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sl0ppyroot/sl0ppy-LNKHunter/main/sl0ppy-LNKHunter.ps1" -OutFile "sl0ppy-LNKHunter.ps1"

Run a basic scan:
.\sl0ppy-LNKHunter.ps1

(Optional) Enable execution policy (if blocked):
Set-ExecutionPolicy Bypass -Scope Process -Force
```


## 🚀 Usage
```
Basic Scan
.\sl0ppy-LNKHunter.ps1
Scans common system paths for suspicious LNK files and LOLBins.
Deep Scan (Recursive)
.\sl0ppy-LNKHunter.ps1 -DeepScan
Recursively scans all subdirectories for hidden threats.
Scan All Users (Admin Required)
.\sl0ppy-LNKHunter.ps1 -ScanAllUsers
Scans all user profiles on the system.
Silent Mode (Automation-Friendly)
.\sl0ppy-LNKHunter.ps1 -SilentMode -Export CSV
Runs quietly and exports results to a CSV file.
Full Comprehensive Scan
.\sl0ppy-LNKHunter.ps1 -DeepScan -ScanAllUsers -Export JSON
Maximal detection with JSON output.
```

## 📊 Output Examples
```
Suspicious LNK Detection
[HIGH] C:\Users\Admin\Desktop\malicious.lnk
   Target: powershell.exe -nop -ep bypass -enc JABXAG...
   Args: -WindowStyle Hidden
   Indicators: Base64-encoded command; Hidden window; PowerShell abuse
   Modified: 2025-10-08 14:30:45 | Size: 1024 bytes
LOLBin Discovery
[+] Found LOLBin: mshta.exe at C:\Windows\System32
[+] Found LOLBin: wmic.exe at C:\Windows\System32
[+] Found LOLBin: certutil.exe at C:\Windows\System32
Export Formats

CSV: Structured data for analysis
JSON: Machine-readable output
TXT: Human-readable report

```
🛡️ Detection Capabilities
```
LNK Abuse Patterns
PowerShell Abuse-nop, -ep bypass, -encCommand ObfuscationfromBase64String, eval(Network Payloadshttp://, \\UNC\pathPersistenceschtasks /create, reg addFileless Executionrundll32 javascript:
LOLBins Covered
Classic LOLBinspowershell.exe, wmic.exe, mshta.exeNetwork Toolscurl.exe, bitsadmin.exe, certutil.exeScript Enginespython.exe, node.exe, php.exeCloud Toolsaz.exe, aws.exe, kubectl.exeDebugging Toolswindbg.exe, procdump.exe
```
## 🔧 Advanced Options
```
-DeepScanRecursive directory scanning-ScanAllUsersScan all user profiles (requires admin)-SilentModeSuppress non-critical output-Export CSVJSONTXTExport results in specified format
```
## 📝 Use Cases
```
✅ Red Team Engagements – Find attack vectors
✅ Blue Team Defense – Hunt for malicious LNK files
✅ Incident Response – Investigate suspicious activity
✅ Compliance Audits – Verify system security posture
✅ Threat Hunting – Proactively detect LOLBin abuse
```
## ⚠️ Disclaimer
## Use Responsibly!
```
This tool is for authorized security testing only.
Ensure compliance with laws and organizational policies.
Do not use on systems without permission.
```


© 2025 Sl0ppyRoot Team | v2.0
"Because LNK files shouldn’t be a backdoor."
