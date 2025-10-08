# sl0ppy-LNKHunter v2.0
**Advanced LNK Abuse & LOLBin Detection Framework**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-7%2F8%2F10%2F11%2FServer-blue)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-Sl0ppyRed-orange)](https://github.com/sl0ppyroot)

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

### **Requirements**
- **PowerShell 5.1 or later**
- **Windows 7 / Server 2012 or newer**
- **Administrator privileges** (for all-user scans)

### **Quick Start**
1. **Download the script**:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sl0ppyroot/sl0ppy-LNKHunter/main/sl0ppy-LNKHunter.ps1" -OutFile "sl0ppy-LNKHunter.ps1"
