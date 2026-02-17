# Zero-Trust Launcher

**Pre-Execution Malware Analyzer for Windows**

Static analysis tool that evaluates executables for malicious behavior before execution. Combines Shannon entropy analysis, PE import scanning, and PyInstaller bytecode detection.

---

## Features

- **Shannon Entropy Analysis** - Detects packed/encrypted malware
- **PE Import Scanning** - Identifies suspicious Windows API calls  
- **PyInstaller Detection** - Analyzes embedded Python bytecode
- **Educational Explanations** - Detailed vulnerability descriptions
- **Risk Scoring** - 0-100 scale (LOW/MEDIUM/HIGH)

---

## Installation

```bash
git clone https://github.com/darama22/ZeroTrustLauncher.git
cd ZeroTrustLauncher
pip install -r requirements.txt
python launcher.py
```

**Requirements:** Python 3.7+, Windows OS

---

## Usage

1. Launch: `python launcher.py`
2. Select an executable (Browse or drag-and-drop)
3. Review risk score and detected APIs
4. Click "View Detailed Explanations" for educational content

---

## Validation Results

| Test File | Type | Risk Score | Result |
|-----------|------|------------|--------|
| `calc.exe` | Legitimate utility | 0/100 (LOW) | ✅ |
| `Valorant.exe` | Game with anti-cheat | 31/100 (MEDIUM) | ✅ |
| `Cheat Engine` | Memory editor | 28/100 (MEDIUM) | ✅ |
| `malware_test.exe` | PyInstaller malware | 56/100 (HIGH) | ✅ |
| `msfvenom payload` | Advanced shellcode | 0/100 (LOW) | ⚠️ * |

**\* Known limitation:** Advanced shellcode with API hashing requires dynamic analysis.

---

## How It Works

### 1. Shannon Entropy
- High entropy (>7.2) → Packed/encrypted
- Normal entropy (<6.8) → Standard executable

### 2. PE Import Scanning
- **CRITICAL:** `WriteProcessMemory`, `CreateRemoteThread`, `GetAsyncKeyState`
- **HIGH:** `VirtualAlloc`, `AdjustTokenPrivileges`, `exec`, `eval`
- **MEDIUM:** `CreateToolhelp32Snapshot`, `subprocess`

### 3. PyInstaller Detection
Scans for: `ctypes`, `subprocess`, `eval`, `exec`, Windows API strings

### 4. Risk Scoring
```
Total Score = Entropy Penalty + API Penalties
LOW: 0-25 | MEDIUM: 26-50 | HIGH: 51-100
```

---

## Limitations

**Static analysis only** - Cannot detect:
- Advanced shellcode with API hashing (msfvenom, Cobalt Strike)
- Polymorphic malware
- Fileless malware
- Obfuscated imports using dynamic resolution

**Recommended for:** Pre-screening executables, educational analysis, detecting common malware families  
**Not recommended for:** APTs, zero-days, replacing professional antivirus

---

## Project Structure

```
ZeroTrustLauncher/
├── launcher.py              # Entry point
├── modules/
│   ├── core_analyzer.py     # PE + entropy analysis
│   ├── pyinstaller_analyzer.py
│   └── vulnerability_explanations.py
├── ui/main_window.py        # GUI
└── dist/malware_test.exe    # Test sample
```

---

## License

Educational purposes only. Do not use to analyze or distribute actual malware without proper authorization.

---

## Acknowledgments

- **pefile** library for PE parsing
- **Shannon entropy** algorithm for packing detection
- **MITRE ATT&CK** framework for threat categorization


**Pre-Execution Malware Analyzer**

A static analysis tool that evaluates Windows executables for malicious behavior **before** execution. Uses Shannon entropy analysis, PE import scanning, and PyInstaller bytecode detection to assign risk scores.

---

## Features

- **Shannon Entropy Analysis** - Detects packed/encrypted malware
- **PE Import Scanning** - Identifies suspicious Windows API calls
- **PyInstaller Detection** - Analyzes embedded Python bytecode
- **Educational Explanations** - Detailed vulnerability descriptions for each detected threat
- **Risk Scoring** - 0-100 scale with LOW/MEDIUM/HIGH classification
- **Modern UI** - Windows-style wizard interface with visual feedback

---

## Installation

### Requirements
- Python 3.7+
- Windows OS (for PE analysis)

### Setup
```bash
git clone https://github.com/yourusername/ZeroTrustLauncher.git
cd ZeroTrustLauncher
pip install -r requirements.txt
python launcher.py
```

### Dependencies
- `pefile` - PE file parsing
- `tkinter` - GUI (included with Python)
- `tkinterdnd2` - Drag-and-drop support (optional)

---

## Usage

1. **Launch the application:**
   ```bash
   python launcher.py
   ```

2. **Select a file:**
   - Click "Browse" to select an executable
   - Or drag-and-drop (if tkinterdnd2 is installed)

3. **Review results:**
   - Risk score (0-100)
   - Detected suspicious APIs
   - Entropy analysis
   - Click "View Detailed Explanations" for educational content

---

## Testing & Validation

The tool has been validated with multiple test cases:

| Test File | Type | Risk Score | Result |
|-----------|------|------------|--------|
| `calc.exe` | Legitimate Windows utility | 0/100 (LOW) | ✅ Correct |
| `Valorant.exe` | Legitimate game (packed) | 31/100 (MEDIUM) | ✅ Correct |
| `Cheat Engine` | Legitimate tool (memory manipulation) | 28/100 (MEDIUM) | ✅ Correct |
| `malware_test.exe` | PyInstaller malware simulator | 56/100 (HIGH) | ✅ Correct |
| `msfvenom payload` | Advanced shellcode | 0/100 (LOW) | ⚠️ See limitations |

### Test Examples

**Low Risk (0-25):**
```bash
python launcher.py
# Select: C:\Windows\System32\calc.exe
# Result: 0/100 - No suspicious APIs detected
```

**Medium Risk (26-50):**
```bash
# Select: Valorant.exe or Cheat Engine
# Result: 28-31/100 - Packed executable with legitimate APIs
```

**High Risk (51-100):**
```bash
# Select: dist/malware_test.exe (PyInstaller sample)
# Result: 56/100 - Suspicious Python patterns detected
```

---

## Limitations

### Static Analysis Constraints
This tool performs **static analysis only** (no code execution). It has known limitations:

#### What it Detects:
- Traditional malware with visible Import Address Table (IAT)
- Packed executables (UPX, ASPack, etc.)
- PyInstaller-packed Python malware
- Executables using suspicious Windows APIs

#### What it May Miss:
- **Advanced shellcode** with API hashing (e.g., msfvenom payloads)
- **Polymorphic malware** that mutates on each execution
- **Fileless malware** that loads entirely in memory
- **Obfuscated imports** using dynamic resolution

### Why msfvenom Payloads Score 0/100
Metasploit payloads use advanced evasion:
- No Import Address Table (IAT) - APIs resolved at runtime
- Position-independent shellcode
- API hashing instead of function names

**Detection requires:** Dynamic analysis (sandboxing, API hooking, behavioral monitoring)

### Recommended Use Cases
- Pre-screening unknown executables
- Educational malware analysis
- Identifying packed/obfuscated software
- Detecting common malware families

**Not recommended for:**
- Advanced persistent threats (APTs)
- Zero-day exploits
- Replacing professional antivirus solutions

---

## How It Works

### 1. Shannon Entropy
Calculates randomness of file data:
- **High entropy (>7.2)** → Likely packed/encrypted
- **Normal entropy (<6.8)** → Standard executable

### 2. PE Import Scanning
Analyzes Import Address Table for suspicious APIs:
- **CRITICAL:** `WriteProcessMemory`, `CreateRemoteThread`, `GetAsyncKeyState`
- **HIGH:** `VirtualAlloc`, `AdjustTokenPrivileges`, `exec`, `eval`
- **MEDIUM:** `CreateToolhelp32Snapshot`, `kernel32`, `subprocess`

### 3. PyInstaller Detection
Scans for Python bytecode patterns:
- `ctypes`, `subprocess`, `eval`, `exec`
- Windows API strings in embedded code
- Dynamic import mechanisms

### 4. Risk Scoring
```
Total Score = Entropy Penalty + API Penalties
- LOW:    0-25   (Safe)
- MEDIUM: 26-50  (Suspicious)
- HIGH:   51-100 (Dangerous)
```

---

## Vulnerability Explanations

The tool provides educational descriptions for each detected threat:
- **What it does** - Technical description
- **Why it's dangerous** - Security implications
- **Legitimate uses** - When it's normal to see this API
- **Malware examples** - Real-world attack scenarios

Example APIs explained:
- `WriteProcessMemory` - Process injection
- `GetAsyncKeyState` - Keylogging
- `VirtualAlloc` - Shellcode allocation
- `exec`/`eval` - Dynamic code execution

---

## Project Structure

```
ZeroTrustLauncher/
├── launcher.py              # Entry point
├── modules/
│   ├── core_analyzer.py     # PE + entropy analysis
│   ├── pyinstaller_analyzer.py  # Python bytecode detection
│   └── vulnerability_explanations.py  # Educational content
├── ui/
│   └── main_window.py       # Tkinter GUI
├── dist/
│   └── malware_test.exe     # PyInstaller test sample
└── requirements.txt
```

---

## Future Enhancements

- Dynamic analysis (sandboxing)
- YARA rule integration
- VirusTotal API integration
- Shellcode pattern detection
- Behavioral heuristics
- Machine learning classification

---

## License

This project is for **educational purposes only**. Do not use to analyze or distribute actual malware without proper authorization and safety measures.

---

## Acknowledgments

- **pefile** library for PE parsing
- **Shannon entropy** algorithm for packing detection
- **MITRE ATT&CK** framework for threat categorization
- **Metasploit** for payload testing methodology

---

## Quick Start

```bash
# Clone and setup
git clone https://github.com/yourusername/ZeroTrustLauncher.git
cd ZeroTrustLauncher
pip install -r requirements.txt

# Run analysis
python launcher.py

# Test with sample
# Browse to: dist/malware_test.exe
# Expected: 56/100 (HIGH RISK)
```

**Stay safe. Analyze first. Execute never (unless you're sure).**

**Pre-Execution Malware Analyzer**

A static analysis tool that evaluates Windows executables for malicious behavior **before** execution. Uses Shannon entropy analysis, PE import scanning, and PyInstaller bytecode detection to assign risk scores.

---

## 🎯 Features

- **Shannon Entropy Analysis** - Detects packed/encrypted malware
- **PE Import Scanning** - Identifies suspicious Windows API calls
- **PyInstaller Detection** - Analyzes embedded Python bytecode
- **Educational Explanations** - Detailed vulnerability descriptions for each detected threat
- **Risk Scoring** - 0-100 scale with LOW/MEDIUM/HIGH classification
- **Modern UI** - Windows-style wizard interface with visual feedback

---

## 📦 Installation

### Requirements
- Python 3.7+
- Windows OS (for PE analysis)

### Setup
```bash
git clone <repository-url>
cd ZeroTrustLauncher
pip install -r requirements.txt
python launcher.py
```

### Dependencies
- `pefile` - PE file parsing
- `tkinter` - GUI (included with Python)
- `tkinterdnd2` - Drag-and-drop support (optional)

---

## 🚀 Usage

1. **Launch the application:**
   ```bash
   python launcher.py
   ```

2. **Select a file:**
   - Click "Browse" to select an executable
   - Or drag-and-drop (if tkinterdnd2 is installed)

3. **Review results:**
   - Risk score (0-100)
   - Detected suspicious APIs
   - Entropy analysis
   - Click "📖 View Detailed Explanations" for educational content

---

## 🧪 Testing & Validation

The tool has been validated with multiple test cases:

| Test File | Type | Risk Score | Result |
|-----------|------|------------|--------|
| `calc.exe` | Legitimate Windows utility | 0/100 (LOW) | ✅ Correct |
| `Valorant.exe` | Legitimate game (packed) | 31/100 (MEDIUM) | ✅ Correct |
| `Cheat Engine` | Legitimate tool (memory manipulation) | 28/100 (MEDIUM) | ✅ Correct |
| `malware_test.exe` | PyInstaller malware simulator | 56/100 (HIGH) | ✅ Correct |
| `msfvenom payload` | Advanced shellcode | 0/100 (LOW) | ⚠️ See limitations |

### Test Examples

**Low Risk (0-25):**
```bash
python launcher.py
# Select: C:\Windows\System32\calc.exe
# Result: 0/100 - No suspicious APIs detected
```

**Medium Risk (26-50):**
```bash
# Select: Valorant.exe or Cheat Engine
# Result: 28-31/100 - Packed executable with legitimate APIs
```

**High Risk (51-100):**
```bash
# Select: dist/malware_test.exe (PyInstaller sample)
# Result: 56/100 - Suspicious Python patterns detected
```

---

## ⚠️ Limitations

### Static Analysis Constraints
This tool performs **static analysis only** (no code execution). It has known limitations:

#### ✅ **Detects:**
- Traditional malware with visible Import Address Table (IAT)
- Packed executables (UPX, ASPack, etc.)
- PyInstaller-packed Python malware
- Executables using suspicious Windows APIs

#### ❌ **May Miss:**
- **Advanced shellcode** with API hashing (e.g., msfvenom payloads)
- **Polymorphic malware** that mutates on each execution
- **Fileless malware** that loads entirely in memory
- **Obfuscated imports** using dynamic resolution

### Why msfvenom Payloads Score 0/100
Metasploit payloads use advanced evasion:
- No Import Address Table (IAT) - APIs resolved at runtime
- Position-independent shellcode
- API hashing instead of function names

**Detection requires:** Dynamic analysis (sandboxing, API hooking, behavioral monitoring)

### Recommended Use Cases
- ✅ Pre-screening unknown executables
- ✅ Educational malware analysis
- ✅ Identifying packed/obfuscated software
- ✅ Detecting common malware families

**Not recommended for:**
- ❌ Advanced persistent threats (APTs)
- ❌ Zero-day exploits
- ❌ Replacing professional antivirus solutions

---

## 📚 How It Works

### 1. Shannon Entropy
Calculates randomness of file data:
- **High entropy (>7.2)** → Likely packed/encrypted
- **Normal entropy (<6.8)** → Standard executable

### 2. PE Import Scanning
Analyzes Import Address Table for suspicious APIs:
- **CRITICAL:** `WriteProcessMemory`, `CreateRemoteThread`, `GetAsyncKeyState`
- **HIGH:** `VirtualAlloc`, `AdjustTokenPrivileges`, `exec`, `eval`
- **MEDIUM:** `CreateToolhelp32Snapshot`, `kernel32`, `subprocess`

### 3. PyInstaller Detection
Scans for Python bytecode patterns:
- `ctypes`, `subprocess`, `eval`, `exec`
- Windows API strings in embedded code
- Dynamic import mechanisms

### 4. Risk Scoring
```
Total Score = Entropy Penalty + API Penalties
- LOW:    0-25   (Safe)
- MEDIUM: 26-50  (Suspicious)
- HIGH:   51-100 (Dangerous)
```

---

## 🔍 Vulnerability Explanations

The tool provides educational descriptions for each detected threat:
- **What it does** - Technical description
- **Why it's dangerous** - Security implications
- **Legitimate uses** - When it's normal to see this API
- **Malware examples** - Real-world attack scenarios

Example APIs explained:
- `WriteProcessMemory` - Process injection
- `GetAsyncKeyState` - Keylogging
- `VirtualAlloc` - Shellcode allocation
- `exec`/`eval` - Dynamic code execution

---

## 📁 Project Structure

```
ZeroTrustLauncher/
├── launcher.py              # Entry point
├── modules/
│   ├── core_analyzer.py     # PE + entropy analysis
│   ├── pyinstaller_analyzer.py  # Python bytecode detection
│   └── vulnerability_explanations.py  # Educational content
├── ui/
│   └── main_window.py       # Tkinter GUI
├── dist/
│   └── malware_test.exe     # PyInstaller test sample
└── requirements.txt
```

---

## 🛠️ Future Enhancements

- [ ] Dynamic analysis (sandboxing)
- [ ] YARA rule integration
- [ ] VirusTotal API integration
- [ ] Shellcode pattern detection
- [ ] Behavioral heuristics
- [ ] Machine learning classification

---

## 📄 License

This project is for **educational purposes only**. Do not use to analyze or distribute actual malware without proper authorization and safety measures.

---

## 🙏 Acknowledgments

- **pefile** library for PE parsing
- **Shannon entropy** algorithm for packing detection
- **MITRE ATT&CK** framework for threat categorization
- **Metasploit** for payload testing methodology

---

## ⚡ Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd ZeroTrustLauncher
pip install -r requirements.txt

# Run analysis
python launcher.py

# Test with sample
# Browse to: dist/malware_test.exe
# Expected: 56/100 (HIGH RISK)
```

**Stay safe. Analyze first. Execute never (unless you're sure).**


**A Pre-Execution Malware Analyzer for Windows**

## Overview

Zero-Trust Launcher is a security tool that analyzes Windows executables **before** you run them. It fills the critical gap where traditional antivirus solutions fail: when users click "Yes" to UAC prompts before the AV has time to analyze obfuscated or packed malware.

### The Problem

You download `GTA6_Crack.exe`. Windows Defender doesn't flag it because it's encrypted (FUD/Crypter). You double-click, grant Admin privileges, and... **it's too late.**

### The Solution

Drag the file into Zero-Trust Launcher **BEFORE** executing it. The tool performs three critical checks:

1. **Shannon Entropy Analysis** - Detects crypters/packers mathematically (not signature-based)
2. **PE Import Scanning** - Identifies suspicious API calls (injection, remote execution, etc.)
3. **Risk Scoring** - Provides a 0-100 risk assessment with detailed explanations

## Technical Approach

### Module 1: Entropy Detection
Crypters hide malware by encrypting it, making the file appear as random noise. Shannon entropy measures this randomness:
- **Normal executable**: 4.5 - 6.0 entropy
- **Packed/Encrypted**: 7.2 - 8.0 entropy (maximum is 8.0)

### Module 2: Import Address Table (IAT) Analysis
Even encrypted malware must declare what Windows APIs it needs. We scan for dangerous functions:
- `VirtualAlloc`, `WriteProcessMemory` → Memory injection
- `CreateRemoteThread` → Code execution in other processes
- `InternetOpen`, `URLDownloadToFile` → C&C communication
- `GetAsyncKeyState` → Keylogging

### Module 3: Risk Scoring
Combines entropy + suspicious imports into a 0-100 score with color-coded alerts:
- 🟢 **0-30**: Low risk (likely safe)
- 🟡 **31-60**: Medium risk (packed but may be legitimate)
- 🔴 **61-100**: High risk (multiple red flags)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ZeroTrustLauncher.git
cd ZeroTrustLauncher

# Install dependencies
pip install -r requirements.txt

# Run the launcher
python launcher.py
```

## Usage

1. Launch the application
2. Drag & drop an `.exe` file or use the file browser
3. Review the analysis results
4. Make an informed decision

## Limitations & Disclaimer

⚠️ **This tool is educational and supplementary.** It does not replace antivirus software.

**Known Limitations:**
- **Designed for native malware** (C/C++/Delphi/etc.) - Python scripts packaged with PyInstaller use dynamic loading and won't show APIs in the IAT
- Advanced malware may use API hashing or dynamic loading to hide imports
- Legitimate compressed installers (7-Zip SFX, game installers) may trigger high entropy warnings
- Legitimate games with anti-cheat (Valorant, Fortnite) may show MEDIUM risk due to packing and low-level APIs
- Does not analyze runtime behavior (only static analysis)

**Use this tool as a "second opinion" before executing unknown files.**

## Testing the Tool

To test detection accuracy, use:
1. **Benign software**: `calc.exe` (should be LOW risk)
2. **Legitimate packed software**: Valorant, game installers (should be MEDIUM risk)
3. **Native malware samples**: Compile `malware_test.c` (see `COMPILE_TEST_MALWARE.md`) or use samples from VirusTotal/theZoo (should be HIGH risk)

## Portfolio Pitch

This project demonstrates:
- Understanding of malware obfuscation techniques (crypters, packers)
- Low-level Windows PE format knowledge
- Mathematical heuristics (Shannon entropy) vs signature-based detection
- Security engineering mindset: "Zero Trust" philosophy

Perfect for cybersecurity, malware analysis, or systems programming roles.

## License

MIT License - Educational purposes only.
