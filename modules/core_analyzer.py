import math
import pefile
import os

# Import PyInstaller analyzer (handle both module and standalone execution)
try:
    from modules.pyinstaller_analyzer import PyInstallerAnalyzer
except ImportError:
    from pyinstaller_analyzer import PyInstallerAnalyzer

class ZeroTrustAnalyzer:
    """
    Core analysis engine combining Shannon Entropy and PE Import scanning.
    
    This class performs static analysis on Windows executables to detect:
    - Packed/encrypted malware (via entropy)
    - Suspicious API usage (via IAT scanning)
    """
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.file_data = None
        self.results = {
            "entropy": 0.0,
            "is_packed": False,
            "suspicious_imports": [],
            "risk_score": 0,  # 0 to 100
            "file_size": 0,
            "file_name": ""
        }

    def load_file(self):
        """Load and validate the PE file"""
        try:
            self.pe = pefile.PE(self.file_path)
            with open(self.file_path, "rb") as f:
                self.file_data = f.read()
            
            self.results["file_size"] = len(self.file_data)
            self.results["file_name"] = os.path.basename(self.file_path)
            return True
        except pefile.PEFormatError:
            print(f"[!] Error: Not a valid PE file")
            return False
        except Exception as e:
            print(f"[!] Error loading file: {e}")
            return False

    def calculate_entropy(self):
        """
        Calculate Shannon Entropy (0.0 to 8.0)
        
        High entropy (>7.2) indicates encryption/compression, commonly used
        by crypters to hide malware from signature-based detection.
        """
        if not self.file_data:
            return 0
        
        entropy = 0
        data_len = len(self.file_data)
        
        # Byte frequency count
        byte_counts = [0] * 256
        for byte in self.file_data:
            byte_counts[byte] += 1
            
        # Shannon's formula: H(X) = -Σ P(x) * log2(P(x))
        for count in byte_counts:
            if count == 0:
                continue
            p_x = float(count) / data_len
            entropy -= p_x * math.log(p_x, 2)
            
        self.results["entropy"] = entropy
        
        # Threshold: >7.2 is typically encrypted/compressed code
        # NOTE: Many legitimate games (Valorant, Fortnite) use packing for anti-tamper
        if entropy > 7.2:
            self.results["is_packed"] = True
            self.results["risk_score"] += 20  # Reduced from 40 (games often packed)
        elif entropy > 6.8:
            self.results["risk_score"] += 10  # Reduced from 20

    def scan_imports(self):
        """
        Scan the Import Address Table (IAT) for suspicious API calls.
        
        Even if malware is packed, it must declare which Windows APIs it needs.
        We look for functions commonly used in malicious behavior.
        """
        if not self.pe:
            return

        # Blacklist of APIs commonly used by malware
        # Format: "FunctionName": ("Category", penalty_score, "severity")
        # Severity: LOW (also used by legit software), MEDIUM (suspicious), HIGH (almost always malicious)
        suspicious_apis = {
            # HIGH SEVERITY - Almost always malicious
            "WriteProcessMemory": ("Process Injection (CRITICAL)", 18, "HIGH"),
            "CreateRemoteThread": ("Code Execution in Remote Process", 18, "HIGH"),
            "GetAsyncKeyState": ("Keylogging (Spyware)", 18, "HIGH"),
            "URLDownloadToFile": ("Payload Download", 15, "HIGH"),
            "SetWindowsHookEx": ("Keylogging/Hooking", 12, "HIGH"),
            
            # MEDIUM SEVERITY - Suspicious but used by some legit software
            "VirtualAllocEx": ("Memory Manipulation", 10, "MEDIUM"),
            "CryptDecrypt": ("Decryption (Ransomware/Payload)", 10, "MEDIUM"),
            "CryptEncrypt": ("Encryption (Ransomware)", 10, "MEDIUM"),
            "ShellExecute": ("Command Execution", 8, "MEDIUM"),
            "ShellExecuteEx": ("Command Execution", 8, "MEDIUM"),
            "WinExec": ("Command Execution", 8, "MEDIUM"),
            "InternetOpen": ("Network Communication", 6, "MEDIUM"),
            "InternetOpenUrl": ("Network Communication", 6, "MEDIUM"),
            
            # LOW SEVERITY - Common in games, anti-cheat, debuggers, legit tools
            "VirtualAlloc": ("Memory Manipulation", 4, "LOW"),
            "AdjustTokenPrivileges": ("Privilege Escalation", 4, "LOW"),
            "CreateToolhelp32Snapshot": ("Process Enumeration", 3, "LOW"),
            "RegSetValueEx": ("Registry Modification", 3, "LOW"),
            "RegCreateKeyEx": ("Registry Modification", 3, "LOW")
        }

        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8') if entry.dll else "Unknown"
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8')
                            
                            if func_name in suspicious_apis:
                                category, penalty, severity = suspicious_apis[func_name]
                                
                                # Store detailed information
                                self.results["suspicious_imports"].append({
                                    "function": func_name,
                                    "dll": dll_name,
                                    "category": category,
                                    "penalty": penalty,
                                    "severity": severity
                                })
                                
                                self.results["risk_score"] += penalty
        except Exception as e:
            print(f"[!] Error scanning imports: {e}")

    def get_risk_level(self):
        """Categorize risk score into Low/Medium/High"""
        score = self.results["risk_score"]
        if score >= 51:
            return "HIGH", "🔴"
        elif score >= 26:
            return "MEDIUM", "🟡"
        else:
            return "LOW", "🟢"

    def analyze(self):
        """
        Execute full analysis pipeline.
        
        Returns:
            dict: Analysis results with entropy, imports, and risk score
            None: If file loading fails
        """
        # First, check if it's a PyInstaller executable
        pyinstaller_analyzer = PyInstallerAnalyzer(self.file_path)
        pyinstaller_results = pyinstaller_analyzer.analyze()
        
        if pyinstaller_results:
            # It's a PyInstaller executable - use PyInstaller analysis
            print(f"\n[*] Analyzing: {os.path.basename(self.file_path)}...")
            print(f"[*] File size: {os.path.getsize(self.file_path):,} bytes")
            print(f"[*] Type: PyInstaller-packed Python executable")
            
            # Also get entropy for packed detection
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            self.calculate_entropy()
            
            # Combine results
            self.results['file_name'] = os.path.basename(self.file_path)
            self.results['file_size'] = os.path.getsize(self.file_path)
            self.results['is_pyinstaller'] = True
            self.results['suspicious_imports'] = [
                {
                    'function': p['pattern'],
                    'dll': 'Python Bytecode',
                    'category': p['category'],
                    'penalty': p['penalty'],
                    'severity': 'MEDIUM'
                }
                for p in pyinstaller_results['suspicious_patterns']
            ]
            self.results['risk_score'] = pyinstaller_results['risk_score']
            self.results['risk_level'] = pyinstaller_results['risk_level']
            self.results['risk_emoji'] = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}[pyinstaller_results['risk_level']]
            
            return self.results
        
        # Not PyInstaller - use standard PE analysis
        if not self.load_file():
            return None
        
        print(f"\n[*] Analyzing: {self.results['file_name']}...")
        print(f"[*] File size: {self.results['file_size']:,} bytes")
        
        self.calculate_entropy()
        self.scan_imports()
        
        # Normalize risk score (max 100)
        if self.results["risk_score"] > 100:
            self.results["risk_score"] = 100
        
        # Add risk level classification
        risk_level, emoji = self.get_risk_level()
        self.results["risk_level"] = risk_level
        self.results["risk_emoji"] = emoji
            
        return self.results

    def print_report(self):
        """Print a formatted console report"""
        if not self.results:
            return
        
        print("\n" + "="*60)
        print("🛡️  ZERO-TRUST ANALYSIS REPORT")
        print("="*60)
        print(f"File: {self.results['file_name']}")
        print(f"Size: {self.results['file_size']:,} bytes")
        print(f"\n📊 Entropy: {self.results['entropy']:.4f} / 8.0")
        
        if self.results['is_packed']:
            print("⚠️  PACKED/ENCRYPTED: Code is obfuscated (common in malware)")
        else:
            print("✅ Normal entropy (not packed)")
        
        print(f"\n🔍 Suspicious Imports: {len(self.results['suspicious_imports'])}")
        if self.results['suspicious_imports']:
            for imp in self.results['suspicious_imports']:
                print(f"  • {imp['function']} ({imp['dll']}) - {imp['category']}")
        else:
            print("  ✅ No suspicious API calls detected")
        
        risk_level = self.results['risk_level']
        risk_emoji = self.results['risk_emoji']
        risk_score = self.results['risk_score']
        
        print(f"\n{risk_emoji} RISK LEVEL: {risk_level} ({risk_score}/100)")
        print("="*60)


# --- STANDALONE TEST ---
if __name__ == "__main__":
    import sys
    
    # Test with calc.exe or any executable
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = r"C:\Windows\System32\calc.exe"
    
    print(f"[*] Zero-Trust Launcher - Testing Core Analyzer")
    print(f"[*] Target: {target}")
    
    analyzer = ZeroTrustAnalyzer(target)
    results = analyzer.analyze()
    
    if results:
        analyzer.print_report()
    else:
        print("[!] Analysis failed. Check if the file is a valid PE executable.")
