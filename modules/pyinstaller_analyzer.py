"""
PyInstaller Detection Module

This module detects and analyzes executables packed with PyInstaller.
It extracts the embedded Python bytecode and scans for suspicious patterns.
"""

import os
import struct
import marshal
import dis
from io import BytesIO

class PyInstallerAnalyzer:
    """
    Analyzes PyInstaller-packed executables by extracting and scanning
    the embedded Python bytecode for suspicious patterns.
    """
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.is_pyinstaller = False
        self.suspicious_imports = []
        self.suspicious_patterns = []
        self.risk_score = 0
        
    def detect_pyinstaller(self):
        """Check if the file is a PyInstaller executable"""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                
            # PyInstaller magic bytes
            pyinstaller_signatures = [
                b'MEI\x0c\x0b\x0a\x0d',  # PyInstaller 2.0+
                b'python',               # Python DLL reference
                b'PYZ-00.pyz',          # PyInstaller archive
            ]
            
            for sig in pyinstaller_signatures:
                if sig in data:
                    self.is_pyinstaller = True
                    return True
                    
            return False
            
        except Exception as e:
            print(f"[!] Error detecting PyInstaller: {e}")
            return False
    
    def analyze_bytecode(self):
        """
        Extract and analyze Python bytecode from PyInstaller archive.
        This is a simplified version - full extraction requires pyinstxtractor.
        """
        if not self.is_pyinstaller:
            return
            
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Look for suspicious string patterns in the binary
            # Higher penalties for dangerous Python patterns
            suspicious_keywords = {
                # CRITICAL - Almost always malicious in packed executables
                b'WriteProcessMemory': ('Process Injection (CRITICAL)', 25),
                b'CreateRemoteThread': ('Code Execution in Remote Process', 25),
                b'GetAsyncKeyState': ('Keylogging (Spyware)', 25),
                b'VirtualAlloc': ('Memory Manipulation', 20),
                b'AdjustTokenPrivileges': ('Privilege Escalation', 20),
                
                # HIGH - Very suspicious in Python executables
                b'exec': ('Arbitrary Code Execution', 20),
                b'eval': ('Dynamic Code Execution', 20),
                b'subprocess': ('Command Execution', 18),
                b'os.system': ('Shell Command Execution', 18),
                b'ctypes': ('Low-level DLL Access', 18),
                b'WinDLL': ('Dynamic DLL Loading', 15),
                b'windll': ('Dynamic DLL Loading', 15),
                
                # MEDIUM - Suspicious but sometimes legitimate
                b'CreateToolhelp32Snapshot': ('Process Enumeration', 12),
                b'kernel32': ('Low-level Windows API', 10),
                b'advapi32': ('Advanced Windows API', 10),
                b'__import__': ('Dynamic Import', 8),
            }
            
            for keyword, (category, penalty) in suspicious_keywords.items():
                if keyword in data:
                    self.suspicious_patterns.append({
                        'pattern': keyword.decode('utf-8', errors='ignore'),
                        'category': category,
                        'penalty': penalty
                    })
                    self.risk_score += penalty
            
            # Deduplicate patterns
            seen = set()
            unique_patterns = []
            for pattern in self.suspicious_patterns:
                key = pattern['pattern']
                if key not in seen:
                    seen.add(key)
                    unique_patterns.append(pattern)
            
            self.suspicious_patterns = unique_patterns
            
        except Exception as e:
            print(f"[!] Error analyzing bytecode: {e}")
    
    def get_risk_level(self):
        """Categorize risk score"""
        if self.risk_score >= 51:
            return "HIGH"
        elif self.risk_score >= 26:
            return "MEDIUM"
        else:
            return "LOW"
    
    def analyze(self):
        """Run full PyInstaller analysis"""
        if not self.detect_pyinstaller():
            return None
        
        print(f"[*] Detected PyInstaller executable")
        self.analyze_bytecode()
        
        # Cap risk score at 100
        if self.risk_score > 100:
            self.risk_score = 100
        
        return {
            'is_pyinstaller': True,
            'suspicious_patterns': self.suspicious_patterns,
            'risk_score': self.risk_score,
            'risk_level': self.get_risk_level()
        }


# Test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "dist/malware_test.exe"
    
    print(f"[*] Analyzing PyInstaller executable: {target}")
    
    analyzer = PyInstallerAnalyzer(target)
    results = analyzer.analyze()
    
    if results:
        print(f"\n[✓] PyInstaller detected")
        print(f"[*] Suspicious patterns found: {len(results['suspicious_patterns'])}")
        for pattern in results['suspicious_patterns']:
            print(f"  - {pattern['pattern']}: {pattern['category']}")
        print(f"\n[*] Risk Score: {results['risk_score']}/100")
        print(f"[*] Risk Level: {results['risk_level']}")
    else:
        print("[!] Not a PyInstaller executable")
