#!/usr/bin/env python3
"""
Zero-Trust Launcher - Main Entry Point

A pre-execution malware analyzer for Windows executables.
Detects packed/encrypted malware and suspicious API usage.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui.main_window import main

if __name__ == "__main__":
    print("="*60)
    print("🛡️  Zero-Trust Launcher")
    print("    Pre-Execution Malware Analyzer")
    print("="*60)
    print()
    
    main()
