import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False
import os
import sys
import threading
import math
from modules.vulnerability_explanations import get_explanation, format_explanation

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.core_analyzer import ZeroTrustAnalyzer


class ZeroTrustLauncherUI:
    """
    Windows Wizard-style UI for Zero-Trust Launcher.
    Classic installer aesthetic with multi-page flow.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Trust Launcher")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        
        # State
        self.current_page = 0
        self.selected_file = None
        self.analysis_results = None
        
        # Configure style for classic Windows look
        self.setup_styles()
        
        # Create pages
        self.pages = []
        self.create_welcome_page()
        self.create_file_selection_page()
        self.create_analysis_page()
        self.create_results_page()
        
        # Show first page
        self.show_page(0)
    
    def setup_styles(self):
        """Configure ttk styles for classic Windows appearance"""
        style = ttk.Style()
        style.theme_use('vista')  # Windows classic theme
        
        # Custom button style
        style.configure('Wizard.TButton', 
                       font=('Segoe UI', 9),
                       padding=6)
        
        # Title label style
        style.configure('Title.TLabel',
                       font=('Segoe UI', 16, 'bold'),
                       foreground='#003366')
        
        # Subtitle style
        style.configure('Subtitle.TLabel',
                       font=('Segoe UI', 10),
                       foreground='#666666')
    
    def create_welcome_page(self):
        """Page 1: Welcome screen"""
        page = ttk.Frame(self.root)
        self.pages.append(page)
        
        # Content container (not expanding)
        content = ttk.Frame(page)
        content.pack(fill='both', expand=False, padx=20, pady=20)
        
        # Graphic Header
        header_frame = ttk.Frame(content)
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Draw Shield Icon using Canvas
        self.canvas = tk.Canvas(header_frame, width=80, height=80, bg='#f0f0f0', highlightthickness=0)
        self.canvas.pack(pady=10)
        
        # Shield logic
        self.canvas.create_polygon(40, 5, 75, 20, 75, 45, 40, 75, 5, 45, 5, 20, 
                                 fill='#003366', outline='#002244', width=2)
        # Shield highlight/glare
        self.canvas.create_polygon(40, 5, 75, 20, 75, 45, 40, 75, 
                                 fill='#004488', outline='')
        # Lock icon inside
        self.canvas.create_rectangle(32, 35, 48, 50, fill='white')
        self.canvas.create_arc(32, 25, 48, 45, start=0, extent=180, style='arc', outline='white', width=3)
        
        
        ttk.Label(header_frame,
                 text="ZERO-TRUST LAUNCHER",
                 font=('Segoe UI', 16, 'bold'),
                 foreground='#003366').pack()
        
        ttk.Label(header_frame,
                 text="PRE-EXECUTION MALWARE ANALYZER",
                 font=('Segoe UI', 9),
                 foreground='#666666').pack(pady=2)
        
        # Welcome text
        welcome_text = """Welcome to Zero-Trust Launcher!

This tool analyzes Windows executables BEFORE you run them, 
detecting packed malware and suspicious behavior that 
traditional antivirus might miss.

What we check:
  > Shannon Entropy (crypter/packer detection)
  > Suspicious API imports (injection, keylogging, etc.)
  > Risk scoring (0-100 scale)

Click "Next" to select a file for analysis."""
        
        ttk.Label(content, 
                 text=welcome_text,
                 font=('Segoe UI', 10),
                 justify='left').pack(anchor='w', pady=10)
        
        # Navigation buttons (at bottom)
        self.create_nav_buttons(page, next_enabled=True)
    
    def create_file_selection_page(self):
        """Page 2: File selection with drag-and-drop"""
        page = ttk.Frame(self.root)
        self.pages.append(page)
        
        # Title
        ttk.Label(page, 
                 text="Select Executable to Analyze",
                 style='Title.TLabel').pack(pady=20)
        
        # Drop zone
        drop_frame = ttk.Frame(page, relief='solid', borderwidth=2)
        drop_frame.pack(fill='both', expand=True, padx=40, pady=20)
        
        # Draw File Icon
        self.drop_canvas = tk.Canvas(drop_frame, width=60, height=80, bg='#f0f0f0', highlightthickness=0)
        self.drop_canvas.pack(pady=(40, 10))
        
        # File shape with folded corner
        self.drop_canvas.create_polygon(10, 5, 40, 5, 55, 20, 55, 75, 10, 75, 
                                      fill='white', outline='#666666', width=2)
        self.drop_canvas.create_line(40, 5, 40, 20, 55, 20, fill='#666666', width=2)
        
        # Binary code lines inside
        self.drop_canvas.create_line(18, 25, 45, 25, fill='#cccccc', width=2)
        self.drop_canvas.create_line(18, 35, 45, 35, fill='#cccccc', width=2)
        self.drop_canvas.create_line(18, 45, 45, 45, fill='#cccccc', width=2)
        
        ttk.Label(drop_frame,
                 text="Drag & Drop .exe file here\n\nor click Browse",
                 font=('Segoe UI', 12),
                 foreground='#666666',
                 justify='center').pack(pady=(0, 40))
        
        # Browse button
        ttk.Button(page,
                  text="Browse...",
                  style='Wizard.TButton',
                  command=self.browse_file).pack(pady=10)
        
        # Selected file label
        self.file_label = ttk.Label(page,
                                   text="No file selected",
                                   font=('Segoe UI', 9, 'italic'),
                                   foreground='#999999')
        self.file_label.pack(pady=5)
        
        # Navigation
        self.create_nav_buttons(page, back_enabled=True, next_enabled=False)
        
        # Enable drag-and-drop only if tkinterdnd2 is available
        if HAS_DND:
            drop_frame.drop_target_register(DND_FILES)
            drop_frame.dnd_bind('<<Drop>>', self.on_drop)
    
    def create_analysis_page(self):
        """Page 3: Analysis in progress"""
        page = ttk.Frame(self.root)
        self.pages.append(page)
        
        ttk.Label(page,
                 text="Analyzing File...",
                 style='Title.TLabel').pack(pady=30)
        
        # Radar Animation Canvas
        self.radar_canvas = tk.Canvas(page, width=200, height=200, bg='#f0f0f0', highlightthickness=0)
        self.radar_canvas.pack(pady=10)
        
        # Draw static radar elements
        self.radar_canvas.create_oval(10, 10, 190, 190, outline='#cccccc', width=2)
        self.radar_canvas.create_oval(50, 50, 150, 150, outline='#cccccc', width=1)
        self.radar_canvas.create_line(100, 10, 100, 190, fill='#cccccc')
        self.radar_canvas.create_line(10, 100, 190, 100, fill='#cccccc')
        
        # Scanning line (will be animated)
        self.scan_angle = 0
        self.scan_line = self.radar_canvas.create_line(100, 100, 100, 10, fill='#00cc00', width=2)
        
        # Status label
        self.status_label = ttk.Label(page,
                                     text="Initializing...",
                                     font=('Segoe UI', 12, 'bold'),
                                     foreground='#003366')
        self.status_label.pack(pady=10)
        
        # Analysis details
        self.analysis_text = tk.Text(page,
                                    height=15,
                                    width=60,
                                    font=('Consolas', 9),
                                    bg='#f0f0f0',
                                    relief='solid',
                                    borderwidth=1)
        self.analysis_text.pack(padx=40, pady=20)
        
        # No navigation buttons (auto-advances)
    
    def create_results_page(self):
        """Page 4: Results display"""
        page = ttk.Frame(self.root)
        self.pages.append(page)
        
        ttk.Label(page,
                 text="Analysis Complete",
                 style='Title.TLabel').pack(pady=20)
        
        # Results container (scrollable, not expanding to push buttons away)
        results_container = ttk.Frame(page)
        results_container.pack(fill='both', expand=True, padx=40, pady=10)
        
        # Canvas for scrolling
        canvas = tk.Canvas(results_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(results_container, orient="vertical", command=canvas.yview)
        self.results_frame = ttk.Frame(canvas)
        
        self.results_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.results_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Navigation (always visible at bottom)
        nav_frame = ttk.Frame(page)
        nav_frame.pack(fill='x', side='bottom', padx=20, pady=10)
        
        ttk.Button(nav_frame,
                  text="Analyze Another File",
                  style='Wizard.TButton',
                  command=lambda: self.show_page(1)).pack(side='left')
        
        ttk.Button(nav_frame,
                  text="Exit",
                  style='Wizard.TButton',
                  command=self.root.quit).pack(side='right')
    
    def create_nav_buttons(self, page, back_enabled=False, next_enabled=False):
        """Create Back/Next navigation buttons"""
        nav_frame = ttk.Frame(page)
        nav_frame.pack(fill='x', side='bottom', padx=20, pady=10)
        
        # Back button
        back_btn = ttk.Button(nav_frame,
                             text="< Back",
                             style='Wizard.TButton',
                             command=self.go_back,
                             state='normal' if back_enabled else 'disabled')
        back_btn.pack(side='left')
        
        # Next button
        self.next_btn = ttk.Button(nav_frame,
                                   text="Next >",
                                   style='Wizard.TButton',
                                   command=self.go_next,
                                   state='normal' if next_enabled else 'disabled')
        self.next_btn.pack(side='right')
    
    def show_page(self, page_num):
        """Display specific page"""
        # Hide all pages
        for page in self.pages:
            page.pack_forget()
        
        # Show requested page
        self.current_page = page_num
        self.pages[page_num].pack(fill='both', expand=True)
    
    def go_back(self):
        """Navigate to previous page"""
        if self.current_page > 0:
            self.show_page(self.current_page - 1)
    
    def go_next(self):
        """Navigate to next page"""
        if self.current_page == 1 and self.selected_file:
            # Start analysis
            self.show_page(2)
            self.run_analysis()
        elif self.current_page < len(self.pages) - 1:
            self.show_page(self.current_page + 1)
    
    def browse_file(self):
        """Open file browser dialog"""
        filename = filedialog.askopenfilename(
            title="Select Executable",
            filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
        )
        
        if filename:
            self.select_file(filename)
    
    def on_drop(self, event):
        """Handle drag-and-drop event"""
        # tkinterdnd2 returns file path with curly braces
        file_path = event.data.strip('{}')
        self.select_file(file_path)
    
    def select_file(self, file_path):
        """Update selected file and visual feedback"""
        if os.path.isfile(file_path):
            self.selected_file = file_path
            
            # Glow effect: Change icon color to blue
            self.drop_canvas.itemconfig(1, outline='#003366', fill='#e6f0ff') # Polygon body
            self.drop_canvas.itemconfig(2, fill='#003366') # Fold corner
            # Code lines turn blue
            self.drop_canvas.itemconfig(3, fill='#0066cc')
            self.drop_canvas.itemconfig(4, fill='#0066cc')
            self.drop_canvas.itemconfig(5, fill='#0066cc')
            
            self.file_label.config(
                text=f"SELECTED: {os.path.basename(file_path)}",
                foreground='#003366',
                font=('Segoe UI', 10, 'bold')
            )
            self.next_btn.config(state='normal')
        else:
            messagebox.showerror("Error", "Invalid file selected")
    
    def run_analysis(self):
        """Execute analysis in background thread"""
        
        def analyze():
            try:
                # Update status
                self.status_label.config(text="Loading file...", foreground='#003366')
                self.analysis_text.delete('1.0', 'end')
                self.analysis_text.insert('end', f"[*] Target: {os.path.basename(self.selected_file)}\n")
                
                # Create analyzer
                analyzer = ZeroTrustAnalyzer(self.selected_file)
                
                # Run analysis with radar animation
                self.status_label.config(text="Scanning file structure...")
                self.analysis_text.insert('end', "[*] Calculating Shannon entropy...\n")
                
                # Simulate scanning time for effect (and to show animation)
                for i in range(25):
                    self.update_radar()
                    self.root.update()
                    import time
                    time.sleep(0.05)
                
                results = analyzer.analyze()
                
                if results:
                    self.analysis_results = results
                    
                    # Display progress
                    self.analysis_text.insert('end', f"[✓] Entropy: {results['entropy']:.4f}\n")
                    self.analysis_text.insert('end', f"[*] Scanning imports...\n")
                    self.analysis_text.insert('end', f"[✓] Found {len(results['suspicious_imports'])} suspicious APIs\n")
                    self.analysis_text.insert('end', f"[*] Calculating risk score...\n")
                    self.analysis_text.insert('end', f"[✓] Risk: {results['risk_score']}/100\n\n")
                    self.analysis_text.insert('end', "[✓] Analysis complete!\n")
                    
                    # Stop progress and show results
                    self.status_label.config(text="Complete!", foreground='#28a745')
                    self.root.after(1000, lambda: self.display_results())
                else:
                    raise Exception("Analysis failed")
                    
            except Exception as e:
                self.analysis_text.insert('end', f"\n[!] Error: {str(e)}\n")
                messagebox.showerror("Analysis Error", f"Failed to analyze file:\n{str(e)}")
                self.show_page(1)
        
        # Run in thread to prevent UI freeze
        thread = threading.Thread(target=analyze, daemon=True)
        thread.start()
    
    def display_results(self):
        """Show results on page 4"""
        self.show_page(3)
        
        # Clear previous results
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        results = self.analysis_results
        
        # Risk level banner
        risk_color = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#dc3545'
        }[results['risk_level']]
        
        banner = ttk.Frame(self.results_frame, relief='solid', borderwidth=2)
        banner.pack(fill='x', pady=10)
        banner.config(style='Risk.TFrame')
        
        # Risk level banner using Canvas
        risk_color = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#dc3545'
        }[results['risk_level']]
        
        banner_canvas = tk.Canvas(self.results_frame, height=80, bg=risk_color, highlightthickness=0)
        banner_canvas.pack(fill='x', pady=10)
        
        # Draw icon based on risk
        if results['risk_level'] == 'LOW':
            # Checkmark
            banner_canvas.create_line(30, 40, 45, 55, 70, 25, fill='white', width=5)
            banner_canvas.create_oval(20, 15, 80, 65, outline='white', width=2)
        elif results['risk_level'] == 'MEDIUM':
            # Exclamation
            banner_canvas.create_text(50, 40, text="!", font=('Segoe UI', 36, 'bold'), fill='white')
            banner_canvas.create_polygon(50, 15, 80, 65, 20, 65, outline='white', width=2)
        else:
            # Cross/Skull
            banner_canvas.create_line(35, 25, 65, 55, fill='white', width=5)
            banner_canvas.create_line(65, 25, 35, 55, fill='white', width=5)
            banner_canvas.create_oval(20, 15, 80, 65, outline='white', width=2)
            
        # Risk Text
        risk_text = f"RISK LEVEL: {results['risk_level']}"
        score_text = f"Score: {results['risk_score']}/100"
        
        banner_canvas.create_text(100, 30, text=risk_text, anchor='w', 
                                font=('Segoe UI', 16, 'bold'), fill='white')
        banner_canvas.create_text(100, 55, text=score_text, anchor='w', 
                                font=('Segoe UI', 12), fill='white')
        
        # Details
        details = ttk.Frame(self.results_frame)
        details.pack(fill='both', expand=True, pady=10)
        
        # Entropy
        ttk.Label(details,
                 text=f"▸ Entropy: {results['entropy']:.4f} / 8.0",
                 font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=5)
        
        if results['is_packed']:
            ttk.Label(details,
                     text="  ⚠ PACKED/ENCRYPTED: Code is obfuscated",
                     foreground='#ff6600').pack(anchor='w', padx=20)
            ttk.Label(details,
                     text="     Note: Games with anti-cheat (Valorant, Fortnite) often use packing",
                     foreground='#666666',
                     font=('Segoe UI', 9, 'italic')).pack(anchor='w', padx=20)
        else:
            ttk.Label(details,
                     text="  ✓ Normal entropy (not packed)",
                     foreground='#28a745').pack(anchor='w', padx=20)
        
        # Imports
        ttk.Label(details,
                 text=f"\n▸ Suspicious APIs: {len(results['suspicious_imports'])}",
                 font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=5)
        
        if results['suspicious_imports']:
            import_text = tk.Text(details, height=8, width=60,
                                 font=('Consolas', 9),
                                 bg='#fff8dc',
                                 relief='solid',
                                 borderwidth=1)
            import_text.pack(anchor='w', padx=20, pady=5)
            
            for imp in results['suspicious_imports']:
                import_text.insert('end', f"  - {imp['function']} ({imp['dll']})\n")
                import_text.insert('end', f"    > {imp['category']}\n\n")
            
            import_text.config(state='disabled')
            
            # Add "View Explanations" button
            btn_frame = ttk.Frame(details)
            btn_frame.pack(anchor='w', padx=20, pady=10)
            
            ttk.Button(btn_frame,
                      text="📖 View Detailed Explanations",
                      command=lambda: self.show_explanations(results['suspicious_imports']),
                      style='Wizard.TButton').pack(side='left')
        else:
            ttk.Label(details,
                     text="  ✓ No suspicious API calls detected",
                     foreground='#28a745').pack(anchor='w', padx=20)

    def show_explanations(self, suspicious_imports):
        """Show detailed explanations for detected vulnerabilities in a popup window"""
        popup = tk.Toplevel(self.root)
        popup.title("Vulnerability Explanations")
        popup.geometry("800x600")
        popup.configure(bg='#f5f5f5')
        
        # Header
        header = ttk.Label(popup,
                          text="🔍 Detailed Vulnerability Explanations",
                          font=('Segoe UI', 14, 'bold'),
                          background='#f5f5f5')
        header.pack(pady=15)
        
        # Scrollable text area
        text_frame = ttk.Frame(popup)
        text_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')
        
        text_widget = tk.Text(text_frame,
                             wrap='word',
                             font=('Consolas', 10),
                             yscrollcommand=scrollbar.set,
                             bg='#ffffff',
                             padx=15,
                             pady=15)
        text_widget.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # Add explanations
        for imp in suspicious_imports:
            api_name = imp['function']
            explanation = get_explanation(api_name)
            
            if explanation:
                # Format with colors
                text_widget.insert('end', f"\n{'='*70}\n", 'separator')
                text_widget.insert('end', f"🔍 {api_name} ", 'title')
                text_widget.insert('end', f"[{explanation['severity']} SEVERITY]\n", 'severity')
                text_widget.insert('end', f"{'='*70}\n\n", 'separator')
                
                text_widget.insert('end', "📖 What it does:\n", 'header')
                text_widget.insert('end', f"   {explanation['description']}\n\n", 'content')
                
                text_widget.insert('end', "⚠️  Why it's dangerous:\n", 'header')
                text_widget.insert('end', f"   {explanation['why_dangerous']}\n\n", 'content')
                
                text_widget.insert('end', "✅ Legitimate uses:\n", 'header')
                text_widget.insert('end', f"   {explanation['legitimate_uses']}\n\n", 'content')
                
                text_widget.insert('end', "🦠 Malware examples:\n", 'header')
                text_widget.insert('end', f"   {explanation['malware_examples']}\n\n", 'content')
            else:
                text_widget.insert('end', f"\n{api_name}: No detailed explanation available.\n\n")
        
        # Configure tags for formatting
        text_widget.tag_config('separator', foreground='#666666')
        text_widget.tag_config('title', font=('Segoe UI', 12, 'bold'), foreground='#003366')
        text_widget.tag_config('severity', font=('Segoe UI', 10, 'bold'), foreground='#dc3545')
        text_widget.tag_config('header', font=('Segoe UI', 10, 'bold'), foreground='#0066cc')
        text_widget.tag_config('content', foreground='#333333')
        
        text_widget.config(state='disabled')
        
        # Close button
        ttk.Button(popup,
                  text="Close",
                  command=popup.destroy,
                  style='Wizard.TButton').pack(pady=15)


    def update_radar(self):
        """Update radar scan line animation"""
        import math
        self.scan_angle = (self.scan_angle + 15) % 360
        radians = math.radians(self.scan_angle)
        
        # Calculate new endpoint
        length = 90
        end_x = 100 + length * math.sin(radians)
        end_y = 100 - length * math.cos(radians)
        
        self.radar_canvas.coords(self.scan_line, 100, 100, end_x, end_y)


def main():
    """Launch the application"""
    root = tk.Tk()
    
    if not HAS_DND:
        print("[!] tkinterdnd2 not available. Drag-and-drop disabled (use Browse button).")
    
    app = ZeroTrustLauncherUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
