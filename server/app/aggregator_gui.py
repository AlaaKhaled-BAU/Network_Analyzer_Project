"""
GUI for Multi-Window Network Traffic Aggregator

Simple interface to:
- Select raw packet CSV file OR dataset folder
- Configure window sizes and label
- Run aggregation (single file or batch folder processing)
- Save results to chosen location

THEMED VERSION: Dark Purple (Data Processing theme)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
from pathlib import Path

# Theme Colors (Data Processing - Dark Purple theme)
BG_COLOR = "#1a1a2e"
CARD_BG = "#252540"
ACCENT_COLOR = "#9b59b6"
ACCENT_HOVER = "#8e44ad"
SUCCESS_COLOR = "#66bb6a"
ERROR_COLOR = "#e74c3c"
WARNING_COLOR = "#f39c12"
TEXT_COLOR = "#ecf0f1"
MUTED_COLOR = "#7f8c8d"

# Import the aggregator (assuming MultiWindowAggregator.py is in same folder)
try:
    from MultiWindowAggregator import MultiWindowAggregator
except ImportError:
    messagebox.showerror(
        "Import Error",
        "Cannot find MultiWindowAggregator.py\n"
        "Make sure it's in the same folder as this GUI script."
    )
    sys.exit(1)


class AggregatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Aggregator")
        
        # Position window (center by default)
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = 950
        window_height = screen_height - 100
        x_position = (screen_width - window_width) // 2
        y_position = 20
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        self.root.minsize(900, 700)
        
        # Apply dark theme
        self.root.configure(bg=BG_COLOR)

        self.input_file = None
        self.input_folder = None
        self.output_file = None
        self.is_running = False

        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        """Configure ttk styles for purple data theme"""
        style = ttk.Style(self.root)
        style.theme_use("clam")
        
        # Frame styles
        style.configure("TFrame", background=BG_COLOR)
        style.configure("Card.TFrame", background=CARD_BG)
        
        # Label styles
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground=ACCENT_COLOR, background=BG_COLOR)
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"), background=BG_COLOR)
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("CardBold.TLabel", background=CARD_BG, foreground=ACCENT_COLOR, font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel", background=CARD_BG, foreground=MUTED_COLOR, font=("Segoe UI", 9))
        
        # LabelFrame styles
        style.configure("Card.TLabelframe", background=CARD_BG, relief="flat", borderwidth=2)
        style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground=ACCENT_COLOR, background=CARD_BG)
        
        # Button styles
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), background=ACCENT_COLOR, foreground="#ffffff", borderwidth=0, padding=[12, 8])
        style.map("Accent.TButton", background=[("active", ACCENT_HOVER)])
        
        style.configure("Cancel.TButton", font=("Segoe UI", 10, "bold"), background=ERROR_COLOR, foreground="#ffffff", borderwidth=0, padding=[12, 8])
        style.map("Cancel.TButton", background=[("active", "#c0392b")])
        
        style.configure("Small.TButton", font=("Segoe UI", 9), background=CARD_BG, foreground=TEXT_COLOR, borderwidth=1, padding=[8, 4])
        style.map("Small.TButton", background=[("active", "#353560")])
        
        # Entry and Combobox styles
        style.configure("TEntry", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1, insertcolor=TEXT_COLOR)
        style.configure("TCombobox", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)
        style.map("TCombobox", fieldbackground=[("readonly", CARD_BG)])
        
        # Checkbutton and Radiobutton
        style.configure("TCheckbutton", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("TRadiobutton", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        
        # Progressbar
        style.configure("purple.Horizontal.TProgressbar", background=ACCENT_COLOR, troughcolor=CARD_BG)
        
        # Separator
        style.configure("TSeparator", background=ACCENT_COLOR)

    def setup_ui(self):
        """Create the GUI layout"""
        
        # ==========================================
        # HEADER
        # ==========================================
        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill="x")
        
        ttk.Label(header, text="📊 Network Traffic Aggregator", style="Header.TLabel").pack(side="left")
        
        # Status indicator
        self.status_label = ttk.Label(header, text="🟢 Ready", style="Status.TLabel", foreground=SUCCESS_COLOR)
        self.status_label.pack(side="left", padx=20)
        
        # Cancel button (right side)
        self.cancel_btn = ttk.Button(header, text="✖ Cancel", command=self.cancel_run, style="Cancel.TButton", state=tk.DISABLED)
        self.cancel_btn.pack(side="right", padx=8)

        # ==========================================
        # MAIN CONTENT (Two columns)
        # ==========================================
        content = ttk.Frame(self.root, padding=16)
        content.pack(fill="both", expand=True)
        
        # LEFT COLUMN - Configuration
        left = ttk.Frame(content)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        
        # MODE SELECTION Card
        mode_card = ttk.LabelFrame(left, text="📁 Processing Mode", style="Card.TLabelframe", padding=12)
        mode_card.pack(fill="x", pady=(0, 10))
        
        mode_inner = ttk.Frame(mode_card, style="Card.TFrame")
        mode_inner.pack(fill="x")
        
        self.mode_var = tk.StringVar(value="folder")
        ttk.Radiobutton(mode_inner, text="📁 Dataset Folder (auto-process all)", 
                       variable=self.mode_var, value="folder",
                       command=self.toggle_mode).pack(anchor="w", pady=2)
        ttk.Radiobutton(mode_inner, text="📄 Single File", 
                       variable=self.mode_var, value="file",
                       command=self.toggle_mode).pack(anchor="w", pady=2)
        
        # INPUT SELECTION Card
        input_card = ttk.LabelFrame(left, text="📂 Input Selection", style="Card.TLabelframe", padding=12)
        input_card.pack(fill="x", pady=(0, 10))
        
        # Folder frame
        self.folder_frame = ttk.Frame(input_card, style="Card.TFrame")
        self.folder_frame.pack(fill="x")
        
        folder_row = ttk.Frame(self.folder_frame, style="Card.TFrame")
        folder_row.pack(fill="x", pady=4)
        
        self.folder_label = ttk.Label(folder_row, text="No folder selected", style="Muted.TLabel")
        self.folder_label.pack(side="left", fill="x", expand=True)
        
        self.folder_btn = ttk.Button(folder_row, text="Browse Folder...", command=self.browse_folder, style="Small.TButton")
        self.folder_btn.pack(side="right")
        
        self.folder_info_label = ttk.Label(self.folder_frame, text="", style="Card.TLabel", foreground=ACCENT_COLOR)
        self.folder_info_label.pack(anchor="w", pady=(4, 0))
        
        # File frame (hidden by default)
        self.file_frame = ttk.Frame(input_card, style="Card.TFrame")
        
        file_row = ttk.Frame(self.file_frame, style="Card.TFrame")
        file_row.pack(fill="x", pady=4)
        
        self.input_label = ttk.Label(file_row, text="No file selected", style="Muted.TLabel")
        self.input_label.pack(side="left", fill="x", expand=True)
        
        self.input_btn = ttk.Button(file_row, text="Browse File...", command=self.browse_input, style="Small.TButton")
        self.input_btn.pack(side="right")
        
        # CONFIGURATION Card
        config_card = ttk.LabelFrame(left, text="⚙ Configuration", style="Card.TLabelframe", padding=12)
        config_card.pack(fill="x", pady=(0, 10))
        
        config_inner = ttk.Frame(config_card, style="Card.TFrame")
        config_inner.pack(fill="x")
        
        # Window sizes
        ttk.Label(config_inner, text="Window Sizes:", style="CardBold.TLabel").pack(anchor="w", pady=(0, 4))
        
        window_frame = ttk.Frame(config_inner, style="Card.TFrame")
        window_frame.pack(fill="x", pady=(0, 8))
        
        self.window_5s = tk.BooleanVar(value=True)
        self.window_30s = tk.BooleanVar(value=True)
        self.window_3min = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(window_frame, text="5 seconds", variable=self.window_5s).pack(side="left", padx=(0, 15))
        ttk.Checkbutton(window_frame, text="30 seconds", variable=self.window_30s).pack(side="left", padx=(0, 15))
        ttk.Checkbutton(window_frame, text="3 minutes", variable=self.window_3min).pack(side="left")
        
        # Label (for single file mode)
        self.label_frame = ttk.Frame(config_inner, style="Card.TFrame")
        self.label_frame.pack(fill="x", pady=(8, 0))
        
        ttk.Label(self.label_frame, text="Traffic Label:", style="CardBold.TLabel").pack(anchor="w", pady=(0, 4))
        
        self.label_var = tk.StringVar()
        self.label_combo = ttk.Combobox(self.label_frame, textvariable=self.label_var, 
                                   state="normal", width=30)
        self.label_combo['values'] = (
            'Normal', 'DDoS', 'Port Scanning', 'Brute Force',
            'ARP Poisoning', 'DNS Tunneling', 'Slowloris'
        )
        self.label_combo.set('Normal')
        
        # Auto-label info (shown in folder mode)
        self.auto_label_info = ttk.Label(self.label_frame, 
            text="ℹ️ Labels read from 'attack_label' column in each CSV",
            style="Card.TLabel", foreground=SUCCESS_COLOR)
        self.auto_label_info.pack(anchor="w")
        
        # Output format
        ttk.Label(config_inner, text="Output Format:", style="CardBold.TLabel").pack(anchor="w", pady=(12, 4))
        
        format_frame = ttk.Frame(config_inner, style="Card.TFrame")
        format_frame.pack(fill="x")
        
        self.format_var = tk.StringVar(value="csv")
        ttk.Radiobutton(format_frame, text="CSV", variable=self.format_var, value="csv").pack(side="left", padx=(0, 15))
        ttk.Radiobutton(format_frame, text="JSON", variable=self.format_var, value="json").pack(side="left")
        
        # RUN BUTTON
        self.run_btn = ttk.Button(left, text="▶ Run Aggregation", command=self.run_aggregation, style="Accent.TButton")
        self.run_btn.pack(fill="x", pady=(10, 0))
        
        # PROGRESS Card
        progress_card = ttk.LabelFrame(left, text="📈 Progress", style="Card.TLabelframe", padding=12)
        progress_card.pack(fill="x", pady=(10, 0))
        
        self.progress_label = ttk.Label(progress_card, text="Ready", style="Muted.TLabel")
        self.progress_label.pack(anchor="w")
        
        self.progress = ttk.Progressbar(progress_card, mode='determinate', maximum=100, style="purple.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(8, 0))
        
        # RIGHT COLUMN - Log Output
        right = ttk.Frame(content)
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))
        
        log_card = ttk.LabelFrame(right, text="📋 Activity Log", style="Card.TLabelframe", padding=12)
        log_card.pack(fill="both", expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            log_card, 
            height=20, 
            state=tk.DISABLED,
            wrap=tk.WORD, 
            font=("Consolas", 9),
            background=BG_COLOR,
            foreground=TEXT_COLOR,
            insertbackground=TEXT_COLOR
        )
        self.log_text.pack(fill="both", expand=True)
        
        # Configure log tags
        self.log_text.tag_config("INFO", foreground=TEXT_COLOR)
        self.log_text.tag_config("ERROR", foreground=ERROR_COLOR)
        self.log_text.tag_config("SUCCESS", foreground=SUCCESS_COLOR)
        self.log_text.tag_config("PROGRESS", foreground=ACCENT_COLOR)
        self.log_text.tag_config("WARNING", foreground=WARNING_COLOR)
        
        # ==========================================
        # FOOTER
        # ==========================================
        footer = ttk.Frame(self.root, padding=(16, 10))
        footer.pack(fill="x")
        
        ttk.Label(footer, text="💡 Process raw CSV packets into ML-ready aggregated features", foreground=ACCENT_COLOR).pack(side="left")
        
        # Clear log button
        ttk.Button(footer, text="🗑", command=self.clear_log, width=3, style="Small.TButton").pack(side="right", padx=4)
        
        # Initial log messages
        self.log("📊 Network Traffic Aggregator loaded", "SUCCESS")
        self.log("", "INFO")
        self.log("📁 FOLDER MODE: Process all attack variations automatically", "INFO")
        self.log("📄 FILE MODE: Process single CSV file", "INFO")
        
        # Apply initial mode
        self.toggle_mode()

    def clear_log(self):
        """Clear the activity log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def toggle_mode(self):
        """Toggle between folder and single file mode"""
        if self.mode_var.get() == "folder":
            self.folder_frame.pack(fill="x")
            self.file_frame.pack_forget()
            self.label_combo.pack_forget()
            self.auto_label_info.pack(anchor="w")
        else:
            self.file_frame.pack(fill="x")
            self.folder_frame.pack_forget()
            self.auto_label_info.pack_forget()
            self.label_combo.pack(fill="x")

    def browse_folder(self):
        """Browse for dataset folder"""
        folder = filedialog.askdirectory(title="Select Attack Datasets Folder")

        if folder:
            self.input_folder = folder
            folder_path = Path(folder)
            self.folder_label.config(text=folder_path.name, foreground=TEXT_COLOR)
            
            # Count variation subfolders
            variations = [d for d in folder_path.iterdir() if d.is_dir() and not d.name.startswith(".")]
            self.folder_info_label.config(text=f"Found {len(variations)} variation folders")
            self.log(f"Selected folder: {folder_path.name}", "INFO")
            self.log(f"  → {len(variations)} variations to process", "SUCCESS")

    def browse_input(self):
        """Browse for input CSV file"""
        filename = filedialog.askopenfilename(
            title="Select Raw Packets CSV File",
            filetypes=[
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )

        if filename:
            self.input_file = filename
            self.input_label.config(text=Path(filename).name, foreground=TEXT_COLOR)
            self.log(f"Selected input: {Path(filename).name}", "INFO")

    def get_window_sizes(self):
        """Get selected window sizes"""
        sizes = []
        if self.window_5s.get():
            sizes.append(5)
        if self.window_30s.get():
            sizes.append(30)
        if self.window_3min.get():
            sizes.append(180)
        return sizes

    def log(self, message, tag="INFO"):
        """Add message to log output"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update_idletasks()

    def update_progress(self, current, total, folder_name):
        """Update progress bar and label"""
        pct = (current / total) * 100
        self.progress['value'] = pct
        self.progress_label.config(text=f"Processing {current}/{total}: {folder_name}", foreground=ACCENT_COLOR)
        self.root.update_idletasks()

    def run_aggregation(self):
        """Run the aggregation process in a separate thread"""
        # Validation based on mode
        if self.mode_var.get() == "folder":
            if not self.input_folder:
                messagebox.showerror("Error", "Please select a dataset folder first!")
                return
            if not Path(self.input_folder).exists():
                messagebox.showerror("Error", "Selected folder does not exist!")
                return
        else:
            if not self.input_file:
                messagebox.showerror("Error", "Please select an input file first!")
                return
            if not Path(self.input_file).exists():
                messagebox.showerror("Error", "Selected input file does not exist!")
                return

        window_sizes = self.get_window_sizes()
        if not window_sizes:
            messagebox.showerror("Error", "Please select at least one window size!")
            return

        # Ask for output location
        default_ext = f".{self.format_var.get()}"
        output_file = filedialog.asksaveasfilename(
            title="Save Aggregated Features As",
            defaultextension=default_ext,
            filetypes=[
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )

        if not output_file:
            self.log("Output save cancelled by user", "WARNING")
            return

        self.output_file = output_file

        # Disable controls
        self.is_running = True
        self.status_label.config(text="🔴 Processing", foreground=WARNING_COLOR)
        self.run_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.folder_btn.config(state=tk.DISABLED)
        if hasattr(self, 'input_btn'):
            self.input_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0

        # Clear log
        self.clear_log()

        # Run in thread
        thread = threading.Thread(target=self._run_aggregation_thread, daemon=True)
        thread.start()

    def _run_aggregation_thread(self):
        """Thread worker for aggregation"""
        try:
            window_sizes = self.get_window_sizes()

            self.log(f"🚀 Starting aggregation...", "SUCCESS")
            self.log(f"Window sizes: {window_sizes} seconds", "INFO")
            self.log(f"Output format: {self.format_var.get().upper()}", "INFO")
            self.log("", "INFO")

            # Create aggregator
            agg = MultiWindowAggregator(window_sizes=window_sizes)

            if self.mode_var.get() == "folder":
                # FOLDER MODE: Process all variations
                self.log(f"📁 FOLDER MODE: {Path(self.input_folder).name}", "INFO")
                self.log("Processing all variations...", "INFO")

                def progress_callback(current, total, folder_name):
                    self.root.after(0, lambda: self.update_progress(current, total, folder_name))
                    self.log(f"  [{current}/{total}] {folder_name}", "PROGRESS")

                result = agg.process_dataset_folder(
                    self.input_folder, 
                    progress_callback=progress_callback
                )

            else:
                # SINGLE FILE MODE
                label = self.label_var.get() if self.label_var.get() else None
                self.log(f"📄 SINGLE FILE MODE", "INFO")
                self.log(f"Input: {Path(self.input_file).name}", "INFO")
                self.log(f"Label: {label or 'None'}", "INFO")

                self.progress.config(mode='indeterminate')
                self.progress.start(10)
                
                result = agg.process_file(self.input_file, label=label)

            if result.empty:
                self.log("ERROR: No data generated! Check input.", "ERROR")
                self.finish_run(success=False)
                return

            self.log(f"", "INFO")
            self.log(f"✓ Generated {len(result)} total records", "SUCCESS")

            # Show distribution
            self.log("", "INFO")
            self.log("Records per window size:", "INFO")
            for ws, count in result.groupby('window_size').size().items():
                self.log(f"  {ws}s: {count} records", "INFO")

            if self.mode_var.get() == "folder":
                self.log("", "INFO")
                self.log("Records per attack type:", "INFO")
                for label, count in result.groupby('label').size().items():
                    self.log(f"  {label}: {count} records", "INFO")

            # Save results
            self.log(f"", "INFO")
            self.log(f"Saving to {Path(self.output_file).name}...", "INFO")
            agg.save_results(result, self.output_file, fmt=self.format_var.get())

            self.log(f"", "INFO")
            self.log(f"✓ SUCCESS! Saved to: {Path(self.output_file).name}", "SUCCESS")
            self.log(f"Features: {len(result.columns)} columns", "INFO")
            self.log(f"Records: {len(result)} rows", "INFO")

            self.finish_run(success=True)

            # Show success dialog
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"Aggregation complete!\n\n"
                f"Records: {len(result)}\n"
                f"Features: {len(result.columns)}\n"
                f"Saved to: {Path(self.output_file).name}"
            ))

        except Exception as e:
            error_msg = f"ERROR: {str(e)}"
            self.log(f"", "INFO")
            self.log(error_msg, "ERROR")
            self.finish_run(success=False)

            # Show error dialog
            self.root.after(0, lambda: messagebox.showerror(
                "Error",
                f"Aggregation failed:\n\n{str(e)}"
            ))

    def cancel_run(self):
        """Cancel the running aggregation"""
        if messagebox.askyesno("Cancel", "Are you sure you want to cancel?"):
            self.is_running = False
            self.log("", "INFO")
            self.log("Cancelled by user", "WARNING")
            self.finish_run(success=False)

    def finish_run(self, success=True):
        """Re-enable controls after run completes"""
        self.is_running = False
        self.progress.stop()
        self.progress.config(mode='determinate')
        if success:
            self.progress['value'] = 100
            self.progress_label.config(text="Complete!", foreground=SUCCESS_COLOR)
            self.status_label.config(text="✓ Complete", foreground=SUCCESS_COLOR)
        else:
            self.progress['value'] = 0
            self.progress_label.config(text="Failed", foreground=ERROR_COLOR)
            self.status_label.config(text="🟢 Ready", foreground=SUCCESS_COLOR)
        self.run_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.folder_btn.config(state=tk.NORMAL)
        if hasattr(self, 'input_btn'):
            self.input_btn.config(state=tk.NORMAL)


def main():
    """Launch the GUI"""
    root = tk.Tk()
    app = AggregatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
