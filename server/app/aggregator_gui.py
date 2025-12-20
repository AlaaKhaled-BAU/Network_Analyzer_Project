"""
GUI for Multi-Window Network Traffic Aggregator

Simple interface to:
- Select raw packet CSV file OR dataset folder
- Configure window sizes and label
- Run aggregation (single file or batch folder processing)
- Save results to chosen location
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
from pathlib import Path

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
        self.root.title("Network Traffic Aggregator - Multi-Window")
        self.root.geometry("750x700")
        self.root.resizable(True, True)

        self.input_file = None
        self.input_folder = None
        self.output_file = None
        self.is_running = False

        self.setup_ui()

    def setup_ui(self):
        """Create the GUI layout"""

        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # ========== MODE SELECTION ==========
        row = 0
        ttk.Label(main_frame, text="Processing Mode:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        self.mode_var = tk.StringVar(value="folder")
        mode_frame = ttk.Frame(main_frame)
        mode_frame.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=(10, 0))

        ttk.Radiobutton(mode_frame, text="📁 Dataset Folder (auto-process all variations)", 
                       variable=self.mode_var, value="folder",
                       command=self.toggle_mode).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="📄 Single File", 
                       variable=self.mode_var, value="file",
                       command=self.toggle_mode).pack(side=tk.LEFT, padx=5)

        # ========== FOLDER INPUT SECTION ==========
        row += 1
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).grid(
            row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10
        )

        row += 1
        self.folder_frame = ttk.Frame(main_frame)
        self.folder_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.folder_frame.columnconfigure(1, weight=1)

        ttk.Label(self.folder_frame, text="Dataset Folder:", 
                  font=("Arial", 10, "bold")).grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 5)
        )

        self.folder_label = ttk.Label(self.folder_frame, text="No folder selected", 
                                      foreground="gray")
        self.folder_label.grid(row=1, column=0, columnspan=2, 
                              sticky=(tk.W, tk.E), padx=(10, 5))

        self.folder_btn = ttk.Button(self.folder_frame, text="Browse Folder...", 
                                    command=self.browse_folder)
        self.folder_btn.grid(row=1, column=2, sticky=tk.E)

        self.folder_info_label = ttk.Label(self.folder_frame, text="", foreground="blue")
        self.folder_info_label.grid(row=2, column=0, columnspan=3, sticky=tk.W, padx=(10, 0), pady=(5, 0))

        # ========== FILE INPUT SECTION (hidden by default) ==========
        self.file_row = row + 1
        self.file_frame = ttk.Frame(main_frame)
        # Initially hidden - folder mode is default

        ttk.Label(self.file_frame, text="Input File (Raw Packets):", 
                  font=("Arial", 10, "bold")).grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 5)
        )

        self.input_label = ttk.Label(self.file_frame, text="No file selected", 
                                      foreground="gray")
        self.input_label.grid(row=1, column=0, columnspan=2, 
                              sticky=(tk.W, tk.E), padx=(10, 5))

        self.input_btn = ttk.Button(self.file_frame, text="Browse...", 
                                    command=self.browse_input)
        self.input_btn.grid(row=1, column=2, sticky=tk.E)

        # ========== CONFIGURATION SECTION ==========
        row += 2
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).grid(
            row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=15
        )

        row += 1
        ttk.Label(main_frame, text="Configuration:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, pady=(0, 5)
        )

        # Window sizes checkboxes
        row += 1
        ttk.Label(main_frame, text="Window Sizes:").grid(
            row=row, column=0, sticky=tk.W, padx=(10, 0)
        )

        window_frame = ttk.Frame(main_frame)
        window_frame.grid(row=row, column=1, columnspan=2, sticky=tk.W)

        self.window_5s = tk.BooleanVar(value=True)
        self.window_30s = tk.BooleanVar(value=True)
        self.window_3min = tk.BooleanVar(value=True)

        ttk.Checkbutton(window_frame, text="5 seconds", 
                       variable=self.window_5s).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(window_frame, text="30 seconds", 
                       variable=self.window_30s).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(window_frame, text="3 minutes", 
                       variable=self.window_3min).pack(side=tk.LEFT, padx=5)

        # Label input (only shown in single file mode)
        row += 1
        self.label_frame = ttk.Frame(main_frame)
        self.label_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Label(self.label_frame, text="Traffic Label:").grid(
            row=0, column=0, sticky=tk.W, padx=(10, 0)
        )

        self.label_var = tk.StringVar()
        self.label_combo = ttk.Combobox(self.label_frame, textvariable=self.label_var, 
                                   state="normal", width=30)
        self.label_combo['values'] = (
            'Normal',
            'DDoS',
            'Port Scanning',
            'Brute Force',
            'ARP Poisoning',
            'DNS Tunneling',
            'Slowloris'
        )
        self.label_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.label_combo.set('Normal')

        # Auto-label info (shown in folder mode)
        self.auto_label_info = ttk.Label(self.label_frame, 
            text="ℹ️ Labels read from 'attack_label' column in each CSV file",
            foreground="green")
        
        # Output format
        row += 1
        ttk.Label(main_frame, text="Output Format:").grid(
            row=row, column=0, sticky=tk.W, padx=(10, 0), pady=(10, 0)
        )

        self.format_var = tk.StringVar(value="csv")
        format_frame = ttk.Frame(main_frame)
        format_frame.grid(row=row, column=1, columnspan=2, 
                         sticky=tk.W, pady=(10, 0))

        ttk.Radiobutton(format_frame, text="CSV", variable=self.format_var, 
                       value="csv").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="JSON", variable=self.format_var, 
                       value="json").pack(side=tk.LEFT, padx=5)

        # ========== RUN BUTTON ==========
        row += 1
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).grid(
            row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=15
        )

        row += 1
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=3, pady=10)

        self.run_btn = ttk.Button(button_frame, text="▶ Run Aggregation", 
                                  command=self.run_aggregation, 
                                  style="Accent.TButton")
        self.run_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(button_frame, text="✖ Cancel", 
                                     command=self.cancel_run, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        # ========== PROGRESS SECTION ==========
        row += 1
        ttk.Label(main_frame, text="Progress:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, pady=(10, 5)
        )

        row += 1
        self.progress_label = ttk.Label(main_frame, text="Ready", foreground="gray")
        self.progress_label.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=(10, 0))

        row += 1
        self.progress = ttk.Progressbar(main_frame, mode='determinate', maximum=100)
        self.progress.grid(row=row, column=0, columnspan=3, 
                          sticky=(tk.W, tk.E), pady=(5, 10))

        # ========== LOG OUTPUT ==========
        row += 1
        ttk.Label(main_frame, text="Log Output:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        self.log_text = scrolledtext.ScrolledText(
            main_frame, height=12, state=tk.DISABLED,
            wrap=tk.WORD, font=("Courier", 9)
        )
        self.log_text.grid(row=row, column=0, columnspan=3, 
                          sticky=(tk.W, tk.E, tk.N, tk.S))

        main_frame.rowconfigure(row, weight=1)

        # Configure tags for colored log output
        self.log_text.tag_config("INFO", foreground="blue")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("SUCCESS", foreground="green")
        self.log_text.tag_config("PROGRESS", foreground="purple")

        # Initial welcome message
        self.log("Welcome to Multi-Window Traffic Aggregator", "INFO")
        self.log("", "INFO")
        self.log("📁 FOLDER MODE (default):", "INFO")
        self.log("   Select your attack_datasets folder and it will", "INFO")
        self.log("   automatically process ALL variations!", "INFO")
        self.log("", "INFO")
        self.log("📄 SINGLE FILE MODE:", "INFO")
        self.log("   Process one CSV file at a time\n", "INFO")

        # Apply initial mode
        self.toggle_mode()

    def toggle_mode(self):
        """Toggle between folder and single file mode"""
        if self.mode_var.get() == "folder":
            # Show folder frame, hide file frame
            self.folder_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E))
            self.file_frame.grid_forget()
            # Hide manual label, show auto-label info
            self.label_combo.grid_forget()
            self.auto_label_info.grid(row=0, column=1, sticky=tk.W)
        else:
            # Show file frame, hide folder frame
            self.file_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E))
            self.file_frame.columnconfigure(1, weight=1)
            self.folder_frame.grid_forget()
            # Show manual label, hide auto-label info
            self.auto_label_info.grid_forget()
            self.label_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))

    def browse_folder(self):
        """Browse for dataset folder"""
        folder = filedialog.askdirectory(
            title="Select Attack Datasets Folder"
        )

        if folder:
            self.input_folder = folder
            folder_path = Path(folder)
            self.folder_label.config(
                text=folder_path.name, 
                foreground="black"
            )
            
            # Count variation subfolders
            variations = [d for d in folder_path.iterdir() if d.is_dir() and not d.name.startswith(".")]
            self.folder_info_label.config(
                text=f"Found {len(variations)} variation folders to process"
            )
            self.log(f"Selected folder: {folder_path.name}", "INFO")
            self.log(f"  → {len(variations)} variations will be processed automatically", "SUCCESS")

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
            self.input_label.config(
                text=Path(filename).name, 
                foreground="black"
            )
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
        self.progress_label.config(
            text=f"Processing {current}/{total}: {folder_name}",
            foreground="purple"
        )
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
            self.log("Output save cancelled by user\n", "INFO")
            return

        self.output_file = output_file

        # Disable controls
        self.is_running = True
        self.run_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.folder_btn.config(state=tk.DISABLED)
        if hasattr(self, 'input_btn'):
            self.input_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0

        # Clear log
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

        # Run in thread
        thread = threading.Thread(target=self._run_aggregation_thread, daemon=True)
        thread.start()

    def _run_aggregation_thread(self):
        """Thread worker for aggregation"""
        try:
            window_sizes = self.get_window_sizes()

            self.log(f"Starting aggregation...", "INFO")
            self.log(f"Window sizes: {window_sizes} seconds", "INFO")
            self.log(f"Output format: {self.format_var.get().upper()}\n", "INFO")

            # Create aggregator
            agg = MultiWindowAggregator(window_sizes=window_sizes)

            if self.mode_var.get() == "folder":
                # FOLDER MODE: Process all variations
                self.log(f"📁 FOLDER MODE: {Path(self.input_folder).name}", "INFO")
                self.log("Processing all variations automatically...\n", "INFO")

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
                self.log(f"Label: {label or 'None'}\n", "INFO")

                self.progress.config(mode='indeterminate')
                self.progress.start(10)
                
                result = agg.process_file(self.input_file, label=label)

            if result.empty:
                self.log("ERROR: No data generated! Check input.", "ERROR")
                self.finish_run(success=False)
                return

            self.log(f"\n✓ Generated {len(result)} total records", "SUCCESS")

            # Show distribution
            self.log("\nRecords per window size:", "INFO")
            for ws, count in result.groupby('window_size').size().items():
                self.log(f"  {ws}s: {count} records", "INFO")

            if self.mode_var.get() == "folder":
                self.log("\nRecords per attack type:", "INFO")
                for label, count in result.groupby('label').size().items():
                    self.log(f"  {label}: {count} records", "INFO")

            # Save results
            self.log(f"\nSaving to {Path(self.output_file).name}...", "INFO")
            agg.save_results(result, self.output_file, fmt=self.format_var.get())

            self.log(f"\n✓ SUCCESS! Saved to:", "SUCCESS")
            self.log(f"  {self.output_file}", "SUCCESS")
            self.log(f"\nFeatures: {len(result.columns)} columns", "INFO")
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
            self.log(f"\n{error_msg}", "ERROR")
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
            self.log("\nCancelled by user", "ERROR")
            self.finish_run(success=False)

    def finish_run(self, success=True):
        """Re-enable controls after run completes"""
        self.is_running = False
        self.progress.stop()
        self.progress.config(mode='determinate')
        if success:
            self.progress['value'] = 100
            self.progress_label.config(text="Complete!", foreground="green")
        else:
            self.progress['value'] = 0
            self.progress_label.config(text="Failed", foreground="red")
        self.run_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.folder_btn.config(state=tk.NORMAL)
        if hasattr(self, 'input_btn'):
            self.input_btn.config(state=tk.NORMAL)


def main():
    """Launch the GUI"""
    root = tk.Tk()

    # Try to apply modern theme
    try:
        style = ttk.Style()
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
    except:
        pass

    app = AggregatorGUI(root)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()


if __name__ == "__main__":
    main()
