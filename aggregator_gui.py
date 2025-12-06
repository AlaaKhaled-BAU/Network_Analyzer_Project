"""
GUI for Multi-Window Network Traffic Aggregator

Simple interface to:
- Select raw packet CSV file
- Configure window sizes and label
- Run aggregation
- Save results to chosen location
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
from pathlib import Path

# Import the aggregator (assuming multi_window_aggregator.py is in same folder)
try:
    from multi_window_aggregator import MultiWindowAggregator
except ImportError:
    messagebox.showerror(
        "Import Error",
        "Cannot find multi_window_aggregator.py\n"
        "Make sure it's in the same folder as this GUI script."
    )
    sys.exit(1)


class AggregatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Aggregator - Multi-Window")
        self.root.geometry("700x600")
        self.root.resizable(True, True)

        self.input_file = None
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

        # ========== INPUT FILE SECTION ==========
        row = 0
        ttk.Label(main_frame, text="Input File (Raw Packets):", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        self.input_label = ttk.Label(main_frame, text="No file selected", 
                                      foreground="gray")
        self.input_label.grid(row=row, column=0, columnspan=2, 
                              sticky=(tk.W, tk.E), padx=(10, 5))

        self.input_btn = ttk.Button(main_frame, text="Browse...", 
                                    command=self.browse_input)
        self.input_btn.grid(row=row, column=2, sticky=tk.E)

        # ========== CONFIGURATION SECTION ==========
        row += 1
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

        # Label input
        row += 1
        ttk.Label(main_frame, text="Traffic Label:").grid(
            row=row, column=0, sticky=tk.W, padx=(10, 0), pady=(10, 0)
        )

        self.label_var = tk.StringVar()
        label_combo = ttk.Combobox(main_frame, textvariable=self.label_var, 
                                   state="normal", width=30)
        label_combo['values'] = (
            'Normal',
            'DDoS',
            'Port Scanning',
            'Brute Force',
            'ARP Poisoning',
            'DNS Tunneling',
            'Slowloris'
        )
        label_combo.grid(row=row, column=1, columnspan=2, 
                        sticky=(tk.W, tk.E), pady=(10, 0))
        label_combo.set('Normal')  # Default

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
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=row, column=0, columnspan=3, 
                          sticky=(tk.W, tk.E), pady=(0, 10))

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

        # Initial welcome message
        self.log("Welcome to Multi-Window Traffic Aggregator", "INFO")
        self.log("1. Select raw packet CSV file", "INFO")
        self.log("2. Configure window sizes and label", "INFO")
        self.log("3. Click 'Run Aggregation'", "INFO")
        self.log("4. Choose where to save the output\n", "INFO")

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

    def run_aggregation(self):
        """Run the aggregation process in a separate thread"""
        # Validation
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
        self.input_btn.config(state=tk.DISABLED)
        self.progress.start(10)

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
            label = self.label_var.get() if self.label_var.get() else None

            self.log(f"Starting aggregation...", "INFO")
            self.log(f"Input: {Path(self.input_file).name}", "INFO")
            self.log(f"Window sizes: {window_sizes} seconds", "INFO")
            self.log(f"Label: {label or 'None'}", "INFO")
            self.log(f"Output format: {self.format_var.get().upper()}\n", "INFO")

            # Create aggregator
            agg = MultiWindowAggregator(window_sizes=window_sizes)

            # Process file
            self.log("Loading raw packets...", "INFO")
            result = agg.process_file(self.input_file, label=label)

            if result.empty:
                self.log("ERROR: No data generated! Check input file.", "ERROR")
                self.finish_run(success=False)
                return

            self.log(f"✓ Generated {len(result)} records", "SUCCESS")

            # Show distribution
            self.log("\nRecords per window size:", "INFO")
            for ws, count in result.groupby('window_size').size().items():
                self.log(f"  {ws}s: {count} records", "INFO")

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
        self.run_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.input_btn.config(state=tk.NORMAL)


def main():
    """Launch the GUI"""
    root = tk.Tk()

    # Try to apply modern theme
    try:
        style = ttk.Style()
        # Use 'clam', 'alt', 'default', or 'classic' theme
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
