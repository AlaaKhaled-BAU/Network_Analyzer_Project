"""
Attack Runner GUI - Easy interface for launching attacks
With Manual Configuration Mode and Presets!

THEMED VERSION: Dark Red theme (Red Team concept)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import os
import sys
import json
import time
from datetime import datetime

# Theme Colors (Red Team - Dark Red theme)
BG_COLOR = "#1a1a1a"
CARD_BG = "#2d2020"
ACCENT_COLOR = "#cc2222"
ACCENT_HOVER = "#aa1111"
SUCCESS_COLOR = "#66bb6a"
ERROR_COLOR = "#cc4444"
WARNING_COLOR = "#dd9933"
TEXT_COLOR = "#e8e8e8"
MUTED_COLOR = "#888888"


class CheckboxTreeview(ttk.Treeview):
    """Treeview with checkbox functionality"""
    
    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.checked = set()  # Set of checked item IDs
        self.bind('<Button-1>', self.on_click)
    
    def on_click(self, event):
        """Handle click to toggle checkbox"""
        region = self.identify_region(event.x, event.y)
        if region == 'tree':  # Clicked on the tree column (icon area)
            item = self.identify_row(event.y)
            if item:
                self.toggle_check(item)
    
    def toggle_check(self, item):
        """Toggle checkbox for an item"""
        tags = self.item(item, 'tags')
        if 'parent' in tags:
            # It's a parent - toggle all children
            children = self.get_children(item)
            if item in self.checked:
                # Uncheck all children
                self.checked.discard(item)
                for child in children:
                    self.checked.discard(child)
                    self.update_display(child)
            else:
                # Check all children
                self.checked.add(item)
                for child in children:
                    self.checked.add(child)
                    self.update_display(child)
            self.update_display(item)
        else:
            # It's a child variation
            if item in self.checked:
                self.checked.discard(item)
            else:
                self.checked.add(item)
            self.update_display(item)
            
            # Update parent state
            parent = self.parent(item)
            if parent:
                self.update_parent_state(parent)
        
        # Fire selection change event
        self.event_generate('<<CheckChanged>>')
    
    def update_parent_state(self, parent):
        """Update parent checkbox based on children"""
        children = self.get_children(parent)
        checked_count = sum(1 for c in children if c in self.checked)
        
        if checked_count == 0:
            self.checked.discard(parent)
        elif checked_count == len(children):
            self.checked.add(parent)
        else:
            self.checked.discard(parent)  # Partial - not fully checked
        
        self.update_display(parent)
    
    def update_display(self, item):
        """Update the checkbox display for an item"""
        tags = list(self.item(item, 'tags'))
        base_tags = [t for t in tags if t not in ('checked', 'unchecked', 'partial')]
        
        if item in self.checked:
            base_tags.append('checked')
        else:
            base_tags.append('unchecked')
        
        self.item(item, tags=base_tags)
        
        # Update the text prefix
        current_text = self.item(item, 'text')
        # Remove any existing prefixes
        if current_text.startswith(('☑ 📁 ', '☐ 📁 ', '☑ ', '☐ ', '📁 ')):
            if '📁' in current_text[:5]:
                current_text = current_text.split('📁 ', 1)[-1]
            else:
                current_text = current_text[2:]
        
        if 'parent' in base_tags:
            # Parent folders get checkbox + folder icon
            if item in self.checked:
                prefix = '☑ 📁 '
            else:
                prefix = '☐ 📁 '
        elif item in self.checked:
            prefix = '☑ '
        else:
            prefix = '☐ '
        
        self.item(item, text=prefix + current_text)
    
    def get_checked_items(self):
        """Get all checked items that are not parents"""
        return [item for item in self.checked if 'parent' not in self.item(item, 'tags')]
    
    def check_all(self):
        """Check all items"""
        for parent in self.get_children():
            self.checked.add(parent)
            self.update_display(parent)
            for child in self.get_children(parent):
                self.checked.add(child)
                self.update_display(child)
        self.event_generate('<<CheckChanged>>')
    
    def uncheck_all(self):
        """Uncheck all items"""
        self.checked.clear()
        for parent in self.get_children():
            self.update_display(parent)
            for child in self.get_children(parent):
                self.update_display(child)
        self.event_generate('<<CheckChanged>>')


class AttackRunnerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Attack Runner Pro")
        
        # Position window (left half by default)
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = screen_width // 2
        window_height = screen_height - 80
        x_position = 0
        y_position = 0
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        self.root.minsize(900, 750)
        
        # Apply dark theme
        self.root.configure(bg=BG_COLOR)
        
        self.is_running = False
        self.config = self.load_config()
        self.interfaces = []
        self.variation_map = {}  # item_id -> (attack_type, index, variation)
        self.manual_widgets = {} # Stores widgets for manual config
        
        self.setup_styles()
        self.setup_ui()
        self.load_interfaces()
        self.populate_attacks()
        self.update_time_estimate()
        
        # Trigger initial manual fields update
        if hasattr(self, 'manual_type_combo'):
            self.update_manual_fields()
    
    def setup_styles(self):
        """Configure ttk styles for red team theme"""
        style = ttk.Style(self.root)
        style.theme_use("clam")
        
        # Frame styles
        style.configure("TFrame", background=BG_COLOR)
        style.configure("Card.TFrame", background=CARD_BG)
        style.configure("Inner.TFrame", background=CARD_BG)
        
        # Label styles
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground=ACCENT_COLOR, background=BG_COLOR)
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"), background=BG_COLOR)
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=CARD_BG, foreground=MUTED_COLOR, font=("Segoe UI", 8))
        
        # LabelFrame styles  
        style.configure("Card.TLabelframe", background=CARD_BG, relief="flat", borderwidth=2)
        style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground=ACCENT_COLOR, background=CARD_BG)
        
        # Notebook styles
        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background="#3d3030", foreground=TEXT_COLOR, padding=[12, 4], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", ACCENT_COLOR)], foreground=[("selected", "#ffffff")])
        
        # Button styles
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), background=ACCENT_COLOR, foreground="#ffffff", borderwidth=0, padding=[12, 8])
        style.map("Accent.TButton", background=[("active", ACCENT_HOVER)])
        
        style.configure("Stop.TButton", font=("Segoe UI", 11, "bold"), background="#cc3333", foreground="#ffffff", borderwidth=0, padding=[14, 8])
        style.map("Stop.TButton", background=[("active", "#aa2222")])
        
        style.configure("Small.TButton", font=("Segoe UI", 9), background=CARD_BG, foreground=TEXT_COLOR, borderwidth=1, padding=[8, 4])
        style.map("Small.TButton", background=[("active", "#3d3030")])
        
        # Entry and Combobox styles - ensure same dark background
        style.configure("TEntry", fieldbackground="#2d2020", foreground=TEXT_COLOR, borderwidth=1, insertcolor=TEXT_COLOR)
        style.configure("TCombobox", fieldbackground="#2d2020", foreground=TEXT_COLOR, borderwidth=1, selectbackground=ACCENT_COLOR, selectforeground="#ffffff")
        style.map("TCombobox", fieldbackground=[("readonly", "#2d2020")], selectbackground=[("readonly", ACCENT_COLOR)])
        
        # Treeview styles
        style.configure("Treeview", 
                       background=CARD_BG, 
                       foreground=TEXT_COLOR, 
                       fieldbackground=CARD_BG,
                       font=("Segoe UI", 9))
        style.configure("Treeview.Heading", 
                       background=ACCENT_COLOR, 
                       foreground="#ffffff", 
                       font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT_COLOR)])
        
        # Progressbar styles
        style.configure("red.Horizontal.TProgressbar", 
                       background=ACCENT_COLOR, 
                       troughcolor=CARD_BG)
    
    def load_config(self):
        """Load attack configuration"""
        try:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack_config.json')
            if not os.path.exists(config_path):
                config_path = 'attack_config.json'
            
            print(f"Loading config from: {os.path.abspath(config_path)}")
            
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    attacks = config.get('attacks', {})
                    total_vars = sum(len(a.get('variations', [])) for a in attacks.values())
                    print(f"Loaded {len(attacks)} attacks with {total_vars} total variations")
                    
                    if attacks:
                        return config
        except Exception as e:
            print(f"Error loading config: {e}")
            import traceback
            traceback.print_exc()
        
        # Fallback defaults
        return {
            'capture_duration': 180,
            'cooldown_period': 10,
            'attacks': {
                'syn_flood': {'variations': [{'port': 80, 'description': 'HTTP Default'}]}
            }
        }
    
    def setup_ui(self):
        # ==========================================
        # HEADER
        # ==========================================
        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill="x")
        
        # Title with crossed swords emoji
        ttk.Label(header, text="⚔️ Attack Runner", style="Header.TLabel").pack(side="left")
        
        # Status indicator
        self.status_label = ttk.Label(header, text="🟢 Ready", style="Status.TLabel", foreground=SUCCESS_COLOR)
        self.status_label.pack(side="left", padx=20)
        
        # Stop button
        self.stop_btn = ttk.Button(header, text="🛑 STOP", command=self.stop_attacks, style="Stop.TButton", state=tk.DISABLED)
        self.stop_btn.pack(side="right", padx=8)
        
        # ==========================================
        # MAIN CONTENT (Two columns)
        # ==========================================
        content = ttk.Frame(self.root, padding=16)
        content.pack(fill="both", expand=True)
        
        # LEFT COLUMN - Configuration
        left = ttk.Frame(content)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        
        # Network Configuration Card (Global)
        net_card = ttk.LabelFrame(left, text="🌐 Network Configuration", style="Card.TLabelframe", padding=12)
        net_card.pack(fill="x", pady=(0, 10))
        
        net_grid = ttk.Frame(net_card, style="Card.TFrame")
        net_grid.pack(fill="x")
        
        # Interface
        ttk.Label(net_grid, text="Interface:", style="Card.TLabel", foreground="#ffffff").grid(row=0, column=0, sticky="w", pady=4)
        iface_frame = ttk.Frame(net_grid, style="Card.TFrame")
        iface_frame.grid(row=0, column=1, sticky="w", pady=4, padx=(8, 0))
        self.interface_combo = ttk.Combobox(iface_frame, width=35, state='readonly')
        self.interface_combo.pack(side="left")
        ttk.Button(iface_frame, text="↻", width=3, command=self.load_interfaces, style="Small.TButton").pack(side="left", padx=(4, 0))
        
        # Target IP
        ttk.Label(net_grid, text="Target IP:", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        self.target_ip = ttk.Entry(net_grid, width=25, font=("Consolas", 10))
        self.target_ip.grid(row=1, column=1, sticky="w", pady=4, padx=(8, 0))
        self.target_ip.insert(0, "26.0.0.0")
        
        # Target MAC
        ttk.Label(net_grid, text="Target MAC:", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        mac_frame = ttk.Frame(net_grid, style="Card.TFrame")
        mac_frame.grid(row=2, column=1, sticky="w", pady=4, padx=(8, 0))
        self.target_mac = ttk.Entry(mac_frame, width=18, font=("Consolas", 10))
        self.target_mac.pack(side="left")
        self.target_mac.insert(0, "ff:ff:ff:ff:ff:ff")
        ttk.Label(mac_frame, text="(ARP spoof)", style="Muted.TLabel").pack(side="left", padx=(6, 0))
        
        # Notebook for Presets vs Manual
        self.notebook = ttk.Notebook(left)
        self.notebook.pack(fill="both", expand=True, pady=(0, 10))
        
        self.tab_presets = ttk.Frame(self.notebook, style="Card.TFrame")
        self.tab_manual = ttk.Frame(self.notebook, style="Card.TFrame")
        
        self.notebook.add(self.tab_presets, text="📂 Presets")
        self.notebook.add(self.tab_manual, text="⚙️ Manual Mode")
        
        # --- PRESETS TAB ---
        self.setup_presets_tab()
        
        # --- MANUAL TAB ---
        self.setup_manual_tab()
        
        # RIGHT COLUMN - Status & Log
        right = ttk.Frame(content)
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))
        
        # Time Estimate Card
        self.time_card = ttk.LabelFrame(right, text="⏱ Time Estimate (Presets)", style="Card.TLabelframe", padding=12)
        self.time_card.pack(fill="x", pady=(0, 10))
        
        time_inner = ttk.Frame(self.time_card, style="Card.TFrame")
        time_inner.pack(fill="x")
        
        self.time_label = ttk.Label(time_inner, text="Selected: 0 variations", style="Card.TLabel", font=("Segoe UI", 11))
        self.time_label.pack(side="left")
        
        self.estimate_label = ttk.Label(time_inner, text="≈ 0 min 0 sec", style="Card.TLabel", font=("Segoe UI", 11, "bold"), foreground=ACCENT_COLOR)
        self.estimate_label.pack(side="right")
        
        # Status Card
        status_card = ttk.LabelFrame(right, text="📊 Progress", style="Card.TLabelframe", padding=12)
        status_card.pack(fill="x", pady=(0, 10))
        
        self.progress_label = ttk.Label(status_card, text="Ready to attack", style="Card.TLabel")
        self.progress_label.pack(anchor="w")
        
        self.progress = ttk.Progressbar(status_card, length=300, mode='determinate', style="red.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, pady=(8, 0))
        
        # Start Button
        self.start_btn = ttk.Button(right, text="▶ LAUNCH ATTACKS", command=self.start_attacks, style="Accent.TButton")
        self.start_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Activity Log Card
        log_card = ttk.LabelFrame(right, text="📋 Activity Log", style="Card.TLabelframe", padding=12)
        log_card.pack(fill="both", expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            log_card, width=40, height=15, state=tk.DISABLED, wrap=tk.WORD,
            background=BG_COLOR, foreground=TEXT_COLOR, font=("Consolas", 9), insertbackground=TEXT_COLOR
        )
        self.log_text.pack(fill="both", expand=True)
        
        # Configure log tags
        self.log_text.tag_config("info", foreground=TEXT_COLOR)
        self.log_text.tag_config("success", foreground=SUCCESS_COLOR)
        self.log_text.tag_config("error", foreground=ERROR_COLOR)
        self.log_text.tag_config("warning", foreground=WARNING_COLOR)
        
        # ==========================================
        # FOOTER
        # ==========================================
        footer = ttk.Frame(self.root, padding=(16, 10))
        footer.pack(fill="x")
        ttk.Label(footer, text="⚠️ Use only in isolated lab environments", foreground=WARNING_COLOR).pack(side="left")
        ttk.Button(footer, text="🗑", command=self.clear_log, width=3, style="Small.TButton").pack(side="right", padx=4)
        
        self.log("⚔️ Attack Runner loaded", "success")
        self.log("⚠️ Run as Administrator for best results", "warning")

    def setup_presets_tab(self):
        """Setup the presets treeview tab"""
        # Duration for presets (Global Override)
        dur_frame = ttk.Frame(self.tab_presets, style="Card.TFrame", padding=(10, 5))
        dur_frame.pack(fill="x")
        ttk.Label(dur_frame, text="Global Override Duration (s):", style="Card.TLabel").pack(side="left")
        
        self.duration_var = tk.StringVar(value=str(self.config.get('capture_duration', 180)))
        self.duration_entry = ttk.Entry(dur_frame, width=10, textvariable=self.duration_var, font=("Consolas", 10))
        self.duration_entry.pack(side="left", padx=5)
        self.duration_var.trace('w', lambda *args: self.update_time_estimate())
        
        # Buttons Frame (Placed at top for visibility)
        btn_row = ttk.Frame(self.tab_presets, style="Card.TFrame", padding=(10, 5))
        btn_row.pack(fill=tk.X)
        
        # Treeview Frame
        tree_frame = ttk.Frame(self.tab_presets, style="Card.TFrame", padding=10)
        tree_frame.pack(fill="both", expand=True)
        
        self.tree = CheckboxTreeview(tree_frame, columns=('description', 'params'), 
                                      show='tree headings', selectmode='none')
        self.tree.heading('#0', text='Attack / Variation')
        self.tree.heading('description', text='Description')
        self.tree.heading('params', text='Parameters')
        self.tree.column('#0', width=180)
        self.tree.column('description', width=150)
        self.tree.column('params', width=200)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.tree.bind('<<CheckChanged>>', lambda e: self.update_time_estimate())
        
        # Now add buttons interacting with self.tree
        ttk.Button(btn_row, text="✓ Select All", command=self.tree.check_all, style="Small.TButton", width=10).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="✗ Select None", command=self.tree.uncheck_all, style="Small.TButton", width=11).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="▼ Expand All", command=self.expand_all, style="Small.TButton", width=11).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="▲ Collapse All", command=self.collapse_all, style="Small.TButton", width=11).pack(side=tk.LEFT, padx=4)

    def setup_manual_tab(self):
        """Setup the manual configuration tab"""
        frame = ttk.Frame(self.tab_manual, style="Card.TFrame", padding=20)
        frame.pack(fill="both", expand=True)
        
        # Attack Type Selection
        ttk.Label(frame, text="Attack Type:", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=10)
        
        attack_types = [
            "syn_flood", "udp_flood", "icmp_flood", 
            "port_scan", "dns_tunnel", "arp_spoof",
            "ssh_brute_force", "slowloris", 
            "dhcp_starvation", "tcp_rst", "icmp_redirect",
            "cam_overflow", "smurf", "land"
        ]
        
        self.manual_type_var = tk.StringVar()
        self.manual_type_combo = ttk.Combobox(frame, textvariable=self.manual_type_var, values=attack_types, state="readonly", width=30)
        self.manual_type_combo.grid(row=0, column=1, sticky="w", pady=10, padx=10)
        self.manual_type_combo.current(0)
        self.manual_type_combo.bind("<<ComboboxSelected>>", self.update_manual_fields)
        
        # Dynamic Fields Container
        self.manual_fields_frame = ttk.Frame(frame, style="Card.TFrame")
        self.manual_fields_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=10)
        
    def update_manual_fields(self, event=None):
        """Update manual fields based on selected attack type"""
        # Clear existing fields
        for widget in self.manual_fields_frame.winfo_children():
            widget.destroy()
        
        self.manual_widgets.clear()
        attack_type = self.manual_type_var.get()
        
        # Common Rows Helper
        row = 0
        def add_field(label, default, key):
            ttk.Label(self.manual_fields_frame, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=5)
            entry = ttk.Entry(self.manual_fields_frame, width=25)
            entry.insert(0, str(default))
            entry.grid(row=row, column=1, sticky="w", pady=5, padx=10)
            self.manual_widgets[key] = entry
        
        # Common fields for almost all attacks
        add_field("Duration (s):", "30", "duration")
        row += 1
        
        if attack_type in ["syn_flood", "udp_flood", "icmp_flood", "tcp_rst", "land", "slowloris", "ssh_brute_force", "dns_tunnel", "cam_overflow", "smurf", "dhcp_starvation", "icmp_redirect", "arp_spoof"]:
             if attack_type not in ["cam_overflow", "dhcp_starvation", "smurf", "icmp_redirect", "arp_spoof"]:
                 add_field("Target Port:", "80", "port")
                 row += 1
        
        if attack_type in ["syn_flood", "udp_flood", "icmp_flood", "tcp_rst", "cam_overflow", "smurf", "dhcp_starvation", "arp_spoof", "icmp_redirect", "land"]:
            add_field("Intensity (packets/loop):", "10", "intensity")
            row += 1
            add_field("Delay (s):", "0.01", "delay")
            row += 1
        
        # Specific fields
        if attack_type == "port_scan":
            add_field("Ports (range/list):", "1-1024", "ports")
            row += 1
            add_field("Delay (s):", "0.1", "delay")
            row += 1
            
        elif attack_type == "dns_tunnel":
            add_field("DNS Server:", "8.8.8.8", "dns_server")
            row += 1
            add_field("Queries/sec (QPS):", "5", "qps")
            row += 1
            
        elif attack_type == "slowloris":
            add_field("Connections:", "100", "connections")
            row += 1
            
        elif attack_type == "icmp_redirect":
            add_field("Gateway IP (Fake):", "10.0.0.1", "gateway_ip")
            row += 1
            
        elif attack_type == "smurf":
            add_field("Broadcast IP:", "192.168.1.255", "broadcast_ip")
            row += 1
            
        elif attack_type == "arp_spoof":
            add_field("Gateway IP (Real):", "192.168.1.1", "gateway_ip")
            row += 1
            
        elif attack_type == "ssh_brute_force":
             add_field("Users (comma sep):", "admin,root", "users")
             row += 1
             add_field("Passwords (comma sep):", "password,123456", "passwords")
             row += 1
             add_field("Delay (s):", "0.5", "delay")
             row += 1

    def get_manual_variation(self):
        """Construct variation dict from manual widgets"""
        var = {}
        for key, widget in self.manual_widgets.items():
            val = widget.get().strip()
            # Convert numbers
            try:
                if '.' in val:
                    val = float(val)
                else:
                    val = int(val)
            except:
                pass # keep as string
            
            # Convert lists
            if key in ['users', 'passwords']:
                val = [x.strip() for x in str(val).split(',')]
            
            var[key] = val
        
        # Add description
        var['description'] = "Manual Config"
        return var

    # ... [Keep existing helper methods like load_interfaces, log, clear_log, etc.] ...
    # I will replicate populate_attacks, expand_all, collapse_all, etc.

    def clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
    
    def populate_attacks(self):
        self.tree.delete(*self.tree.get_children())
        self.variation_map.clear()
        for attack_type, attack_cfg in self.config.get('attacks', {}).items():
            variations = attack_cfg.get('variations', [])
            parent = self.tree.insert('', 'end', text=f'📁 {attack_type}', values=(f'{len(variations)} variations', ''), open=True, tags=('parent',))
            for i, var in enumerate(variations):
                desc = var.get('description', f'Variation {i+1}')
                params = [f"{k}={v}" for k, v in var.items() if k != 'description']
                params_str = ', '.join(params[:4])
                item_id = self.tree.insert(parent, 'end', text=f'☐ {desc}', values=(desc, params_str), tags=('variation',))
                self.variation_map[item_id] = (attack_type, i, var)
    
    def get_selected_variations(self):
        selected = []
        for item_id in self.tree.get_checked_items():
            if item_id in self.variation_map:
                selected.append(self.variation_map[item_id])
        return selected
    
    def update_time_estimate(self):
        try: global_duration = int(self.duration_var.get())
        except: global_duration = 180
        cooldown = self.config.get('cooldown_period', 10)
        selected = self.get_selected_variations()
        count = len(selected)
        if count == 0: total_seconds = 0
        else:
            total_seconds = sum(var[2].get('duration', global_duration) for var in selected)
            total_seconds += (count - 1) * cooldown
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        self.time_label.config(text=f"Selected: {count} variations")
        self.estimate_label.config(text=f"≈ {minutes} min {seconds} sec")
    
    def expand_all(self):
        for item in self.tree.get_children(): self.tree.item(item, open=True)
    def collapse_all(self):
        for item in self.tree.get_children(): self.tree.item(item, open=False)
    
    def load_interfaces(self):
        try:
            from scapy.all import IFACES
            self.interfaces = []
            for raw_name, iface in IFACES.items():
                try:
                    if not hasattr(iface, 'ip') or not iface.ip or iface.ip == '0.0.0.0': continue
                    display = f"{getattr(iface, 'name', raw_name) or raw_name} ({iface.ip})"
                    self.interfaces.append({'raw': raw_name, 'display': display, 'ip': iface.ip, 'friendly': display})
                except: continue
            self.interface_combo['values'] = [i['display'] for i in self.interfaces]
            if self.interfaces: self.interface_combo.current(0)
        except Exception as e:
            print(f"Error loading interfaces: {e}")
            self.interface_combo['values'] = ['Default Interface']
            self.interface_combo.current(0)
            
    def log(self, message, level="info"):
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def validate_inputs(self):
        ip = self.target_ip.get().strip()
        try:
            parts = ip.split('.')
            if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts): raise ValueError
        except:
            messagebox.showerror("Error", "Invalid Target IP")
            return False
            
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0: # Presets
            if not self.get_selected_variations():
                messagebox.showerror("Error", "Select at least one variation (or switch to Manual Mode)")
                return False
        return True

    def start_attacks(self):
        if not self.validate_inputs(): return
        
        idx = self.interface_combo.current()
        iface = self.interfaces[idx]['raw'] if idx >= 0 and idx < len(self.interfaces) else None
        target = self.target_ip.get().strip()
        
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 0: # Presets
            selected = self.get_selected_variations()
            try: duration = int(self.duration_var.get())
            except: duration = 180
        else: # Manual
            attack_type = self.manual_type_var.get()
            var = self.get_manual_variation()
            selected = [(attack_type, 0, var)]
            duration = var.get('duration', 30)
        
        self.log(f"🚀 Launching {len(selected)} attacks on {target}", "success")
        self.is_running = True
        self.status_label.config(text="🔴 ATTACKING", foreground=ERROR_COLOR)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        target_mac = self.target_mac.get().strip() or "ff:ff:ff:ff:ff:ff"
        
        threading.Thread(target=self.run_attacks, args=(target, iface, selected, duration, target_mac), daemon=True).start()

    def run_attacks(self, target, iface, selected_variations, duration, target_mac="ff:ff:ff:ff:ff:ff"):
        try:
            import attack_core
            from scapy.all import conf
            if iface: conf.iface = iface
            
            cooldown = self.config.get('cooldown_period', 10)
            total = len(selected_variations)
            
            for i, (attack_type, var_idx, variation) in enumerate(selected_variations):
                if not self.is_running: break
                
                desc = variation.get('description', f'manual')
                label = f"{attack_type}"
                var_duration = variation.get('duration', duration)
                
                self.root.after(0, lambda l=f"{attack_type}: {desc}": self.log(f"⚡ Running: {l}", "warning"))
                self.root.after(0, lambda l=f"{attack_type}: {desc}": self.progress_label.config(text=l))
                
                try:
                    # Generic getter with default fallback
                    def val(key, default): return variation.get(key, default)
                    
                    if attack_type == 'syn_flood':
                        attack_core.syn_flood_impl(target, val('port', 80), val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'udp_flood':
                        attack_core.udp_flood_impl(target, val('port', 53), val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'icmp_flood':
                        attack_core.icmp_flood_impl(target, val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'port_scan':
                        attack_core.port_scan_impl(target, val('ports', '1-1024'), val('delay', 0.1), var_duration, label)
                    elif attack_type == 'dns_tunnel':
                        attack_core.dns_tunnel_impl(target, val('dns_server', '8.8.8.8'), val('qps', 5), var_duration, label, val('mirror_to', None), val('mirror_mac', None), val('preserve_dst', False))
                    elif attack_type == 'arp_spoof':
                        attack_core.arp_spoof_impl(target, val('fake_mac', 'aa:bb:cc:dd:ee:ff'), val('intensity', 1), var_duration, label, target_mac, val('fake_mac2', None), val('mac_switch_delay', 0), val('gateway_ip', None))
                    elif attack_type == 'ssh_brute_force':
                        attack_core.ssh_brute_force_impl(target, val('port', 22), val('users', ['admin']), val('passwords', ['password']), val('delay', 0.5), var_duration, label)
                    elif attack_type == 'slowloris':
                        attack_core.slowloris_impl(target, val('port', 80), val('connections', 100), var_duration, label)
                    # NEW ATTACKS
                    elif attack_type == 'dhcp_starvation':
                        attack_core.dhcp_starvation_impl(target, val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'tcp_rst':
                        attack_core.tcp_rst_impl(target, val('port', 80), val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'icmp_redirect':
                        attack_core.icmp_redirect_impl(target, val('gateway_ip', '10.0.0.1'), val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'cam_overflow':
                        attack_core.cam_overflow_impl(target, val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'smurf':
                        attack_core.smurf_impl(target, val('broadcast_ip', '192.168.1.255'), val('intensity', 10), val('delay', 0.01), var_duration, label)
                    elif attack_type == 'land':
                        attack_core.land_impl(target, val('port', 80), val('intensity', 10), val('delay', 0.01), var_duration, label)
                    
                    self.root.after(0, lambda: self.log(f"✓ Completed", "success"))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.log(f"✗ Error: {e}", "error"))
                
                progress = int(((i + 1) / total) * 100)
                self.root.after(0, lambda p=progress: self.progress.configure(value=p))
                if i < total - 1 and self.is_running and current_tab == 0: # Only sleep cooldown in presets
                    time.sleep(cooldown)
            
            self.root.after(0, self.attacks_completed)
        except Exception as e:
            self.root.after(0, lambda: self.log(f"FATAL: {e}", "error"))
            self.root.after(0, self.attacks_completed)

    def attacks_completed(self):
        self.is_running = False
        self.status_label.config(text="✓ Completed", foreground=SUCCESS_COLOR)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_label.config(text="Done")
        self.log("🏁 All attacks completed!", "success")

    def stop_attacks(self):
        self.is_running = False
        try:
            import attack_core
            attack_core.stop_event.set()
        except: pass
        self.status_label.config(text="⏹ Stopped", foreground=WARNING_COLOR)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("🛑 Stopped by user", "warning")

    def on_closing(self):
        if self.is_running:
            if messagebox.askokcancel("Quit", "Attacks running. Stop and quit?"):
                self.stop_attacks()
                time.sleep(0.5)
                self.root.destroy()
        else: self.root.destroy()

def main():
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showerror("Error", "Administrator privileges required!")
            sys.exit(1)
    root = tk.Tk()
    app = AttackRunnerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == '__main__':
    main()
