"""
Attack Runner GUI - Easy interface for launching attacks
With checkbox selection for variations!
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import os
import sys
import json
import time
from datetime import datetime


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
        if current_text.startswith(('☑ ', '☐ ', '📁 ')):
            current_text = current_text[2:]
        
        if 'parent' in base_tags:
            prefix = '📁 '
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
        self.root.title("Attack Runner - Attacker Machine")
        self.root.geometry("750x800")
        self.root.resizable(True, True)
        
        self.is_running = False
        self.config = self.load_config()
        self.interfaces = []
        self.variation_map = {}  # item_id -> (attack_type, index, variation)
        
        self.setup_ui()
        self.load_interfaces()
        self.populate_attacks()
        self.update_time_estimate()
    
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
                'syn_flood': {'variations': [{'port': 80, 'description': 'HTTP Default'}]},
                'udp_flood': {'variations': [{'port': 53, 'description': 'DNS Default'}]},
                'icmp_flood': {'variations': [{'count': 100, 'description': 'Default'}]},
                'port_scan': {'variations': [{'ports': '1-1024', 'description': 'Default'}]},
                'dns_tunnel': {'variations': [{'dns_server': '8.8.8.8', 'description': 'Google DNS'}]},
                'arp_spoof': {'variations': [{'description': 'Default'}]},
                'ssh_brute_force': {'variations': [{'port': 22, 'description': 'Default'}]},
                'slowloris': {'variations': [{'port': 80, 'description': 'Default'}]}
            }
        }
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(main_frame, text="⚔️ Attack Runner", 
                         font=('Segoe UI', 16, 'bold'))
        title.pack(pady=(0, 15))
        
        # Network Configuration
        net_frame = ttk.LabelFrame(main_frame, text="Network Configuration", padding="10")
        net_frame.pack(fill=tk.X, pady=(0, 10))
        
        row1 = ttk.Frame(net_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Interface:", width=12).pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(row1, width=45, state='readonly')
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        ttk.Button(row1, text="↻", width=3, command=self.load_interfaces).pack(side=tk.LEFT)
        
        row2 = ttk.Frame(net_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Target IP:", width=12).pack(side=tk.LEFT)
        self.target_ip = ttk.Entry(row2, width=47)
        self.target_ip.pack(side=tk.LEFT, padx=5)
        self.target_ip.insert(0, "26.0.0.0")
        
        row3 = ttk.Frame(net_frame)
        row3.pack(fill=tk.X, pady=2)
        ttk.Label(row3, text="Duration (s):", width=12).pack(side=tk.LEFT)
        self.duration_var = tk.StringVar(value=str(self.config.get('capture_duration', 180)))
        self.duration_entry = ttk.Entry(row3, width=10, textvariable=self.duration_var)
        self.duration_entry.pack(side=tk.LEFT, padx=5)
        self.duration_var.trace('w', lambda *args: self.update_time_estimate())
        
        # Target MAC for ARP spoof
        row4 = ttk.Frame(net_frame)
        row4.pack(fill=tk.X, pady=2)
        ttk.Label(row4, text="Target MAC:", width=12).pack(side=tk.LEFT)
        self.target_mac = ttk.Entry(row4, width=20)
        self.target_mac.pack(side=tk.LEFT, padx=5)
        self.target_mac.insert(0, "ff:ff:ff:ff:ff:ff")
        ttk.Label(row4, text="(for ARP spoof - broadcast or target's MAC)", 
                 font=('Segoe UI', 8), foreground='gray').pack(side=tk.LEFT, padx=5)
        
        # Attack Selection
        attack_frame = ttk.LabelFrame(main_frame, text="Select Attack Variations (Click to toggle)", padding="10")
        attack_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        tree_frame = ttk.Frame(attack_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree = CheckboxTreeview(tree_frame, columns=('description', 'params'), 
                                      show='tree headings', selectmode='none')
        self.tree.heading('#0', text='Attack / Variation')
        self.tree.heading('description', text='Description')
        self.tree.heading('params', text='Parameters')
        self.tree.column('#0', width=220)
        self.tree.column('description', width=180)
        self.tree.column('params', width=250)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.tree.bind('<<CheckChanged>>', lambda e: self.update_time_estimate())
        
        btn_row = ttk.Frame(attack_frame)
        btn_row.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_row, text="✓ Select All", command=self.tree.check_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_row, text="✗ Select None", command=self.tree.uncheck_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_row, text="▼ Expand All", command=self.expand_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_row, text="▲ Collapse All", command=self.collapse_all).pack(side=tk.LEFT, padx=5)
        
        # Time Estimate
        time_frame = ttk.LabelFrame(main_frame, text="Time Estimate", padding="10")
        time_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.time_label = ttk.Label(time_frame, text="Selected: 0 variations", 
                                    font=('Segoe UI', 11))
        self.time_label.pack(side=tk.LEFT)
        
        self.estimate_label = ttk.Label(time_frame, text="≈ 0 min 0 sec", 
                                        font=('Segoe UI', 11, 'bold'))
        self.estimate_label.pack(side=tk.RIGHT)
        
        # Status
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame, text="⏹ Ready", 
                                      font=('Segoe UI', 11, 'bold'), foreground='gray')
        self.status_label.pack(side=tk.LEFT)
        
        self.progress_label = ttk.Label(status_frame, text="")
        self.progress_label.pack(side=tk.RIGHT)
        
        self.progress = ttk.Progressbar(status_frame, length=300, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(5, 0))
        
        # Control Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(btn_frame, text="▶ START ATTACKS", command=self.start_attacks)
        self.start_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹ STOP", command=self.stop_attacks, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
        
        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.log_text = tk.Text(log_frame, height=5, font=('Consolas', 9),
                               state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def populate_attacks(self):
        """Populate treeview with attacks and variations"""
        self.tree.delete(*self.tree.get_children())
        self.variation_map.clear()
        
        for attack_type, attack_cfg in self.config.get('attacks', {}).items():
            variations = attack_cfg.get('variations', [])
            
            parent = self.tree.insert('', 'end', text=f'📁 {attack_type}', 
                                       values=(f'{len(variations)} variations', ''),
                                       open=True, tags=('parent',))
            
            for i, var in enumerate(variations):
                desc = var.get('description', f'Variation {i+1}')
                
                params = []
                for k, v in var.items():
                    if k != 'description':
                        params.append(f"{k}={v}")
                params_str = ', '.join(params[:4])
                
                item_id = self.tree.insert(parent, 'end', text=f'☐ {desc}',
                                           values=(desc, params_str),
                                           tags=('variation',))
                self.variation_map[item_id] = (attack_type, i, var)
    
    def get_selected_variations(self):
        """Get list of selected variations"""
        selected = []
        for item_id in self.tree.get_checked_items():
            if item_id in self.variation_map:
                selected.append(self.variation_map[item_id])
        return selected
    
    def update_time_estimate(self):
        try:
            global_duration = int(self.duration_var.get())
        except:
            global_duration = 180
        
        cooldown = self.config.get('cooldown_period', 10)
        selected = self.get_selected_variations()
        count = len(selected)
        
        if count == 0:
            total_seconds = 0
        else:
            # Sum up per-variation durations (fallback to global if not set)
            total_seconds = sum(
                var[2].get('duration', global_duration) for var in selected
            )
            # Add cooldowns between variations
            total_seconds += (count - 1) * cooldown
        
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        
        self.time_label.config(text=f"Selected: {count} variations")
        self.estimate_label.config(text=f"≈ {minutes} min {seconds} sec")
    
    def expand_all(self):
        for item in self.tree.get_children():
            self.tree.item(item, open=True)
    
    def collapse_all(self):
        for item in self.tree.get_children():
            self.tree.item(item, open=False)
    
    def load_interfaces(self):
        """Load network interfaces using Scapy's IFACES (works without psutil)"""
        try:
            from scapy.all import IFACES
            
            self.interfaces = []
            
            # Use Scapy's IFACES - it has all the info we need on Windows
            for raw_name, iface in IFACES.items():
                try:
                    # Skip interfaces without IP or with 0.0.0.0
                    if not hasattr(iface, 'ip') or not iface.ip or iface.ip == '0.0.0.0':
                        continue
                    
                    ip = iface.ip
                    friendly_name = getattr(iface, 'name', raw_name) or raw_name
                    
                    display = f"{friendly_name} ({ip})"
                    self.interfaces.append({
                        'raw': raw_name,  # The NPF device path for scapy
                        'display': display,
                        'ip': ip,
                        'friendly': friendly_name
                    })
                except Exception as e:
                    print(f"Error processing interface {raw_name}: {e}")
                    continue
            
            # Sort interfaces, putting common ones first (Radmin VPN, Ethernet, WiFi)
            def sort_key(iface):
                name_lower = iface['friendly'].lower() if iface.get('friendly') else ''
                if 'radmin' in name_lower:
                    return (0, name_lower)
                elif 'ethernet' in name_lower or 'eth' in name_lower:
                    return (1, name_lower)
                elif 'wi-fi' in name_lower or 'wifi' in name_lower or 'wlan' in name_lower:
                    return (2, name_lower)
                elif 'loopback' in name_lower:
                    return (9, name_lower)  # Put loopback last
                else:
                    return (3, name_lower)
            
            self.interfaces.sort(key=sort_key)
            
            self.interface_combo['values'] = [i['display'] for i in self.interfaces]
            if self.interfaces:
                self.interface_combo.current(0)
                
            # Log found interfaces for debugging
            print(f"Found {len(self.interfaces)} interfaces:")
            for iface in self.interfaces:
                print(f"  - {iface['display']} -> {iface['raw']}")
                
        except Exception as e:
            print(f"Error loading interfaces: {e}")
            import traceback
            traceback.print_exc()
            self.interface_combo['values'] = ['Default Interface']
            self.interface_combo.current(0)
    
    def log(self, message):
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
    
    def validate_inputs(self):
        ip = self.target_ip.get().strip()
        try:
            parts = ip.split('.')
            if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid Target IP")
            return False
        
        if not self.get_selected_variations():
            messagebox.showerror("Error", "Select at least one variation")
            return False
        return True
    
    def start_attacks(self):
        if not self.validate_inputs():
            return
        
        selected = self.get_selected_variations()
        idx = self.interface_combo.current()
        iface = self.interfaces[idx]['raw'] if idx >= 0 and idx < len(self.interfaces) else None
        target = self.target_ip.get().strip()
        
        try:
            duration = int(self.duration_var.get())
        except:
            duration = 180
        
        self.log(f"Starting {len(selected)} variations on {target}")
        
        self.is_running = True
        self.status_label.config(text="🔴 ATTACKING", foreground='red')
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Get target MAC for ARP spoof
        target_mac = self.target_mac.get().strip() or "ff:ff:ff:ff:ff:ff"
        
        threading.Thread(target=self.run_attacks, 
                        args=(target, iface, selected, duration, target_mac), 
                        daemon=True).start()
    
    def run_attacks(self, target, iface, selected_variations, duration, target_mac="ff:ff:ff:ff:ff:ff"):
        try:
            import attack_core
            from scapy.all import conf
            
            if iface:
                conf.iface = iface
            
            cooldown = self.config.get('cooldown_period', 10)
            total = len(selected_variations)
            
            for i, (attack_type, var_idx, variation) in enumerate(selected_variations):
                if not self.is_running:
                    break
                
                desc = variation.get('description', f'var{var_idx+1}')
                label = f"{attack_type}"
                
                # Use per-variation duration if specified, else use global duration
                var_duration = variation.get('duration', duration)
                
                self.root.after(0, lambda l=f"{attack_type}: {desc} ({var_duration}s)": self.log(f"Running: {l}"))
                self.root.after(0, lambda l=f"{attack_type}: {desc}": self.progress_label.config(text=l))
                
                try:
                    attack_funcs = {
                        'syn_flood': lambda: attack_core.syn_flood_impl(target, variation.get('port', 80),
                            variation.get('intensity', 10), variation.get('delay', 0.01), var_duration, label),
                        'udp_flood': lambda: attack_core.udp_flood_impl(target, variation.get('port', 53),
                            variation.get('size', 512), variation.get('delay', 0.001), var_duration, label),
                        'icmp_flood': lambda: attack_core.icmp_flood_impl(target,
                            variation.get('intensity', 50), variation.get('delay', 0.01), var_duration, label),
                        'port_scan': lambda: attack_core.port_scan_impl(target, variation.get('ports', '1-1024'),
                            variation.get('delay', 0.1), var_duration, label),
                        'dns_tunnel': lambda: attack_core.dns_tunnel_impl(target, variation.get('dns_server', '8.8.8.8'),
                            variation.get('qps', 5), var_duration, label, variation.get('mirror_to')),
                        'arp_spoof': lambda: attack_core.arp_spoof_impl(target, variation.get('fake_mac', 'aa:bb:cc:dd:ee:ff'),
                            variation.get('intensity', 1), var_duration, label, target_mac,
                            variation.get('fake_mac2'), variation.get('mac_switch_delay', 0)),
                        'ssh_brute_force': lambda: attack_core.ssh_brute_force_impl(target, variation.get('port', 22),
                            variation.get('users', ['admin']), variation.get('passwords', ['password']),
                            variation.get('delay', 0.5), var_duration, label),
                        'slowloris': lambda: attack_core.slowloris_impl(target, variation.get('port', 80),
                            variation.get('connections', 100), var_duration, label)
                    }
                    
                    if attack_type in attack_funcs:
                        attack_funcs[attack_type]()
                    
                    self.root.after(0, lambda: self.log(f"✓ Completed"))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.log(f"✗ Error: {e}"))
                
                progress = int(((i + 1) / total) * 100)
                self.root.after(0, lambda p=progress: self.progress.configure(value=p))
                
                if i < total - 1 and self.is_running:
                    time.sleep(cooldown)
            
            self.root.after(0, self.attacks_completed)
        except Exception as e:
            self.root.after(0, lambda: self.log(f"FATAL: {e}"))
            self.root.after(0, self.attacks_completed)
    
    def attacks_completed(self):
        self.is_running = False
        self.status_label.config(text="✓ Completed", foreground='green')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_label.config(text="Done")
        self.log("All attacks completed!")
    
    def stop_attacks(self):
        self.is_running = False
        try:
            import attack_core
            attack_core.stop_event.set()
        except:
            pass
        self.status_label.config(text="⏹ Stopped", foreground='orange')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("Stopped by user")
    
    def on_closing(self):
        if self.is_running:
            if messagebox.askokcancel("Quit", "Attacks running. Stop and quit?"):
                self.stop_attacks()
                time.sleep(0.5)
                self.root.destroy()
        else:
            self.root.destroy()


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
