import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import os
import platform
from datetime import datetime

class SnortGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Snort Management GUI")
        self.root.geometry("1200x800")
        
        # Theme variables
        self.dark_mode = False
        self.themes = {
            'dark': {
                'bg': '#2d2d2d',
                'fg': '#ffffff',
                'entry_bg': '#3d3d3d',
                'entry_fg': '#ffffff',
                'text_bg': '#252525',
                'text_fg': '#e0e0e0',
                'button_bg': '#3d3d3d',
                'button_fg': '#ffffff',
                'tree_bg': '#3d3d3d',
                'tree_fg': '#ffffff',
                'tree_heading_bg': '#2d2d2d',
                'tree_heading_fg': '#ffffff',
                'select_bg': '#4d4d4d',
                'select_fg': '#ffffff',
                'label_frame_bg': '#2d2d2d',
                'label_frame_fg': '#ffffff'
            },
            'light': {
                'bg': '#f0f0f0',
                'fg': '#000000',
                'entry_bg': '#ffffff',
                'entry_fg': '#000000',
                'text_bg': '#ffffff',
                'text_fg': '#000000',
                'button_bg': '#e0e0e0',
                'button_fg': '#000000',
                'tree_bg': '#ffffff',
                'tree_fg': '#000000',
                'tree_heading_bg': '#e0e0e0',
                'tree_heading_fg': '#000000',
                'select_bg': '#d0d0d0',
                'select_fg': '#000000',
                'label_frame_bg': '#f0f0f0',
                'label_frame_fg': '#000000'
            }
        }
        
        # Detect OS and set appropriate paths
        self.os_type = platform.system().lower()
        self.set_os_specific_paths()
        
        # Create menu
        self.create_menu()
        
        # Create main frames
        self.create_widgets()
        
        # Apply initial theme
        self.toggle_theme()
        
        # Load initial data
        self.load_snort_status()
        self.load_rules_files()
    
    def set_os_specific_paths(self):
        """Set paths based on operating system"""
        if self.os_type == 'windows':
            # Windows paths
            program_files = os.getenv('ProgramFiles', 'C:\\Program Files')
            self.snort_config_path = os.path.join(program_files, 'Snort', 'etc', 'snort.conf')
            self.snort_rules_path = os.path.join(program_files, 'Snort', 'etc', 'rules')
            self.snort_log_path = os.path.join(program_files, 'Snort', 'log')
            self.snort_bin_path = os.path.join(program_files, 'Snort', 'bin', 'snort.exe')
            self.service_cmd = 'net'
        else:
            # Linux paths
            self.snort_config_path = "/etc/snort/snort.conf"
            self.snort_rules_path = "/etc/snort/rules/"
            self.snort_log_path = "/var/log/snort/"
            self.snort_bin_path = "/usr/sbin/snort"
            self.service_cmd = 'systemctl'
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Dark/Light Mode", command=self.toggle_theme)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def toggle_theme(self):
        """Toggle between dark and light theme"""
        self.dark_mode = not self.dark_mode
        theme = 'dark' if self.dark_mode else 'light'
        
        # Update root window
        self.root.configure(bg=self.themes[theme]['bg'])
        
        # Update all widgets
        self.update_widgets_theme(self.root, theme)
    
    def update_widgets_theme(self, widget, theme):
        """Recursively update all widgets with the selected theme"""
        try:
            if isinstance(widget, (ttk.LabelFrame, ttk.Frame)):
                widget.configure(style=f'{theme}.TLabelframe')
            elif isinstance(widget, (tk.Label, ttk.Label)):
                widget.configure(foreground=self.themes[theme]['fg'], background=self.themes[theme]['bg'])
            elif isinstance(widget, (tk.Entry, ttk.Entry)):
                widget.configure(background=self.themes[theme]['entry_bg'], foreground=self.themes[theme]['entry_fg'])
            elif isinstance(widget, (tk.Button, ttk.Button)):
                widget.configure(background=self.themes[theme]['button_bg'], foreground=self.themes[theme]['button_fg'])
            elif isinstance(widget, (scrolledtext.ScrolledText, tk.Text)):
                widget.configure(background=self.themes[theme]['text_bg'], foreground=self.themes[theme]['text_fg'],
                               insertbackground=self.themes[theme]['fg'])
            elif isinstance(widget, ttk.Treeview):
                widget.configure(style=f'{theme}.Treeview')
        except:
            pass
        
        # Recursively update child widgets
        for child in widget.winfo_children():
            self.update_widgets_theme(child, theme)
    
    def create_widgets(self):
        # Create style for themed widgets
        self.style = ttk.Style()
        self.style.theme_use('clam')  # A theme that works well for both dark and light
        
        # Configure styles for both themes
        for theme in ['dark', 'light']:
            self.style.configure(f'{theme}.TLabelframe', 
                               background=self.themes[theme]['label_frame_bg'],
                               foreground=self.themes[theme]['label_frame_fg'])
            self.style.configure(f'{theme}.TLabelframe.Label', 
                               background=self.themes[theme]['label_frame_bg'],
                               foreground=self.themes[theme]['label_frame_fg'])
            self.style.configure(f'{theme}.Treeview', 
                               background=self.themes[theme]['tree_bg'],
                               foreground=self.themes[theme]['tree_fg'],
                               fieldbackground=self.themes[theme]['tree_bg'])
            self.style.configure(f'{theme}.Treeview.Heading', 
                               background=self.themes[theme]['tree_heading_bg'],
                               foreground=self.themes[theme]['tree_heading_fg'])
            self.style.map(f'{theme}.Treeview', 
                         background=[('selected', self.themes[theme]['select_bg'])],
                         foreground=[('selected', self.themes[theme]['select_fg'])])
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard Tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.create_dashboard_tab()
        
        # Rules Management Tab
        self.rules_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_tab, text="Rules Management")
        self.create_rules_tab()
        
        # Alerts View Tab
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="Alerts")
        self.create_alerts_tab()
        
        # Configuration Tab
        self.config_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.config_tab, text="Configuration")
        self.create_config_tab()
        
        # Log Tab
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_tab, text="Logs")
        self.create_log_tab()
    
    def create_dashboard_tab(self):
        # Status Frame
        status_frame = ttk.LabelFrame(self.dashboard_tab, text="Snort Status")
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Unknown", font=('Helvetica', 12))
        self.status_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.start_button = ttk.Button(status_frame, text="Start Snort", command=self.start_snort)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(status_frame, text="Stop Snort", command=self.stop_snort)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.restart_button = ttk.Button(status_frame, text="Restart Snort", command=self.restart_snort)
        self.restart_button.pack(side=tk.LEFT, padx=5)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(self.dashboard_tab, text="Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD, width=100, height=20)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        refresh_button = ttk.Button(stats_frame, text="Refresh Statistics", command=self.update_statistics)
        refresh_button.pack(pady=5)
        
        # Quick Actions Frame
        actions_frame = ttk.LabelFrame(self.dashboard_tab, text="Quick Actions")
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="View Recent Alerts", command=self.show_recent_alerts).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Test Configuration", command=self.test_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Reload Rules", command=self.reload_rules).pack(side=tk.LEFT, padx=5)
    
    def create_rules_tab(self):
        # Rules Files Frame
        files_frame = ttk.LabelFrame(self.rules_tab, text="Rules Files")
        files_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.rules_files_tree = ttk.Treeview(files_frame, columns=('size', 'modified'), selectmode='browse')
        self.rules_files_tree.heading('#0', text='File Name')
        self.rules_files_tree.heading('size', text='Size')
        self.rules_files_tree.heading('modified', text='Modified')
        self.rules_files_tree.column('size', width=100, anchor='e')
        self.rules_files_tree.column('modified', width=150, anchor='center')
        
        vsb = ttk.Scrollbar(files_frame, orient="vertical", command=self.rules_files_tree.yview)
        hsb = ttk.Scrollbar(files_frame, orient="horizontal", command=self.rules_files_tree.xview)
        self.rules_files_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.rules_files_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        files_frame.grid_columnconfigure(0, weight=1)
        files_frame.grid_rowconfigure(0, weight=1)
        
        # Rules Actions Frame
        rules_actions_frame = ttk.Frame(self.rules_tab)
        rules_actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(rules_actions_frame, text="Add Rule", command=self.add_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(rules_actions_frame, text="Edit Rule", command=self.edit_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(rules_actions_frame, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(rules_actions_frame, text="Import Rules", command=self.import_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(rules_actions_frame, text="Export Rules", command=self.export_rules).pack(side=tk.LEFT, padx=5)
        
        # Rules Content Frame
        content_frame = ttk.LabelFrame(self.rules_tab, text="Rule Content")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.rule_content_text = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, width=100, height=20)
        self.rule_content_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind treeview selection event
        self.rules_files_tree.bind('<<TreeviewSelect>>', self.on_rule_file_select)
    
    def create_alerts_tab(self):
        # Alerts Filter Frame
        filter_frame = ttk.LabelFrame(self.alerts_tab, text="Filter Alerts")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="From:").pack(side=tk.LEFT, padx=5)
        self.alert_from_entry = ttk.Entry(filter_frame, width=12)
        self.alert_from_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="To:").pack(side=tk.LEFT, padx=5)
        self.alert_to_entry = ttk.Entry(filter_frame, width=12)
        self.alert_to_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Priority:").pack(side=tk.LEFT, padx=5)
        self.alert_priority_combobox = ttk.Combobox(filter_frame, values=["All", "1", "2", "3", "4"], width=5)
        self.alert_priority_combobox.pack(side=tk.LEFT, padx=5)
        self.alert_priority_combobox.current(0)
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.filter_alerts).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter).pack(side=tk.LEFT, padx=5)
        
        # Alerts Table Frame
        table_frame = ttk.Frame(self.alerts_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('id', 'timestamp', 'priority', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'message')
        self.alerts_tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        
        # Configure columns
        self.alerts_tree.heading('id', text='ID')
        self.alerts_tree.column('id', width=50, anchor='center')
        
        self.alerts_tree.heading('timestamp', text='Timestamp')
        self.alerts_tree.column('timestamp', width=150)
        
        self.alerts_tree.heading('priority', text='Priority')
        self.alerts_tree.column('priority', width=70, anchor='center')
        
        self.alerts_tree.heading('protocol', text='Protocol')
        self.alerts_tree.column('protocol', width=80, anchor='center')
        
        self.alerts_tree.heading('src_ip', text='Source IP')
        self.alerts_tree.column('src_ip', width=120)
        
        self.alerts_tree.heading('src_port', text='Src Port')
        self.alerts_tree.column('src_port', width=80, anchor='center')
        
        self.alerts_tree.heading('dst_ip', text='Destination IP')
        self.alerts_tree.column('dst_ip', width=120)
        
        self.alerts_tree.heading('dst_port', text='Dst Port')
        self.alerts_tree.column('dst_port', width=80, anchor='center')
        
        self.alerts_tree.heading('message', text='Message')
        self.alerts_tree.column('message', width=300)
        
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.alerts_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.alerts_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        
        # Alert Details Frame
        details_frame = ttk.LabelFrame(self.alerts_tab, text="Alert Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.alert_details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, width=100, height=10)
        self.alert_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind treeview selection event
        self.alerts_tree.bind('<<TreeviewSelect>>', self.on_alert_select)
        
        # Load initial alerts
        self.load_alerts()
    
    def create_config_tab(self):
        # Config Editor Frame
        editor_frame = ttk.LabelFrame(self.config_tab, text="Snort Configuration")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.config_text = scrolledtext.ScrolledText(editor_frame, wrap=tk.WORD, width=100, height=30)
        self.config_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Config Actions Frame
        actions_frame = ttk.Frame(self.config_tab)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="Load Config", command=self.load_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Save Config", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Test Config", command=self.test_config).pack(side=tk.LEFT, padx=5)
        
        # Load initial config
        self.load_config()
    
    def create_log_tab(self):
        # Log Viewer Frame
        log_frame = ttk.LabelFrame(self.log_tab, text="Snort Logs")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=100, height=30)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Log Actions Frame
        actions_frame = ttk.Frame(self.log_tab)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Follow Logs", command=self.follow_logs).pack(side=tk.LEFT, padx=5)
        
        # Load initial logs
        self.refresh_logs()
    
    # ========== Snort Service Methods ==========
    def load_snort_status(self):
        try:
            if self.os_type == 'windows':
                result = subprocess.run(['sc', 'query', 'snort'], capture_output=True, text=True, shell=True)
                status = 'RUNNING' if 'RUNNING' in result.stdout else 'STOPPED'
            else:
                result = subprocess.run(['systemctl', 'is-active', 'snort'], capture_output=True, text=True)
                status = result.stdout.strip()
            
            if status in ('active', 'RUNNING'):
                self.status_label.config(text="Status: Running")
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
            else:
                self.status_label.config(text="Status: Stopped")
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
        except Exception as e:
            self.status_label.config(text=f"Status: Error ({str(e)})")
    
    def start_snort(self):
        try:
            if self.os_type == 'windows':
                subprocess.run(['net', 'start', 'snort'], check=True, shell=True)
            else:
                subprocess.run(['sudo', 'systemctl', 'start', 'snort'], check=True)
            messagebox.showinfo("Success", "Snort service started successfully")
            self.load_snort_status()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to start Snort: {e.stderr}")
    
    def stop_snort(self):
        try:
            if self.os_type == 'windows':
                subprocess.run(['net', 'stop', 'snort'], check=True, shell=True)
            else:
                subprocess.run(['sudo', 'systemctl', 'stop', 'snort'], check=True)
            messagebox.showinfo("Success", "Snort service stopped successfully")
            self.load_snort_status()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to stop Snort: {e.stderr}")
    
    def restart_snort(self):
        try:
            if self.os_type == 'windows':
                subprocess.run(['net', 'stop', 'snort'], check=True, shell=True)
                subprocess.run(['net', 'start', 'snort'], check=True, shell=True)
            else:
                subprocess.run(['sudo', 'systemctl', 'restart', 'snort'], check=True)
            messagebox.showinfo("Success", "Snort service restarted successfully")
            self.load_snort_status()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to restart Snort: {e.stderr}")
    
    def reload_rules(self):
        try:
            if self.os_type == 'windows':
                # On Windows, we need to restart the service to reload rules
                subprocess.run(['net', 'stop', 'snort'], check=True, shell=True)
                subprocess.run(['net', 'start', 'snort'], check=True, shell=True)
            else:
                subprocess.run(['sudo', 'systemctl', 'reload', 'snort'], check=True)
            messagebox.showinfo("Success", "Snort rules reloaded successfully")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to reload Snort rules: {e.stderr}")
    
    def test_config(self):
        try:
            if self.os_type == 'windows':
                cmd = [self.snort_bin_path, '-T', '-c', self.snort_config_path]
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            else:
                cmd = ['sudo', self.snort_bin_path, '-T', '-c', self.snort_config_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                messagebox.showinfo("Success", "Snort configuration test passed")
                self.log_text.insert(tk.END, result.stdout)
            else:
                messagebox.showerror("Error", "Snort configuration test failed")
                self.log_text.insert(tk.END, result.stderr)
            
            self.log_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to test Snort configuration: {str(e)}")
    
    def update_statistics(self):
        try:
            if self.os_type == 'windows':
                cmd = [self.snort_bin_path, '-Q', '--dump-stats']
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            else:
                cmd = ['sudo', self.snort_bin_path, '-Q', '--dump-stats']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, result.stdout)
        except Exception as e:
            self.stats_text.insert(tk.END, f"Error getting statistics: {str(e)}")
    
    # ========== Rules Management Methods ==========
    def load_rules_files(self):
        try:
            # Clear existing items
            for item in self.rules_files_tree.get_children():
                self.rules_files_tree.delete(item)
            
            # Check if rules directory exists
            if not os.path.exists(self.snort_rules_path):
                messagebox.showwarning("Warning", f"Rules directory not found at {self.snort_rules_path}")
                return
            
            # Get list of rule files
            rule_files = [f for f in os.listdir(self.snort_rules_path) if f.endswith(('.rules', '.conf'))]
            
            for file in rule_files:
                file_path = os.path.join(self.snort_rules_path, file)
                try:
                    file_size = os.path.getsize(file_path)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                    
                    self.rules_files_tree.insert('', tk.END, text=file, values=(f"{file_size} bytes", mod_time))
                except Exception as e:
                    print(f"Error loading file {file}: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load rules files: {str(e)}")
    
    def on_rule_file_select(self, event):
        selected_item = self.rules_files_tree.selection()
        if not selected_item:
            return
            
        file_name = self.rules_files_tree.item(selected_item, 'text')
        file_path = os.path.join(self.snort_rules_path, file_name)
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                self.rule_content_text.delete(1.0, tk.END)
                self.rule_content_text.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read rule file: {str(e)}")
    
    def add_rule(self):
        selected_item = self.rules_files_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rules file first")
            return
            
        file_name = self.rules_files_tree.item(selected_item, 'text')
        file_path = os.path.join(self.snort_rules_path, file_name)
        
        rule_dialog = tk.Toplevel(self.root)
        rule_dialog.title("Add New Rule")
        rule_dialog.geometry("600x400")
        
        ttk.Label(rule_dialog, text="Rule Action:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        action_var = tk.StringVar(value="alert")
        action_combobox = ttk.Combobox(rule_dialog, textvariable=action_var, 
                                      values=["alert", "log", "pass", "drop", "reject"])
        action_combobox.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(rule_dialog, text="Protocol:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        protocol_var = tk.StringVar(value="tcp")
        protocol_combobox = ttk.Combobox(rule_dialog, textvariable=protocol_var, 
                                        values=["tcp", "udp", "icmp", "ip"])
        protocol_combobox.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(rule_dialog, text="Source IP:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
        src_ip_entry = ttk.Entry(rule_dialog)
        src_ip_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        src_ip_entry.insert(0, "$HOME_NET")
        
        ttk.Label(rule_dialog, text="Source Port:").grid(row=3, column=0, padx=5, pady=5, sticky='e')
        src_port_entry = ttk.Entry(rule_dialog)
        src_port_entry.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        src_port_entry.insert(0, "any")
        
        ttk.Label(rule_dialog, text="Direction:").grid(row=4, column=0, padx=5, pady=5, sticky='e')
        direction_var = tk.StringVar(value="->")
        direction_combobox = ttk.Combobox(rule_dialog, textvariable=direction_var, 
                                         values=["->", "<>"])
        direction_combobox.grid(row=4, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(rule_dialog, text="Destination IP:").grid(row=5, column=0, padx=5, pady=5, sticky='e')
        dst_ip_entry = ttk.Entry(rule_dialog)
        dst_ip_entry.grid(row=5, column=1, padx=5, pady=5, sticky='w')
        dst_ip_entry.insert(0, "$EXTERNAL_NET")
        
        ttk.Label(rule_dialog, text="Destination Port:").grid(row=6, column=0, padx=5, pady=5, sticky='e')
        dst_port_entry = ttk.Entry(rule_dialog)
        dst_port_entry.grid(row=6, column=1, padx=5, pady=5, sticky='w')
        dst_port_entry.insert(0, "any")
        
        ttk.Label(rule_dialog, text="Message:").grid(row=7, column=0, padx=5, pady=5, sticky='e')
        msg_entry = ttk.Entry(rule_dialog, width=40)
        msg_entry.grid(row=7, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(rule_dialog, text="Options:").grid(row=8, column=0, padx=5, pady=5, sticky='e')
        options_text = scrolledtext.ScrolledText(rule_dialog, wrap=tk.WORD, width=50, height=5)
        options_text.grid(row=8, column=1, padx=5, pady=5, sticky='w')
        options_text.insert(tk.END, 'classtype:attempted-recon; sid:1000001; rev:1;')
        
        def save_rule():
            rule_parts = [
                action_var.get(),
                protocol_var.get(),
                src_ip_entry.get(),
                src_port_entry.get(),
                direction_var.get(),
                dst_ip_entry.get(),
                dst_port_entry.get()
            ]
            
            rule = " ".join(rule_parts) + f' (msg:"{msg_entry.get()}"; {options_text.get(1.0, tk.END).strip()})'
            
            try:
                with open(file_path, 'a') as f:
                    f.write("\n" + rule)
                
                self.on_rule_file_select(None)  # Refresh the view
                rule_dialog.destroy()
                messagebox.showinfo("Success", "Rule added successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add rule: {str(e)}")
        
        ttk.Button(rule_dialog, text="Save Rule", command=save_rule).grid(row=9, column=1, padx=5, pady=10, sticky='e')
    
    def edit_rule(self):
        selected_item = self.rules_files_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rules file first")
            return
            
        file_name = self.rules_files_tree.item(selected_item, 'text')
        file_path = os.path.join(self.snort_rules_path, file_name)
        
        current_content = self.rule_content_text.get(1.0, tk.END)
        
        edit_dialog = tk.Toplevel(self.root)
        edit_dialog.title(f"Edit {file_name}")
        edit_dialog.geometry("800x600")
        
        edit_text = scrolledtext.ScrolledText(edit_dialog, wrap=tk.WORD, width=100, height=30)
        edit_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        edit_text.insert(tk.END, current_content)
        
        def save_changes():
            try:
                with open(file_path, 'w') as f:
                    f.write(edit_text.get(1.0, tk.END))
                
                self.on_rule_file_select(None)  # Refresh the view
                edit_dialog.destroy()
                messagebox.showinfo("Success", "Rules file saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save changes: {str(e)}")
        
        ttk.Button(edit_dialog, text="Save Changes", command=save_changes).pack(pady=5)
    
    def delete_rule(self):
        selected_item = self.rules_files_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule file first")
            return
            
        file_name = self.rules_files_tree.item(selected_item, 'text')
        
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete {file_name}?"):
            return
            
        file_path = os.path.join(self.snort_rules_path, file_name)
        
        try:
            os.remove(file_path)
            self.load_rules_files()
            self.rule_content_text.delete(1.0, tk.END)
            messagebox.showinfo("Success", "Rule file deleted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete rule file: {str(e)}")
    
    def import_rules(self):
        file_path = filedialog.askopenfilename(title="Select Rules File", 
                                             filetypes=[("Rules files", "*.rules *.conf"), ("All files", "*.*")])
        if not file_path:
            return
            
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(self.snort_rules_path, file_name)
        
        try:
            if os.path.exists(dest_path):
                if not messagebox.askyesno("Confirm", f"{file_name} already exists. Overwrite?"):
                    return
            
            with open(file_path, 'r') as src, open(dest_path, 'w') as dst:
                dst.write(src.read())
            
            self.load_rules_files()
            messagebox.showinfo("Success", "Rules imported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {str(e)}")
    
    def export_rules(self):
        selected_item = self.rules_files_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule file first")
            return
            
        file_name = self.rules_files_tree.item(selected_item, 'text')
        source_path = os.path.join(self.snort_rules_path, file_name)
        
        dest_path = filedialog.asksaveasfilename(title="Save Rules File As", 
                                               initialfile=file_name,
                                               defaultextension=".rules",
                                               filetypes=[("Rules files", "*.rules"), ("All files", "*.*")])
        if not dest_path:
            return
            
        try:
            with open(source_path, 'r') as src, open(dest_path, 'w') as dst:
                dst.write(src.read())
            
            messagebox.showinfo("Success", "Rules exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export rules: {str(e)}")
    
    # ========== Alerts Methods ==========
    def load_alerts(self):
        try:
            # Clear existing alerts
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            alert_file = os.path.join(self.snort_log_path, "alert")
            if not os.path.exists(alert_file):
                return
                
            with open(alert_file, 'r') as f:
                alerts = f.readlines()
            
            alert_id = 1
            for alert in alerts:
                if not alert.strip():
                    continue
                    
                # Simple parsing of alert (this would need to be more robust in a real application)
                parts = alert.split()
                if len(parts) < 10:
                    continue
                    
                timestamp = " ".join(parts[:2])
                priority = parts[3].strip('[]')
                protocol = parts[4]
                
                # Extract source and destination (simplified)
                src = parts[5].split(':')
                dst = parts[7].split(':')
                
                src_ip = src[0] if len(src) > 0 else ""
                src_port = src[1] if len(src) > 1 else ""
                dst_ip = dst[0] if len(dst) > 0 else ""
                dst_port = dst[1] if len(dst) > 1 else ""
                
                message = " ".join(parts[9:])
                
                self.alerts_tree.insert('', tk.END, values=(
                    alert_id, timestamp, priority, protocol, 
                    src_ip, src_port, dst_ip, dst_port, message
                ))
                alert_id += 1
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load alerts: {str(e)}")
    
    def on_alert_select(self, event):
        selected_item = self.alerts_tree.selection()
        if not selected_item:
            return
            
        alert_details = self.alerts_tree.item(selected_item, 'values')
        self.alert_details_text.delete(1.0, tk.END)
        
        details = f"""
        Alert ID: {alert_details[0]}
        Timestamp: {alert_details[1]}
        Priority: {alert_details[2]}
        Protocol: {alert_details[3]}
        Source: {alert_details[4]}:{alert_details[5]}
        Destination: {alert_details[6]}:{alert_details[7]}
        Message: {alert_details[8]}
        """
        
        self.alert_details_text.insert(tk.END, details.strip())
    
    def filter_alerts(self):
        # This is a simplified filter implementation
        # A real application would need more sophisticated filtering
        
        from_date = self.alert_from_entry.get()
        to_date = self.alert_to_entry.get()
        priority = self.alert_priority_combobox.get()
        
        for item in self.alerts_tree.get_children():
            values = self.alerts_tree.item(item, 'values')
            
            show_item = True
            
            # Filter by date range
            if from_date:
                if values[1] < from_date:
                    show_item = False
                    
            if to_date:
                if values[1] > to_date:
                    show_item = False
                    
            # Filter by priority
            if priority != "All":
                if values[2] != priority:
                    show_item = False
                    
            if show_item:
                self.alerts_tree.attach(item, '', 'end')
            else:
                self.alerts_tree.detach(item)
    
    def clear_filter(self):
        self.alert_from_entry.delete(0, tk.END)
        self.alert_to_entry.delete(0, tk.END)
        self.alert_priority_combobox.current(0)
        
        for item in self.alerts_tree.get_children():
            self.alerts_tree.attach(item, '', 'end')
    
    def show_recent_alerts(self):
        # Show alerts from the last 24 hours (simplified)
        now = datetime.now()
        yesterday = now.replace(day=now.day-1).strftime('%m/%d')
        
        self.alert_from_entry.delete(0, tk.END)
        self.alert_from_entry.insert(0, yesterday)
        self.filter_alerts()
    
    # ========== Configuration Methods ==========
    def load_config(self):
        try:
            if not os.path.exists(self.snort_config_path):
                messagebox.showwarning("Warning", f"Snort configuration file not found at {self.snort_config_path}")
                return
                
            with open(self.snort_config_path, 'r') as f:
                content = f.read()
                self.config_text.delete(1.0, tk.END)
                self.config_text.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")
    
    def save_config(self):
        try:
            with open(self.snort_config_path, 'w') as f:
                f.write(self.config_text.get(1.0, tk.END))
            
            messagebox.showinfo("Success", "Configuration saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")
    
    # ========== Log Methods ==========
    def refresh_logs(self):
        try:
            log_files = [
                os.path.join(self.snort_log_path, "alert"),
                os.path.join(self.snort_log_path, "snort.log")
            ]
            
            self.log_text.delete(1.0, tk.END)
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    self.log_text.insert(tk.END, f"=== {os.path.basename(log_file)} ===\n")
                    
                    with open(log_file, 'r') as f:
                        lines = f.readlines()
                        # Show last 100 lines to prevent UI freeze
                        for line in lines[-100:]:
                            self.log_text.insert(tk.END, line)
                    
                    self.log_text.insert(tk.END, "\n")
            
            self.log_text.see(tk.END)
        except Exception as e:
            self.log_text.insert(tk.END, f"Error loading logs: {str(e)}")
    
    def clear_logs(self):
        if not messagebox.askyesno("Confirm", "Are you sure you want to clear all logs?"):
            return
            
        try:
            log_files = [
                os.path.join(self.snort_log_path, "alert"),
                os.path.join(self.snort_log_path, "snort.log")
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'w') as f:
                        f.write("")
            
            self.refresh_logs()
            messagebox.showinfo("Success", "Logs cleared successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
    
    def follow_logs(self):
        # This would implement tail -f functionality in a real application
        # For simplicity, we'll just refresh the logs
        self.refresh_logs()
        self.root.after(5000, self.follow_logs)
    
    def show_about(self):
        about_text = f"""
        Snort Management GUI
        
        Version: 1.0
        OS: {platform.system()} {platform.release()}
        Python: {platform.python_version()}
        
        A cross-platform GUI for managing Snort IDS/IPS
        """
        messagebox.showinfo("About", about_text.strip())

if __name__ == "__main__":
    root = tk.Tk()
    app = SnortGUI(root)
    root.mainloop()