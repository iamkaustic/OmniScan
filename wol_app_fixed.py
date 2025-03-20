# Add the current directory to the path to ensure modules can be found
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import socket
import struct
import threading
import json
import os
import subprocess
import re
import time
import telnetlib
from datetime import datetime
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from ad_tools import ActiveDirectoryTools, ActiveDirectoryToolsDialog

# Application information
APP_NAME = "OmniScan"
APP_VERSION = "1.0"
APP_BUILD = "A"
APP_AUTHOR = "Kaustubh Parab"
APP_TITLE = "OmniScan - Simple tool for Network / Admin tasks."

# We don't need nmap anymore, we'll use our own implementation
NETWORK_SCANNING_AVAILABLE = True


class Computer:
    def __init__(self, name, mac, ip="255.255.255.255", port=9):
        self.name = name
        self.mac = mac
        self.ip = ip
        self.port = port

    def to_dict(self):
        return {
            "name": self.name,
            "mac": self.mac,
            "ip": self.ip,
            "port": self.port
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            name=data["name"],
            mac=data["mac"],
            ip=data.get("ip", "255.255.255.255"),
            port=data.get("port", 9)
        )


class ComputerManager:
    def __init__(self, file_path="computers.json"):
        self.file_path = file_path
        self.computers = []
        self.load_computers()

    def load_computers(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    data = json.load(f)
                    self.computers = [Computer.from_dict(c) for c in data]
            except Exception as e:
                print(f"Error loading computers: {e}")
                self.computers = []
        else:
            self.computers = []

    def save_computers(self):
        try:
            with open(self.file_path, "w") as f:
                json.dump([c.to_dict() for c in self.computers], f, indent=2)
        except Exception as e:
            print(f"Error saving computers: {e}")

    def add_computer(self, computer):
        self.computers.append(computer)
        self.save_computers()

    def update_computer(self, index, computer):
        if 0 <= index < len(self.computers):
            self.computers[index] = computer
            self.save_computers()

    def delete_computer(self, index):
        if 0 <= index < len(self.computers):
            del self.computers[index]
            self.save_computers()

    def get_computer(self, index):
        if 0 <= index < len(self.computers):
            return self.computers[index]
        return None


class NetworkScanner:
    def __init__(self):
        self.scan_results = []
        self.scanning = False
        self.scan_thread = None
        
    def get_local_ip(self):
        """Get the local IP address of this machine."""
        try:
            # Create a socket connection to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'
    
    def get_network_range(self):
        """Get the network range based on local IP."""
        local_ip = self.get_local_ip()
        # Assume a /24 network (most common for home networks)
        network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
        return network
    
    def scan_network(self, callback=None, progress_callback=None):
        """
        Scan the local network for devices.
        
        Args:
            callback: Function to call when scan is complete
            progress_callback: Function to call with progress updates
        """
        if self.scanning:
            return False
        
        self.scanning = True
        self.scan_results = []
        
        def run_scan():
            try:
                if progress_callback:
                    progress_callback("Starting network scan...")
                
                # First, get devices from ARP table
                if progress_callback:
                    progress_callback("Scanning ARP table...")
                
                arp_devices = self.scan_arp_table()
                
                # Add ARP devices to results
                for device in arp_devices:
                    self.scan_results.append(device)
                    if progress_callback:
                        progress_callback(f"Found device: {device['hostname']} ({device['ip']})")
                
                if progress_callback:
                    progress_callback(f"Found {len(arp_devices)} devices in ARP table")
                
                # Then scan the network for additional devices
                network_range = self.get_network_range()
                
                if progress_callback:
                    progress_callback("Determining network range: " + network_range)
                
                # Get list of all IPs in the network
                all_ips = list(ipaddress.ip_network(network_range).hosts())
                
                # Filter out IPs we already found in ARP table
                arp_ips = [device['ip'] for device in arp_devices]
                remaining_ips = [ip for ip in all_ips if str(ip) not in arp_ips]
                
                total_ips = len(remaining_ips)
                scanned_ips = 0
                
                if progress_callback:
                    progress_callback(f"Starting scan of {total_ips} additional hosts...")
                
                with ThreadPoolExecutor(max_workers=50) as executor:
                    # Submit all ping tasks
                    futures = {executor.submit(self.ping, ip): ip for ip in remaining_ips}
                    
                    # Process results as they complete
                    for future in futures:
                        if not self.scanning:  # Check if scan was cancelled
                            break
                        
                        ip = futures[future]
                        scanned_ips += 1
                        
                        if scanned_ips % 10 == 0 and progress_callback:
                            progress_callback(f"Scanned {scanned_ips}/{total_ips} hosts...")
                        
                        try:
                            if future.result():
                                # If ping succeeded, get MAC and hostname
                                mac = self.get_mac_from_arp(ip)
                                hostname = self.get_hostname(ip)
                                
                                self.scan_results.append({
                                    'ip': str(ip),
                                    'mac': mac if mac else "Unknown",
                                    'hostname': hostname
                                })
                                
                                if progress_callback:
                                    progress_callback(f"Found device: {hostname} ({ip})")
                        except Exception as e:
                            print(f"Error processing result for {ip}: {e}")
                
                if progress_callback:
                    progress_callback(f"Scan complete! Found {len(self.scan_results)} devices.")
                
            except Exception as e:
                if progress_callback:
                    progress_callback(f"Error during scan: {e}")
                print(f"Scan error: {e}")
            
            finally:
                self.scanning = False
                if callback:
                    callback(self.scan_results)
        
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        return True
    
    def stop_scan(self):
        self.scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=1.0)
    
    def ping(self, ip):
        """Ping an IP address to check if it's up."""
        try:
            # Windows-specific ping command (no -c option)
            subprocess.check_output(f"ping -n 1 -w 500 {ip}", shell=True, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get_mac_from_arp(self, ip):
        """Get MAC address from ARP table for a given IP."""
        try:
            # Run arp command
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
            # Parse output to find MAC
            for line in output.splitlines():
                if str(ip) in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        # MAC is typically the second column in Windows arp output
                        potential_mac = parts[1].replace('-', ':')
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', potential_mac):
                            return potential_mac
        except Exception as e:
            print(f"Error getting MAC from ARP: {e}")
        return None
    
    def get_hostname(self, ip):
        """Try to get hostname for an IP address."""
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except socket.herror:
            return str(ip)
    
    def scan_arp_table(self):
        """Scan the ARP table for devices."""
        devices = []
        try:
            # Run arp -a command
            output = subprocess.check_output("arp -a", shell=True).decode('utf-8')
            
            # Parse output to find IP and MAC addresses
            for line in output.splitlines():
                # Skip header lines
                if "Interface" in line or "Internet Address" in line:
                    continue
                
                # Parse the line
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].replace('-', ':')
                    
                    # Validate MAC address format
                    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                        # Skip invalid MACs (all zeros or broadcast)
                        if mac == "00:00:00:00:00:00" or mac == "ff:ff:ff:ff:ff:ff":
                            continue
                        
                        # Get hostname
                        hostname = self.get_hostname(ip)
                        
                        devices.append({
                            'ip': ip,
                            'mac': mac,
                            'hostname': hostname
                        })
        except Exception as e:
            print(f"Error scanning ARP table: {e}")
        
        return devices


class WakeOnLan:
    @staticmethod
    def validate_mac(mac):
        """Validate the MAC address format."""
        # Remove any separators and convert to lowercase
        mac = re.sub(r'[^a-fA-F0-9]', '', mac).lower()
        
        # Check if we have exactly 12 hex characters
        if len(mac) != 12:
            return False
        
        return True

    @staticmethod
    def format_mac(mac):
        """Format the MAC address to a standard format."""
        # Remove any separators
        mac = re.sub(r'[^a-fA-F0-9]', '', mac).lower()
        
        # Format as XX:XX:XX:XX:XX:XX
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def send_magic_packet(mac_address, ip_address="255.255.255.255", port=9):
        """
        Send a magic packet to wake up a computer with the given MAC address.
        
        Args:
            mac_address (str): The MAC address of the target computer.
            ip_address (str): The IP address to send the packet to. Default is broadcast.
            port (int): The port to send the packet to. Default is 9.
            
        Returns:
            bool: True if the packet was sent successfully, False otherwise.
        """
        try:
            # Remove any separators from the MAC address
            mac_address = re.sub(r'[^a-fA-F0-9]', '', mac_address).lower()
            
            # Create the magic packet
            # FF FF FF FF FF FF followed by the MAC address repeated 16 times
            data = b'\xff' * 6 + bytes.fromhex(mac_address) * 16
            
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Send the packet
            sock.sendto(data, (ip_address, port))
            sock.close()
            
            return True
        except Exception as e:
            print(f"Error sending magic packet: {e}")
            return False


class ComputerDialog(simpledialog.Dialog):
    def __init__(self, parent, title, computer=None):
        self.computer = computer
        super().__init__(parent, title)

    def body(self, frame):
        # Name
        ttk.Label(frame, text="Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.name_var = tk.StringVar(value=self.computer.name if self.computer else "")
        ttk.Entry(frame, textvariable=self.name_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # MAC Address
        ttk.Label(frame, text="MAC Address:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.mac_var = tk.StringVar(value=self.computer.mac if self.computer else "")
        ttk.Entry(frame, textvariable=self.mac_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Format: XX:XX:XX:XX:XX:XX").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        
        # IP Address
        ttk.Label(frame, text="IP Address:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.ip_var = tk.StringVar(value=self.computer.ip if self.computer else "255.255.255.255")
        ttk.Entry(frame, textvariable=self.ip_var, width=30).grid(row=2, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Default: 255.255.255.255 (broadcast)").grid(row=2, column=2, sticky="w", padx=5, pady=5)
        
        # Port
        ttk.Label(frame, text="Port:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.port_var = tk.StringVar(value=str(self.computer.port) if self.computer else "9")
        ttk.Entry(frame, textvariable=self.port_var, width=30).grid(row=3, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Default: 9").grid(row=3, column=2, sticky="w", padx=5, pady=5)
        
        return frame

    def validate(self):
        # Validate name
        if not self.name_var.get().strip():
            messagebox.showerror("Error", "Name cannot be empty")
            return False
        
        # Validate MAC address
        mac = self.mac_var.get().strip()
        if not WakeOnLan.validate_mac(mac):
            messagebox.showerror("Error", "Invalid MAC address format")
            return False
        
        # Validate IP address
        ip = self.ip_var.get().strip()
        try:
            socket.inet_aton(ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return False
        
        # Validate port
        try:
            port = int(self.port_var.get().strip())
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Port must be a number between 1 and 65535")
            return False
        
        return True

    def apply(self):
        mac = re.sub(r'[^a-fA-F0-9]', '', self.mac_var.get().strip()).lower()
        formatted_mac = WakeOnLan.format_mac(mac)
        
        self.result = Computer(
            name=self.name_var.get().strip(),
            mac=formatted_mac,
            ip=self.ip_var.get().strip(),
            port=int(self.port_var.get().strip())
        )


class NetworkScanDialog(tk.Toplevel):
    def __init__(self, parent, scanner, on_select=None):
        super().__init__(parent)
        self.title("Network Scanner")
        self.geometry("800x500")
        self.minsize(800, 500)
        self.transient(parent)
        self.grab_set()
        
        self.scanner = scanner
        self.on_select = on_select
        self.scan_results = []
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
        
        # Start scanning
        self.start_scan()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT, padx=5)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", length=200)
        self.progress.pack(side=tk.LEFT, padx=5)
        
        # Button frame
        button_frame = ttk.Frame(status_frame)
        button_frame.pack(side=tk.RIGHT)
        
        self.scan_button = ttk.Button(button_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results tree
        columns = ("hostname", "ip", "mac")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        # Define headings
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        
        # Define columns
        self.tree.column("hostname", width=250)
        self.tree.column("ip", width=150)
        self.tree.column("mac", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Double-click to select
        self.tree.bind("<Double-1>", self.on_double_click)
        
        # Action frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(action_frame, text="Select", command=self.select_computer).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)
    
    def start_scan(self):
        # Clear the tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.scan_results = []
        self.status_var.set("Scanning...")
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        
        # Start the scan
        self.scanner.scan_network(
            callback=self.on_scan_complete,
            progress_callback=self.update_status
        )
    
    def stop_scan(self):
        self.scanner.stop_scan()
        self.status_var.set("Scan stopped")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
    
    def update_status(self, message):
        self.status_var.set(message)
        self.update_idletasks()
    
    def on_scan_complete(self, results):
        self.scan_results = results
        
        # Update the tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for result in results:
            self.tree.insert("", tk.END, values=(
                result["hostname"],
                result["ip"],
                result["mac"]
            ))
        
        self.status_var.set(f"Scan complete! Found {len(results)} devices.")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
    
    def on_double_click(self, event):
        self.select_computer()
    
    def select_computer(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a computer")
            return
        
        item_id = selected_item[0]
        values = self.tree.item(item_id, "values")
        
        hostname = values[0]
        ip = values[1]
        mac = values[2]
        
        if mac == "Unknown":
            messagebox.showwarning("Warning", "MAC address is unknown for this device. Cannot use for Wake-on-LAN.")
            return
        
        if self.on_select:
            self.on_select(hostname, ip, mac)
        
        self.destroy()


class WakeOnLanApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Try to set the icon
        try:
            icon_path = "new_app_icon.ico"
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Could not set icon: {e}")
        
        # Status variable
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        # Computer list variable
        self.computer_list_var = tk.StringVar()
        
        # Quick wake variable
        self.quick_mac_var = tk.StringVar()
        self.quick_port_var = tk.StringVar(value="9")
        
        # Initialize managers
        self.computer_manager = ComputerManager()
        self.wol = WakeOnLan()
        self.network_scanner = NetworkScanner()
        self.network_tools = NetworkTools()
        self.active_directory_tools = ActiveDirectoryTools()
        
        self.create_widgets()
        self.refresh_computer_list()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create menu
        self.create_menu()
        
        # Computer list frame
        list_frame = ttk.LabelFrame(main_frame, text="Saved Computers", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Computer list
        self.tree = ttk.Treeview(
            list_frame, 
            columns=("name", "mac", "ip", "port"),
            show="headings"
        )
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Define headings
        self.tree.heading("name", text="Name")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("port", text="Port")
        
        # Define columns
        self.tree.column("name", width=200)
        self.tree.column("mac", width=150)
        self.tree.column("ip", width=150)
        self.tree.column("port", width=50)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.config(yscrollcommand=scrollbar.set)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        ttk.Button(button_frame, text="Wake Up", command=self.wake_up_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add", command=self.add_computer).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit", command=self.edit_computer).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self.delete_computer).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Scan Network", command=self.scan_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Network Tools", command=self.open_tools).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Active Directory Tools", command=self.open_ad_tools).pack(side=tk.LEFT, padx=5)
        
        # Quick wake frame
        quick_frame = ttk.LabelFrame(main_frame, text="Quick Wake", padding="10")
        quick_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # MAC address input
        ttk.Label(quick_frame, text="MAC Address:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(quick_frame, textvariable=self.quick_mac_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        # Port input
        ttk.Label(quick_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        ttk.Entry(quick_frame, textvariable=self.quick_port_var, width=5).grid(row=0, column=3, padx=5, pady=5)
        
        # Wake button
        ttk.Button(quick_frame, text="Wake Up", command=self.quick_wake).grid(row=0, column=4, padx=5, pady=5)
        
        # Version information frame
        version_frame = ttk.Frame(main_frame)
        version_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Version information
        version_text = f"{APP_NAME} v{APP_VERSION} (Build {APP_BUILD}) - by {APP_AUTHOR}"
        ttk.Label(version_frame, text=version_text, font=("", 8)).pack(side=tk.LEFT)
        
        # Status bar
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_menu(self):
        """Create the application menu."""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Scan Network", command=self.scan_network)
        file_menu.add_command(label="Network Tools", command=self.open_tools)
        file_menu.add_command(label="Active Directory Tools", command=self.open_ad_tools)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def show_about(self):
        """Show the about dialog."""
        about_text = f"{APP_NAME} v{APP_VERSION} (Build {APP_BUILD})\n\n" \
                     f"Author: {APP_AUTHOR}\n" \
                     f"GitHub: https://github.com/iamkaustic"
        messagebox.showinfo("About", about_text)
    
    def refresh_computer_list(self):
        # Clear the tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add computers to the tree
        for i, computer in enumerate(self.computer_manager.computers):
            self.tree.insert("", tk.END, values=(
                computer.name,
                computer.mac,
                computer.ip,
                computer.port
            ))
    
    def wake_up_selected(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a computer to wake up")
            return
        
        item_id = selected_item[0]
        index = self.tree.index(item_id)
        computer = self.computer_manager.get_computer(index)
        
        if computer:
            self.status_var.set(f"Sending magic packet to {computer.name}...")
            self.root.update_idletasks()
            
            success = self.wol.send_magic_packet(computer.mac, computer.ip, computer.port)
            
            if success:
                self.status_var.set(f"Magic packet sent to {computer.name} successfully")
                messagebox.showinfo("Success", f"Magic packet sent to {computer.name} successfully")
            else:
                self.status_var.set(f"Failed to send magic packet to {computer.name}")
                messagebox.showerror("Error", f"Failed to send magic packet to {computer.name}")

    def add_computer(self):
        dialog = ComputerDialog(self.root, "Add Computer")
        if dialog.result:
            self.computer_manager.add_computer(dialog.result)
            self.refresh_computer_list()
            self.status_var.set(f"Computer '{dialog.result.name}' added")

    def edit_computer(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a computer to edit")
            return
        
        item_id = selected_item[0]
        index = self.tree.index(item_id)
        computer = self.computer_manager.get_computer(index)
        
        if computer:
            dialog = ComputerDialog(self.root, "Edit Computer", computer)
            if dialog.result:
                self.computer_manager.update_computer(index, dialog.result)
                self.refresh_computer_list()
                self.status_var.set(f"Computer '{dialog.result.name}' updated")

    def delete_computer(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a computer to delete")
            return
        
        item_id = selected_item[0]
        index = self.tree.index(item_id)
        computer = self.computer_manager.get_computer(index)
        
        if computer:
            confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete '{computer.name}'?")
            if confirm:
                self.computer_manager.delete_computer(index)
                self.refresh_computer_list()
                self.status_var.set(f"Computer '{computer.name}' deleted")

    def quick_wake(self):
        mac = self.quick_mac_var.get().strip()
        
        if not mac:
            messagebox.showinfo("Info", "Please enter a MAC address")
            return
        
        if not self.wol.validate_mac(mac):
            messagebox.showerror("Error", "Invalid MAC address format")
            return
        
        self.status_var.set(f"Sending magic packet to {mac}...")
        self.root.update_idletasks()
        
        success = self.wol.send_magic_packet(mac)
        
        if success:
            self.status_var.set(f"Magic packet sent to {mac} successfully")
            messagebox.showinfo("Success", f"Magic packet sent to {mac} successfully")
        else:
            self.status_var.set(f"Failed to send magic packet to {mac}")
            messagebox.showerror("Error", f"Failed to send magic packet to {mac}")
    
    def scan_network(self):
        """Open the network scanner dialog."""
        dialog = NetworkScanDialog(self.root, self.network_scanner, self.on_computer_selected_from_scan)
    
    def on_computer_selected_from_scan(self, hostname, ip, mac):
        """Handle a computer selection from the network scanner."""
        # Create a new computer with the selected information
        computer = Computer(
            name=hostname,
            mac=mac,
            ip=ip,
            port=9
        )
        
        # Ask if the user wants to add this computer to the saved list
        confirm = messagebox.askyesno(
            "Add Computer", 
            f"Do you want to add this computer to your saved list?\n\nHostname: {hostname}\nIP: {ip}\nMAC: {mac}"
        )
        
        if confirm:
            self.computer_manager.add_computer(computer)
            self.refresh_computer_list()
            self.status_var.set(f"Computer '{hostname}' added")
        else:
            # Just put the MAC in the quick wake field
            self.quick_mac_var.set(mac)
            self.status_var.set(f"MAC address {mac} copied to Quick Wake")
    
    def open_tools(self):
        """Open the network tools dialog."""
        dialog = ToolsDialog(self.root)
    
    def open_ad_tools(self):
        """Open the Active Directory tools dialog."""
        dialog = ActiveDirectoryToolsDialog(self.root)


class NetworkTools:
    """Class to handle various network tools functionality."""
    
    @staticmethod
    def ping(host, count=4):
        """
        Ping a host and return the results.
        
        Args:
            host: The hostname or IP address to ping
            count: Number of pings to send
            
        Returns:
            str: Output of the ping command
        """
        try:
            # Windows-specific ping command (no -c option)
            output = subprocess.check_output(
                f"ping -n {count} {host}", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')
    
    @staticmethod
    def traceroute(host):
        """
        Perform a traceroute to a host and return the results.
        
        Args:
            host: The hostname or IP address to trace
            
        Returns:
            str: Output of the traceroute command
        """
        try:
            # Windows tracert command
            output = subprocess.check_output(
                f"tracert {host}", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')
    
    @staticmethod
    def telnet(host, port, timeout=5):
        """
        Test telnet connection to a host and port.
        
        Args:
            host: The hostname or IP address
            port: The port number
            timeout: Connection timeout in seconds
            
        Returns:
            str: Result of the telnet attempt
        """
        try:
            # Try to establish a telnet connection
            tn = telnetlib.Telnet(host, port, timeout)
            tn.close()
            return f"Successfully connected to {host} on port {port}"
        except socket.timeout:
            return f"Connection to {host} on port {port} timed out after {timeout} seconds"
        except ConnectionRefusedError:
            return f"Connection to {host} on port {port} was refused"
        except Exception as e:
            return f"Error connecting to {host} on port {port}: {str(e)}"
    
    @staticmethod
    def ipconfig():
        """
        Run ipconfig command and return the results.
        
        Returns:
            str: Output of the ipconfig command
        """
        try:
            output = subprocess.check_output(
                "ipconfig", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')
    
    @staticmethod
    def ipconfig_all():
        """
        Run ipconfig /all command and return the results.
        
        Returns:
            str: Output of the ipconfig /all command
        """
        try:
            output = subprocess.check_output(
                "ipconfig /all", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')
    
    @staticmethod
    def flush_dns():
        """
        Flush the DNS cache and return the results.
        
        Returns:
            str: Output of the ipconfig /flushdns command
        """
        try:
            output = subprocess.check_output(
                "ipconfig /flushdns", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')
    
    @staticmethod
    def nslookup(domain):
        """
        Perform a DNS lookup for a domain and return the results.
        
        Args:
            domain: The domain name to look up
            
        Returns:
            str: Output of the nslookup command
        """
        try:
            output = subprocess.check_output(
                f"nslookup {domain}", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')


class ActiveDirectoryTools:
    """Class to handle Active Directory tools functionality."""
    
    @staticmethod
    def get_domain_info():
        """
        Get information about the current domain.
        
        Returns:
            str: Output of the domain information command
        """
        try:
            output = subprocess.check_output(
                "systeminfo | findstr /B /C:\"Domain\"", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def list_domain_users():
        """
        List users in the domain.
        
        Returns:
            str: Output of the net user /domain command
        """
        try:
            output = subprocess.check_output(
                "net user /domain", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def get_user_info(username):
        """
        Get information about a specific domain user.
        
        Args:
            username: The username to query
            
        Returns:
            str: Output of the net user command
        """
        try:
            output = subprocess.check_output(
                f"net user {username} /domain", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def list_domain_groups():
        """
        List groups in the domain.
        
        Returns:
            str: Output of the net group /domain command
        """
        try:
            output = subprocess.check_output(
                "net group /domain", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def get_group_info(groupname):
        """
        Get information about a specific domain group.
        
        Args:
            groupname: The group name to query
            
        Returns:
            str: Output of the net group command
        """
        try:
            output = subprocess.check_output(
                f"net group {groupname} /domain", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def get_domain_controllers():
        """
        List domain controllers.
        
        Returns:
            str: Output of the nltest command
        """
        try:
            output = subprocess.check_output(
                "nltest /dclist", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def get_domain_trusts():
        """
        List domain trusts.
        
        Returns:
            str: Output of the nltest command
        """
        try:
            output = subprocess.check_output(
                "nltest /domain_trusts", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"


class PingDialog(tk.Toplevel):
    """Dialog for ping tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Ping Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Host input
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.host_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.host_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Count input
        ttk.Label(input_frame, text="Count:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.count_var = tk.StringVar(value="4")
        ttk.Entry(input_frame, textvariable=self.count_var, width=5).grid(row=0, column=3, padx=5, pady=5)
        
        # Ping button
        ttk.Button(input_frame, text="Ping", command=self.ping).grid(row=0, column=4, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def ping(self):
        """Perform ping and display results."""
        host = self.host_var.get().strip()
        if not host:
            messagebox.showinfo("Info", "Please enter a host to ping")
            return
        
        try:
            count = int(self.count_var.get().strip())
            if count < 1:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Count must be a positive number")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Pinging {host} with {count} packets...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run ping in a separate thread
        def run_ping():
            output = NetworkTools.ping(host, count)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_ping, daemon=True).start()


class TracerouteDialog(tk.Toplevel):
    """Dialog for traceroute tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Traceroute Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Host input
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.host_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.host_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Traceroute button
        ttk.Button(input_frame, text="Trace", command=self.traceroute).grid(row=0, column=2, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def traceroute(self):
        """Perform traceroute and display results."""
        host = self.host_var.get().strip()
        if not host:
            messagebox.showinfo("Info", "Please enter a host to trace")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Tracing route to {host}...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run traceroute in a separate thread
        def run_traceroute():
            output = NetworkTools.traceroute(host)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_traceroute, daemon=True).start()


class TelnetDialog(tk.Toplevel):
    """Dialog for telnet tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Telnet Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Host input
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.host_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.host_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Port input
        ttk.Label(input_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.port_var = tk.StringVar(value="23")
        ttk.Entry(input_frame, textvariable=self.port_var, width=5).grid(row=0, column=3, padx=5, pady=5)
        
        # Timeout input
        ttk.Label(input_frame, text="Timeout:").grid(row=0, column=4, sticky="w", padx=5, pady=5)
        self.timeout_var = tk.StringVar(value="5")
        ttk.Entry(input_frame, textvariable=self.timeout_var, width=5).grid(row=0, column=5, padx=5, pady=5)
        
        # Connect button
        ttk.Button(input_frame, text="Connect", command=self.telnet).grid(row=0, column=6, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Common ports frame
        common_ports_frame = ttk.LabelFrame(main_frame, text="Common Ports", padding="5")
        common_ports_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Common ports
        common_ports = [
            ("HTTP", "80"),
            ("HTTPS", "443"),
            ("FTP", "21"),
            ("SSH", "22"),
            ("Telnet", "23"),
            ("SMTP", "25"),
            ("POP3", "110"),
            ("IMAP", "143"),
            ("RDP", "3389")
        ]
        
        # Create buttons for common ports
        for i, (name, port) in enumerate(common_ports):
            ttk.Button(
                common_ports_frame, 
                text=name, 
                width=8,
                command=lambda p=port: self.set_port(p)
            ).grid(row=i//5, column=i%5, padx=5, pady=2)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def set_port(self, port):
        """Set the port number."""
        self.port_var.set(port)
    
    def telnet(self):
        """Perform telnet and display results."""
        host = self.host_var.get().strip()
        if not host:
            messagebox.showinfo("Info", "Please enter a host to connect to")
            return
        
        try:
            port = int(self.port_var.get().strip())
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Port must be a number between 1 and 65535")
            return
        
        try:
            timeout = int(self.timeout_var.get().strip())
            if timeout < 1:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Timeout must be a positive number")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Connecting to {host} on port {port}...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run telnet in a separate thread
        def run_telnet():
            output = NetworkTools.telnet(host, port, timeout)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_telnet, daemon=True).start()


class ToolsDialog(tk.Toplevel):
    """Dialog for selecting network tools."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Network Tools")
        self.geometry("300x400")
        self.minsize(300, 400)
        self.transient(parent)
        self.grab_set()
        
        self.parent = parent
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(
            main_frame, 
            text="Select a Network Tool",
            font=("", 12, "bold")
        ).pack(pady=10)
        
        # Create a canvas with a scrollbar for the tools
        canvas_frame = ttk.Frame(main_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add a canvas
        canvas = tk.Canvas(canvas_frame)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add a scrollbar to the canvas
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure the canvas
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Create a frame inside the canvas to hold the tools
        tools_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=tools_frame, anchor="nw", width=canvas.winfo_reqwidth())
        
        # Add tool buttons
        ttk.Button(
            tools_frame, 
            text="Ping",
            width=20,
            command=self.open_ping
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Traceroute",
            width=20,
            command=self.open_traceroute
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Telnet",
            width=20,
            command=self.open_telnet
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="IPConfig",
            width=20,
            command=self.open_ipconfig
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="IPConfig /all",
            width=20,
            command=self.open_ipconfig_all
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Flush DNS",
            width=20,
            command=self.open_flush_dns
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="NSLookup",
            width=20,
            command=self.open_nslookup
        ).pack(pady=5)
        
        # Bind mousewheel to the canvas for scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def open_ping(self):
        """Open the ping dialog."""
        self.destroy()
        PingDialog(self.parent)
    
    def open_traceroute(self):
        """Open the traceroute dialog."""
        self.destroy()
        TracerouteDialog(self.parent)
    
    def open_telnet(self):
        """Open the telnet dialog."""
        self.destroy()
        TelnetDialog(self.parent)
    
    def open_ipconfig(self):
        """Open the ipconfig dialog."""
        self.destroy()
        IpconfigDialog(self.parent)
    
    def open_ipconfig_all(self):
        """Open the ipconfig /all dialog."""
        self.destroy()
        IpconfigAllDialog(self.parent)
    
    def open_flush_dns(self):
        """Open the flush DNS dialog."""
        self.destroy()
        FlushDnsDialog(self.parent)
    
    def open_nslookup(self):
        """Open the NSLookup dialog."""
        self.destroy()
        NslookupDialog(self.parent)


class IpconfigDialog(tk.Toplevel):
    """Dialog for ipconfig tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("IPConfig Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run ipconfig in a separate thread
        def run_ipconfig():
            output = NetworkTools.ipconfig()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_ipconfig, daemon=True).start()


class IpconfigAllDialog(tk.Toplevel):
    """Dialog for ipconfig /all tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("IPConfig /all Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run ipconfig /all in a separate thread
        def run_ipconfig_all():
            output = NetworkTools.ipconfig_all()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_ipconfig_all, daemon=True).start()


class FlushDnsDialog(tk.Toplevel):
    """Dialog for flush DNS tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Flush DNS Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run flush DNS in a separate thread
        def run_flush_dns():
            output = NetworkTools.flush_dns()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_flush_dns, daemon=True).start()


class NslookupDialog(tk.Toplevel):
    """Dialog for NSLookup tool."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("NSLookup Tool")
        self.geometry("600x400")
        self.minsize(600, 400)
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog on the parent window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Domain input
        ttk.Label(input_frame, text="Domain:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.domain_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.domain_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # NSLookup button
        ttk.Button(input_frame, text="Lookup", command=self.nslookup).grid(row=0, column=2, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def nslookup(self):
        """Perform NSLookup and display results."""
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showinfo("Info", "Please enter a domain to look up")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Looking up {domain}...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run NSLookup in a separate thread
        def run_nslookup():
            output = NetworkTools.nslookup(domain)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_nslookup, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = WakeOnLanApp(root)
    root.mainloop()
