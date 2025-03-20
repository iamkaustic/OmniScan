import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import re

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
    
    @staticmethod
    def list_roles_features():
        """
        List installed roles and features.
        
        Returns:
            str: Output of the Get-WindowsFeature command
        """
        try:
            output = subprocess.check_output(
                "powershell -Command \"Get-WindowsFeature | Where-Object {$_.Installed -eq $true} | Format-Table -Property Name,DisplayName\"", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def test_server_connectivity(server):
        """
        Test connectivity to a server.
        
        Args:
            server: The server name or IP to test
            
        Returns:
            str: Output of the Test-NetConnection command
        """
        try:
            output = subprocess.check_output(
                f"powershell -Command \"Test-NetConnection -ComputerName {server} -InformationLevel Detailed\"", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"
    
    @staticmethod
    def get_domain_ip_fqdn():
        """
        Get domain IP and FQDN.
        
        Returns:
            str: Output of the nslookup command
        """
        try:
            # Get domain name first
            domain_output = subprocess.check_output(
                "systeminfo | findstr /B /C:\"Domain\"", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            
            # Extract domain name
            domain_match = re.search(r"Domain:\s+(.+)", domain_output)
            if domain_match:
                domain_name = domain_match.group(1).strip()
                # Now get IP for the domain
                ip_output = subprocess.check_output(
                    f"nslookup {domain_name}", 
                    shell=True, 
                    stderr=subprocess.STDOUT
                ).decode('utf-8')
                return f"Domain: {domain_name}\n\n{ip_output}"
            else:
                return "Error: Could not determine domain name"
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8') if hasattr(e, 'output') else "Error: Command failed"


class ActiveDirectoryToolsDialog(tk.Toplevel):
    """Dialog for selecting Active Directory tools."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Active Directory Tools")
        self.geometry("300x400")
        self.minsize(300, 400)
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
        
        # Title
        ttk.Label(
            main_frame, 
            text="Active Directory Tools",
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
            text="Domain Information",
            width=25,
            command=self.open_domain_info
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="List Domain Users",
            width=25,
            command=self.open_list_users
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="User Information",
            width=25,
            command=self.open_user_info
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="List Domain Groups",
            width=25,
            command=self.open_list_groups
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Group Information",
            width=25,
            command=self.open_group_info
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Domain Controllers",
            width=25,
            command=self.open_domain_controllers
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Domain Trusts",
            width=25,
            command=self.open_domain_trusts
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="List Roles and Features",
            width=25,
            command=self.open_list_roles_features
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Test Server Connectivity",
            width=25,
            command=self.open_test_server_connectivity
        ).pack(pady=5)
        
        ttk.Button(
            tools_frame, 
            text="Get Domain IP and FQDN",
            width=25,
            command=self.open_get_domain_ip_fqdn
        ).pack(pady=5)
        
        # Bind mousewheel to the canvas for scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def open_domain_info(self):
        """Open the domain information dialog."""
        self.destroy()
        DomainInfoDialog(self.parent)
    
    def open_list_users(self):
        """Open the list domain users dialog."""
        self.destroy()
        ListDomainUsersDialog(self.parent)
    
    def open_user_info(self):
        """Open the user information dialog."""
        self.destroy()
        UserInfoDialog(self.parent)
    
    def open_list_groups(self):
        """Open the list domain groups dialog."""
        self.destroy()
        ListDomainGroupsDialog(self.parent)
    
    def open_group_info(self):
        """Open the group information dialog."""
        self.destroy()
        GroupInfoDialog(self.parent)
    
    def open_domain_controllers(self):
        """Open the domain controllers dialog."""
        self.destroy()
        DomainControllersDialog(self.parent)
    
    def open_domain_trusts(self):
        """Open the domain trusts dialog."""
        self.destroy()
        DomainTrustsDialog(self.parent)
    
    def open_list_roles_features(self):
        """Open the list roles and features dialog."""
        self.destroy()
        ListRolesFeaturesDialog(self.parent)
    
    def open_test_server_connectivity(self):
        """Open the test server connectivity dialog."""
        self.destroy()
        TestServerConnectivityDialog(self.parent)
    
    def open_get_domain_ip_fqdn(self):
        """Open the get domain IP and FQDN dialog."""
        self.destroy()
        GetDomainIPFQDNDialog(self.parent)


class DomainInfoDialog(tk.Toplevel):
    """Dialog for domain information."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Domain Information")
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
        output_frame = ttk.LabelFrame(main_frame, text="Domain Information", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run domain info in a separate thread
        def run_domain_info():
            output = ActiveDirectoryTools.get_domain_info()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_domain_info, daemon=True).start()


class ListDomainUsersDialog(tk.Toplevel):
    """Dialog for listing domain users."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Domain Users")
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
        output_frame = ttk.LabelFrame(main_frame, text="Domain Users", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run list users in a separate thread
        def run_list_users():
            output = ActiveDirectoryTools.list_domain_users()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_list_users, daemon=True).start()


class UserInfoDialog(tk.Toplevel):
    """Dialog for user information."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("User Information")
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
        
        # Username input
        ttk.Label(input_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.username_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Get info button
        ttk.Button(input_frame, text="Get Info", command=self.get_user_info).grid(row=0, column=2, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="User Information", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def get_user_info(self):
        """Get information about a user."""
        username = self.username_var.get().strip()
        if not username:
            messagebox.showinfo("Info", "Please enter a username")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Getting information for user '{username}'...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run get user info in a separate thread
        def run_get_user_info():
            output = ActiveDirectoryTools.get_user_info(username)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_get_user_info, daemon=True).start()


class ListDomainGroupsDialog(tk.Toplevel):
    """Dialog for listing domain groups."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Domain Groups")
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
        output_frame = ttk.LabelFrame(main_frame, text="Domain Groups", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run list groups in a separate thread
        def run_list_groups():
            output = ActiveDirectoryTools.list_domain_groups()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_list_groups, daemon=True).start()


class GroupInfoDialog(tk.Toplevel):
    """Dialog for group information."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Group Information")
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
        
        # Group name input
        ttk.Label(input_frame, text="Group Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.groupname_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.groupname_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Get info button
        ttk.Button(input_frame, text="Get Info", command=self.get_group_info).grid(row=0, column=2, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Group Information", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def get_group_info(self):
        """Get information about a group."""
        groupname = self.groupname_var.get().strip()
        if not groupname:
            messagebox.showinfo("Info", "Please enter a group name")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Getting information for group '{groupname}'...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run get group info in a separate thread
        def run_get_group_info():
            output = ActiveDirectoryTools.get_group_info(groupname)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_get_group_info, daemon=True).start()


class DomainControllersDialog(tk.Toplevel):
    """Dialog for domain controllers."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Domain Controllers")
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
        output_frame = ttk.LabelFrame(main_frame, text="Domain Controllers", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run domain controllers in a separate thread
        def run_domain_controllers():
            output = ActiveDirectoryTools.get_domain_controllers()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_domain_controllers, daemon=True).start()


class DomainTrustsDialog(tk.Toplevel):
    """Dialog for domain trusts."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Domain Trusts")
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
        output_frame = ttk.LabelFrame(main_frame, text="Domain Trusts", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run domain trusts in a separate thread
        def run_domain_trusts():
            output = ActiveDirectoryTools.get_domain_trusts()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_domain_trusts, daemon=True).start()


class ListRolesFeaturesDialog(tk.Toplevel):
    """Dialog for listing roles and features."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Roles and Features")
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
        output_frame = ttk.LabelFrame(main_frame, text="Roles and Features", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run list roles and features in a separate thread
        def run_list_roles_features():
            output = ActiveDirectoryTools.list_roles_features()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_list_roles_features, daemon=True).start()


class TestServerConnectivityDialog(tk.Toplevel):
    """Dialog for testing server connectivity."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Test Server Connectivity")
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
        
        # Server input
        ttk.Label(input_frame, text="Server:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.server_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.server_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Test button
        ttk.Button(input_frame, text="Test", command=self.test_server).grid(row=0, column=2, padx=5, pady=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Test Results", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def test_server(self):
        """Test server connectivity."""
        server = self.server_var.get().strip()
        if not server:
            messagebox.showinfo("Info", "Please enter a server name or IP")
            return
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Testing connectivity to server '{server}'...\n\n")
        self.output_text.config(state=tk.DISABLED)
        self.update_idletasks()
        
        # Run test server in a separate thread
        def run_test_server():
            output = ActiveDirectoryTools.test_server_connectivity(server)
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_test_server, daemon=True).start()


class GetDomainIPFQDNDialog(tk.Toplevel):
    """Dialog for getting domain IP and FQDN."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Domain IP and FQDN")
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
        output_frame = ttk.LabelFrame(main_frame, text="Domain IP and FQDN", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Run get domain IP and FQDN in a separate thread
        def run_get_domain_ip_fqdn():
            output = ActiveDirectoryTools.get_domain_ip_fqdn()
            
            # Update output
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, output)
            self.output_text.config(state=tk.DISABLED)
            self.output_text.see(tk.END)
        
        threading.Thread(target=run_get_domain_ip_fqdn, daemon=True).start()
