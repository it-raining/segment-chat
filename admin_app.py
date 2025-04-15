import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import json
import threading
import subprocess
import sys
import os
import time
import argparse
from src.common.utils import log_connection
from src.client.admin_client import AdminClient

class AdminApp:
    def __init__(self, root, host='localhost'):
        self.host = host
        self.root = root
        self.root.title("SegmentChat Admin Panel")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#36393f')
        self.style.configure('TLabel', background='#36393f', foreground='#ffffff')
        self.style.configure('TButton', background='#7289da', foreground='#000000',
                           font=('Arial', 10, 'bold'), padding=6)
        self.style.configure('Admin.TButton', background='#ed4245', foreground='#000000',
                           font=('Arial', 10, 'bold'), padding=6)
        
        # Create admin client
        self.client = AdminClient(host=self.host)
        
        # Create main frames
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.login_frame = ttk.Frame(self.main_frame, padding=20)
        self.admin_frame = ttk.Frame(self.main_frame)
        
        # Setup login UI
        self.setup_login_ui()
        
        # Setup admin panel UI
        self.setup_admin_ui()
        
        # Set server status
        self.server_running = False
        
        # Connection status - IMPORTANT: Define this BEFORE calling check_server_status
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(root, textvariable=self.status_var, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
        
        # Either show login frame or server control based on connection status
        self.check_server_status()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        log_connection("Admin application started")
    
    def setup_login_ui(self):
        ttk.Label(self.login_frame, text="Admin Login", font=("Arial", 24)).pack(pady=20)
        
        ttk.Label(self.login_frame, text="Username").pack(pady=(10, 2))
        self.username_entry = ttk.Entry(self.login_frame, width=30)
        self.username_entry.pack(pady=(0, 10))
        
        ttk.Label(self.login_frame, text="Password").pack(pady=(10, 2))
        self.password_entry = ttk.Entry(self.login_frame, width=30, show="*")
        self.password_entry.pack(pady=(0, 10))
        
        self.login_btn = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_btn.pack(pady=20)
    
    def setup_admin_ui(self):
        # Create a notebook with tabs
        self.notebook = ttk.Notebook(self.admin_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Users tab
        self.users_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.users_frame, text="Users")
        
        # Channels tab
        self.channels_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.channels_frame, text="Channels")
        
        # Server tab
        self.server_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.server_frame, text="Server Control")
        
        # Setup each tab
        self.setup_users_tab()
        self.setup_channels_tab()
        self.setup_server_tab()
    
    def setup_users_tab(self):
        # Top controls
        controls_frame = ttk.Frame(self.users_frame)
        controls_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(controls_frame, text="Refresh Users", 
                 command=self.refresh_users).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="Create User", 
                 command=self.show_create_user_dialog).pack(side=tk.LEFT, padx=5)
        
        # Users list with scrollbar
        list_frame = ttk.Frame(self.users_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.users_tree = ttk.Treeview(list_frame, columns=("Username", "Admin"), show="headings")
        self.users_tree.heading("Username", text="Username")
        self.users_tree.heading("Admin", text="Admin")
        self.users_tree.column("Username", width=200)
        self.users_tree.column("Admin", width=100)
        self.users_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.users_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind double-click for user details
        self.users_tree.bind("<Double-1>", self.on_user_double_click)
        
        # Bottom controls
        button_frame = ttk.Frame(self.users_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Delete Selected User", 
                 command=self.delete_selected_user,
                 style="Admin.TButton").pack(side=tk.RIGHT, padx=5)
    
    def setup_channels_tab(self):
        # Top controls
        controls_frame = ttk.Frame(self.channels_frame)
        controls_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(controls_frame, text="Refresh Channels", 
                 command=self.refresh_channels).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="Create Channel", 
                 command=self.show_create_channel_dialog).pack(side=tk.LEFT, padx=5)
        
        # Channels list with scrollbar
        list_frame = ttk.Frame(self.channels_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.channels_tree = ttk.Treeview(list_frame, columns=("ID", "Public"), show="headings")
        self.channels_tree.heading("ID", text="Channel ID")
        self.channels_tree.heading("Public", text="Public")
        self.channels_tree.column("ID", width=200)
        self.channels_tree.column("Public", width=100)
        self.channels_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.channels_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.channels_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bottom controls
        button_frame = ttk.Frame(self.channels_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Delete Selected Channel", 
                 command=self.delete_selected_channel,
                 style="Admin.TButton").pack(side=tk.RIGHT, padx=5)
    
    def setup_server_tab(self):
        # Server status
        status_frame = ttk.Frame(self.server_frame, padding=20)
        status_frame.pack(fill=tk.X)
        
        ttk.Label(status_frame, text="Server Status:", 
                font=("Arial", 14)).pack(side=tk.LEFT, padx=10)
        
        self.server_status_var = tk.StringVar(value="Unknown")
        status_label = ttk.Label(status_frame, textvariable=self.server_status_var,
                               font=("Arial", 14, "bold"))
        status_label.pack(side=tk.LEFT, padx=10)
        
        # Server log (simplified)
        log_frame = ttk.Frame(self.server_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(log_frame, text="Server Log:").pack(anchor=tk.W)
        
        self.log_text = tk.Text(log_frame, height=15, bg="#2f3136", fg="#43c8cf")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Control buttons
        button_frame = ttk.Frame(self.server_frame, padding=20)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Start Server", 
                 command=self.start_server).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_frame, text="Stop Server", 
                 command=self.stop_server,
                 style="Admin.TButton").pack(side=tk.RIGHT, padx=10)
        
        # Refresh button for log
        ttk.Button(button_frame, text="Refresh Log", 
                 command=self.refresh_server_log).pack(side=tk.RIGHT, padx=10)
    
    def show_login_frame(self):
        self.admin_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_admin_frame(self):
        self.login_frame.pack_forget()
        self.admin_frame.pack(fill=tk.BOTH, expand=True)
        
        # Refresh all tabs
        # Only try to refresh these if server is running
        if self.server_running:
            self.refresh_users()
            self.refresh_channels()
        
        # Always refresh logs - log files can be read even if server is down
        self.refresh_server_log()
        # Go to server tab by default if server is down
        if not self.server_running:
            self.notebook.select(self.server_frame)
    
    def check_server_status(self):
        """Check if server is running and update UI accordingly."""
        # Try to connect without blocking the UI
        try:
            # Test if server is running with a quick socket connection
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(0.5)  # Short timeout
            result = test_socket.connect_ex(('localhost', 5000))
            test_socket.close()
            
            if result == 0:  # Port is open, server is running
                self.server_running = True
                self.server_status_var.set("Running")
                self.status_var.set("Server is running. Connect to manage.")
                self.show_login_frame()
                # Try to connect in a separate thread
                threading.Thread(target=self.connect_to_server, daemon=True).start()
            else:  # Server is not running
                self.server_running = False
                self.server_status_var.set("Offline")
                self.status_var.set("Server is not running. Start it from Server Control tab.")
                # Show admin frame with limited functionality
                self.show_admin_frame()
        except Exception as e:
            self.server_running = False
            self.server_status_var.set("Unknown")
            self.status_var.set(f"Error checking server status: {str(e)}")
            # Show admin frame with limited functionality
            self.show_admin_frame()
    
    def connect_to_server(self):
        if self.client.connect():
            self.status_var.set("Connected to server")
            self.server_running = True
            self.server_status_var.set("Running")
        else:
            self.status_var.set("Failed to connect to server")
            self.server_running = False
            self.server_status_var.set("Offline")
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        if not self.server_running:
            messagebox.showerror("Error", "Server is not running. Start it from the Server Control tab.")
            return
        
        success, message = self.client.admin_login(username, password)
        if success:
            self.show_admin_frame()
        else:
            messagebox.showerror("Login Failed", message)
    
    def refresh_users(self):
        # Clear existing users
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        if not self.server_running:
            messagebox.showinfo("Server Offline", "Cannot refresh users: Server is offline")
            return
        
        success, users = self.client.get_users()
        if success:
            for user in users:
                self.users_tree.insert("", tk.END, values=(
                    user['username'],
                    "Yes" if user.get('is_admin', False) else "No"
                ))
        else:
            messagebox.showerror("Error", f"Failed to get users: {users}")
    
    def show_create_user_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New User")
        dialog.geometry("350x280")  # Slightly larger dialog
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Create New User", font=("Arial", 16)).pack(pady=10)
        
        ttk.Label(dialog, text="Username:").pack(anchor=tk.W, padx=20, pady=(10, 2))
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.pack(padx=20, pady=(0, 10))
        
        ttk.Label(dialog, text="Password:").pack(anchor=tk.W, padx=20, pady=(10, 2))
        password_entry = ttk.Entry(dialog, width=30, show="*")
        password_entry.pack(padx=20, pady=(0, 10))
        
        is_admin_var = tk.BooleanVar(value=False)
        admin_check = ttk.Checkbutton(dialog, text="Administrator", variable=is_admin_var)
        admin_check.pack(anchor=tk.W, padx=20, pady=10)
        
        def on_create():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            is_admin = is_admin_var.get()
            
            if not username or not password:
                messagebox.showerror("Error", "Please enter username and password", parent=dialog)
                return
            
            success, message = self.client.create_user(username, password, is_admin)
            if success:
                messagebox.showinfo("Success", "User created successfully", parent=dialog)
                dialog.destroy()
                self.refresh_users()
            else:
                messagebox.showerror("Error", message, parent=dialog)
        
        # Add button container frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Create a more prominent button with increased width
        create_button = ttk.Button(
            button_frame, 
            text="Create User", 
            command=on_create,
            style="Action.TButton",
            width=30  # Make the button wider
        )
        create_button.pack(fill=tk.X, pady=5)
    
    def on_user_double_click(self, event):
        item = self.users_tree.selection()[0]
        username = self.users_tree.item(item, "values")[0]
        
        # Show user details or edit dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"User: {username}")
        dialog.geometry("300x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"User: {username}", font=("Arial", 16)).pack(pady=10)
        
        ttk.Button(dialog, text="Reset Password", 
                 command=lambda: self.reset_user_password(username, dialog)).pack(pady=10)
        
        ttk.Button(dialog, text="Delete User", 
                 command=lambda: self.delete_user(username, dialog),
                 style="Admin.TButton").pack(pady=10)
    
    def reset_user_password(self, username, parent_dialog):
        new_password = simpledialog.askstring("Reset Password", 
                                           f"Enter new password for {username}:", 
                                           parent=parent_dialog, show="*")
        if new_password:
            # Implement password reset
            success, message = self.client.create_user(username, new_password, False)
            if success:
                messagebox.showinfo("Success", "Password reset successfully", parent=parent_dialog)
            else:
                messagebox.showerror("Error", message, parent=parent_dialog)
    
    def delete_user(self, username, parent_dialog=None):
        confirm = messagebox.askyesno("Confirm Delete", 
                                    f"Are you sure you want to delete user '{username}'?",
                                    parent=parent_dialog or self.root)
        if confirm:
            success, message = self.client.delete_user(username)
            if success:
                messagebox.showinfo("Success", "User deleted successfully", 
                                  parent=parent_dialog or self.root)
                if parent_dialog:
                    parent_dialog.destroy()
                self.refresh_users()
            else:
                messagebox.showerror("Error", message, 
                                   parent=parent_dialog or self.root)
    
    def delete_selected_user(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showerror("Error", "No user selected")
            return
        
        item = selection[0]
        username = self.users_tree.item(item, "values")[0]
        self.delete_user(username)
    
    def refresh_channels(self):
        # Clear existing channels
        for item in self.channels_tree.get_children():
            self.channels_tree.delete(item)
        
        if not self.server_running:
            messagebox.showinfo("Server Offline", "Cannot refresh channels: Server is offline")
            return
        
        success, channels = self.client.get_channels()
        if success:
            for channel in channels:
                self.channels_tree.insert("", tk.END, values=(
                    channel['id'],
                    "Yes" if channel.get('is_public', True) else "No"
                ))
        else:
            messagebox.showerror("Error", f"Failed to get channels: {channels}")
    
    def show_create_channel_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New Channel")
        dialog.geometry("350x230")  # Slightly larger dialog
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Create New Channel", font=("Arial", 16)).pack(pady=10)
        
        ttk.Label(dialog, text="Channel ID:").pack(anchor=tk.W, padx=20, pady=(10, 2))
        channel_entry = ttk.Entry(dialog, width=30)
        channel_entry.pack(padx=20, pady=(0, 10))
        
        is_public_var = tk.BooleanVar(value=True)
        public_check = ttk.Checkbutton(dialog, text="Public Channel", variable=is_public_var)
        public_check.pack(anchor=tk.W, padx=20, pady=10)
        
        def on_create():
            channel_id = channel_entry.get().strip()
            is_public = is_public_var.get()
            
            if not channel_id:
                messagebox.showerror("Error", "Please enter a channel ID", parent=dialog)
                return
            
            success, message = self.client.create_channel(channel_id, is_public)
            if success:
                messagebox.showinfo("Success", "Channel created successfully", parent=dialog)
                dialog.destroy()
                self.refresh_channels()
            else:
                messagebox.showerror("Error", message, parent=dialog)
        
        # Add button container frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Create a more prominent button with increased width
        create_button = ttk.Button(
            button_frame,
            text="Create Channel",
            command=on_create,
            style="Action.TButton",
            width=20  # Make the button wider
        )
        create_button.pack(fill=tk.X, pady=5)
    
    def delete_selected_channel(self):
        selection = self.channels_tree.selection()
        if not selection:
            messagebox.showerror("Error", "No channel selected")
            return
        
        item = selection[0]
        channel_id = self.channels_tree.item(item, "values")[0]
        
        confirm = messagebox.askyesno("Confirm Delete", 
                                    f"Are you sure you want to delete channel '{channel_id}'?")
        if confirm:
            success, message = self.client.delete_channel(channel_id)
            if success:
                messagebox.showinfo("Success", "Channel deleted successfully")
                self.refresh_channels()
            else:
                messagebox.showerror("Error", message)
    
    def refresh_server_log(self):
        # Clear log
        self.log_text.delete(1.0, tk.END)
        
        # Read log file
        try:
            # Ensure logs directory exists
            os.makedirs('logs', exist_ok=True)
            
            # Create log file if it doesn't exist
            log_path = 'logs/connection_log.txt'
            if not os.path.exists(log_path):
                with open(log_path, 'w') as f:
                    f.write("Log file created\n")
            
            with open(log_path, 'r') as f:
                log_lines = f.readlines()
                # Show last 100 lines
                for line in log_lines[-100:]:
                    self.log_text.insert(tk.END, line)
            
            self.log_text.see(tk.END)  # Scroll to end
        except Exception as e:
            self.log_text.insert(tk.END, f"Error reading log: {str(e)}")
        
        # Just update the server status display without calling check_server_status again
        self.server_status_var.set("Running" if self.server_running else "Offline")
        
    def start_server(self):
        # Check if server is already running
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(0.5)
            result = test_socket.connect_ex(('localhost', 5000))
            test_socket.close()
            
            if result == 0:  # Port is open, server is running
                messagebox.showinfo("Server Status", "Server is already running")
                self.server_running = True
                self.server_status_var.set("Running")
                return
        except:
            pass  # Ignore errors and try to start server anyway
        
        try:
            # Get the path to server.py relative to admin_app.py
            base_dir = os.path.dirname(os.path.abspath(__file__))
            server_path = os.path.join(base_dir, 'src', 'server', 'server.py') # Updated path

            # Make sure the logs directory exists
            os.makedirs('logs', exist_ok=True)

            # Start server as a subprocess
            subprocess.Popen([sys.executable, server_path])

            messagebox.showinfo("Server Status", "Server starting...")

            # Wait a moment then try to connect
            self.root.after(2000, self.check_server_and_connect)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
    
    def check_server_and_connect(self):
        """Check if server is now running and try to connect."""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(0.5)
            result = test_socket.connect_ex(('localhost', 5000))
            test_socket.close()
            
            if result == 0:  # Server is running
                self.server_running = True
                self.server_status_var.set("Running")
                self.status_var.set("Server is running. Connecting...")
                
                # Try to connect
                if self.client.connect():
                    self.status_var.set("Connected to server")
                    messagebox.showinfo("Success", "Server started and connection established")
                    # Show login form
                    if not self.client.authenticated:
                        self.show_login_frame()
                else:
                    messagebox.showinfo("Server Started", 
                                     "Server started but connection could not be established yet. Try again in a moment.")
            else:
                # Server still starting, try again
                # Check if we've been trying for too long
                if not hasattr(self, '_reconnect_count'):
                    self._reconnect_count = 1
                else:
                    self._reconnect_count += 1
                    
                if self._reconnect_count > 10:  # After about 20 seconds of trying
                    messagebox.showerror("Error", "Server did not start successfully after multiple attempts.")
                    self.server_status_var.set("Offline")
                    self._reconnect_count = 0
                    return
                    
                self.root.after(2000, self.check_server_and_connect)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to server: {str(e)}")
    
    def stop_server(self, force=False):
        if not self.server_running and not force:
            messagebox.showerror("Error", "Server is not running")
            return
        
        confirm = messagebox.askyesno("Confirm Shutdown", 
                                    "Are you sure you want to shut down the server?")
        if not confirm:
            return
            
        if not self.client.connected and not force:
            # Try to connect first
            if not self.client.connect():
                if messagebox.askyesno("Connection Failed", 
                                     "Cannot connect to server to send shutdown command. Do you want to force kill?"):
                    self.stop_server(force=True)
                return
        
        if force:
            # Force kill the server process
            try:
                # Find the process listening on port 5000
                if sys.platform == 'win32':
                    os.system(f'FOR /F "tokens=5" %P IN (\'netstat -ano ^| findstr :5000 ^| findstr LISTENING\') DO TaskKill /PID %P /F')
                else:  # Unix-like
                    os.system("kill -9 $(lsof -t -i:5000)")
                
                messagebox.showinfo("Server Status", "Server forcefully terminated")
                self.server_running = False
                self.server_status_var.set("Offline")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to kill server: {str(e)}")
        else:
            success, message = self.client.shutdown_server()
            if success:
                messagebox.showinfo("Server Status", "Server shutting down...")
                self.client.disconnect()
                self.server_running = False
                self.server_status_var.set("Offline")
            else:
                messagebox.showerror("Error", message)
    
    def on_closing(self):
        if self.client.connected:
            self.client.disconnect()
        self.root.destroy()

def main():
    # --- Add argument parsing ---
    parser = argparse.ArgumentParser(description="SegmentChat Admin Client")
    parser.add_argument('--host', type=str, default='localhost',
                        help='The IP address of the server to connect to.')
    args = parser.parse_args()
    # --- End argument parsing ---

    root = tk.Tk()
    app = AdminApp(root, host=args.host) # Pass host to AdminApp
    root.mainloop()

if __name__ == "__main__":
    main()
