import tkinter as tk
from tkinter import Menu
from tkinter import ttk, messagebox, simpledialog, filedialog
import threading
import time
import datetime
import os
from PIL import Image, ImageTk
import argparse 
import traceback
from src.client.client import ChatClient
from src.common.utils import log_connection
from src.p2p.livestream import LivestreamClient, LivestreamWindow
from src.p2p.peer_manager import PeerConnectionManager
import uuid

class ChatApp:
    def __init__(self, root, host='localhost'):
        self.root = root
        self.root.title("SegmentChat")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Configure style with black text for better readability
        self.style = ttk.Style()
        self.style.theme_use("clam") 
        self.style.configure('TFrame', background='#2f3136')
        self.style.configure('TLabel', background='#2f3136', foreground='#ffffff', font=('Segoe UI', 10))
        
        # Enhanced button styles with more contrast and visibility
        self.style.configure('TButton', 
                          background='#7289da', 
                          foreground='#ffffff',
                          font=('Segoe UI', 10, 'bold'),
                          padding=6)
        
        self.style.configure('Channel.TButton', 
                          background='#40444b', 
                          foreground='#dddddd',
                          font=('Segoe UI', 10),
                          padding=8)
        
        # Create a distinct style for important buttons
        self.style.configure('Action.TButton', 
                          background='#7289da',
                          foreground='#ffffff',
                          font=('Segoe UI', 10, 'bold'),
                          padding=6)
        
        self.style.configure('Logout.TButton', 
                     font=("Segoe UI", 10, "bold"), 
                     background='#7289da', 
                     foreground='#ffffff', 
                     padding=6)
        
        # Add hover-like effect for buttons
        self.style.map('Channel.TButton',
                    foreground=[('active', '#ffffff'), ('pressed', '#ffffff')],
                    background=[('active', '#5865f2'), ('pressed', '#3d55c0')])
        
        self.style.map('TButton',
                    foreground=[('active', '#ffffff'), ('pressed', '#ffffff')],
                    background=[('active', '#5865f2'), ('pressed', '#3d55c0')])
        
        self.style.map('Action.TButton',
                    background=[('active', '#5865f2'), ('pressed', '#3d55c0')],
                    foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        
        # Real-time updates
        self.update_interval = 1000  # Update every 1 second (1000ms)
        self.update_job = None
        self.last_message_count = 0
        
        self.visitor_username = None  # Thêm biến lưu visitor username
        
        # Initialize client
        self.client = ChatClient(host=host)
        self.client.set_message_callback(self.update_messages)
        self.client.set_channels_callback(self.update_channels)
        self.client.set_connection_callback(self.update_connection_status)
        self.client.set_auth_callback(self.update_auth_status)
        self.client.set_error_callback(self.show_error)
        self.client.set_online_status_callback(self.update_online_status)
        self.client.set_invisible_status_callback(self.handle_set_invisible_response)
        self.client.set_host_status_callback(self.update_host_status)
        self.client.set_peer_content_callback(self.handle_peer_content) # Changed callback
        self.client.set_peer_status_callback(self.handle_peer_status)   # Changed callback
        self.client.set_channel_users_callback(self.update_channel_users)
        
        # Initialize livestream client with server connection
        # Pass the root window for UI updates
        self.livestream_client = LivestreamClient(root_window=self.root)
        
        # Add callback for active streams
        self.livestream_client.set_server_client(self.client)
        self.client.set_active_streams_callback(self.update_active_streams)
        
        # Network status tracking
        self.online_users = {}  # Track online users
        self.channel_hosts = {}  # Track channel host status
        self.online_peers = {}  # {channel_id: {username: status}}
        
        # Create main frames
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.login_frame = tk.Frame(self.main_frame, bg="#2f3136", padx=20, pady=20)
        self.chat_frame = ttk.Frame(self.main_frame)
        
        # Initialize login UI
        self.setup_login_ui()
        
        # Initialize chat UI
        self.setup_chat_ui()
        
        # Show login frame by default
        self.show_login_frame()
        
        # Connection status
        self.status_var = tk.StringVar(value="Disconnected")
        #self.status_label = ttk.Label(root, textvariable=self.status_var, anchor=tk.W)
        #self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
        
        # Add connection status indicator
        self.setup_connection_indicator()
        
        # Automatically try to connect
        threading.Thread(target=self.client.connect, daemon=True).start()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        log_connection("Chat application started")
    
    def setup_connection_indicator(self):
        """Setup UI elements for connection status."""
        self.connection_frame = ttk.Frame(self.root, style='TFrame', height=30)
        self.connection_frame.pack(side=tk.TOP, fill=tk.X)
        
        # Status indicator - colored circle
        self.status_canvas = tk.Canvas(self.connection_frame, width=15, height=15, 
                                     bg="#36393f", highlightthickness=0)
        self.status_canvas.pack(side=tk.LEFT, padx=5)
        self.status_indicator = self.status_canvas.create_oval(2, 2, 13, 13, fill="red")
        
        # Status text
        self.status_var = tk.StringVar(value="Offline")
        self.status_label = ttk.Label(self.connection_frame, textvariable=self.status_var, 
                                    foreground="#ffffff")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Add reconnect button
        #self.reconnect_btn = ttk.Button(self.connection_frame, text="🔄 Reconnect", 
        #                              command=self.reconnect, width=15)
        #self.reconnect_btn.pack(side=tk.RIGHT, padx=10)
    
    def setup_login_ui(self):
        ttk.Label(self.login_frame, text="SegmentChat", font=("Segoe UI", 24, "bold"), foreground="#7289da", background="#2f3136").pack(pady=20)
        
        ttk.Label(self.login_frame, text="Username", font=("Segoe UI", 10),foreground="#c0c0c0", background="#2f3136").pack(pady=(10, 2))
        self.username_entry = ttk.Entry(self.login_frame, width=30)
        self.username_entry.pack(pady=(0, 10))
        
        ttk.Label(self.login_frame, text="Password", font=("Segoe UI", 10), foreground="#c0c0c0", background="#2f3136").pack(pady=(10, 2))
        self.password_entry = ttk.Entry(self.login_frame, width=30, show="*")
        self.password_entry.pack(pady=(0, 10))
        
        btn_frame = ttk.Frame(self.login_frame, style="Button.TFrame")
        btn_frame.pack(pady=20)
        
        self.login_btn = ttk.Button(btn_frame, text="👤 Login", command=self.login)
        self.login_btn.pack(side=tk.LEFT, padx=5)
        
        self.register_btn = ttk.Button(btn_frame, text="🔐 Register", command=self.register)
        self.register_btn.pack(side=tk.LEFT, padx=5)
        
        self.visitor_btn = ttk.Button(self.login_frame, text="🧑‍🤝‍🧑 Continue as Visitor", command=self.continue_as_visitor)
        self.visitor_btn.pack(pady=10)
    
    def setup_chat_ui(self):
        # Split into sidebar and content area
        self.sidebar = ttk.Frame(self.chat_frame, width=200, style='TFrame')
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)
        
        self.content = ttk.Frame(self.chat_frame, style='TFrame')
        self.content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Sidebar - User info
        self.user_frame = ttk.Frame(self.sidebar, style='TFrame')
        self.user_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # Thêm label trạng thái online/invisible
        self.profile_status_var = tk.StringVar(value="Online")
        self.profile_status_label = ttk.Label(self.user_frame, textvariable=self.profile_status_var, font=("Arial", 9, "italic"))
        self.profile_status_label.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=(0, 2))

        # Thêm nút chuyển chế độ
        self.invisible_btn = ttk.Button(
            self.user_frame, text="Go Invisible", style='TButton',
            command=self.toggle_invisible_mode
        )
        self.invisible_btn.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=(0, 5))
        
        self.user_label = ttk.Label(self.user_frame, text="👤 Visitor Mode", font=("Arial", 10, "bold"), anchor="w", wraplength=180)
        self.user_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=(0, 5))
         
        self.logout_btn = ttk.Button(self.user_frame, text="Logout", style='Logout.TButton', command=self.logout)
        self.logout_btn.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=(0, 5))
        
        separator_profile = tk.Canvas(self.sidebar, height=2, bg="#5c5c5e", highlightthickness=0)
        separator_profile.pack(fill=tk.X, padx=10, pady=5)
        
        # Sidebar - Channels
        ttk.Label(self.sidebar, text="CHANNELS", font=("Arial", 10, "bold")).pack(fill=tk.X, padx=10, pady=(10, 5), anchor=tk.W)
        
        self.channels_frame = ttk.Frame(self.sidebar, style='TFrame')
        self.channels_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.create_channel_btn = ttk.Button(self.sidebar, text="➕ Create Channel", 
                                           command=self.create_channel, style='Action.TButton')
        self.create_channel_btn.pack(fill=tk.X, padx=5, pady=5)
        
        separator_channels = tk.Canvas(self.sidebar, height=2, bg="#5c5c5e", highlightthickness=0)
        separator_channels.pack(fill=tk.X, padx=10, pady=(5, 5))
        
        # Add peer status frame to sidebar
        peer_status_frame = ttk.Frame(self.sidebar, style='TFrame')
        peer_status_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # Add green dot for ONLINE PEERS
        peer_status_canvas = tk.Canvas(peer_status_frame, width=15, height=15, 
                                bg="#2f3136", highlightthickness=0)
        peer_status_canvas.pack(side=tk.LEFT, padx=(0, 5))
        peer_status_indicator = peer_status_canvas.create_oval(2, 2, 13, 13, fill="#43b581")
        
        # Add ONLINE PEERS label
        ttk.Label(peer_status_frame, text="ONLINE PEERS", font=("Arial", 9, "bold"), 
            foreground="#eeeeee").pack(side=tk.LEFT, anchor=tk.W)
        
        # Add vertical separator between sidebar and content
        separator_vertical = tk.Canvas(self.chat_frame, width=2, bg="#5c5c5e", highlightthickness=0)
        separator_vertical.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        # Create peers frame to list online peers
        self.peers_frame = ttk.Frame(self.sidebar, style='TFrame')
        self.peers_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        # Content area - Channel name
        self.channel_header = ttk.Frame(self.content, style='TFrame', height=50)
        self.channel_header.pack(fill=tk.X)
        self.channel_header.pack_propagate(False)
        
        self.channel_name = ttk.Label(self.channel_header, text="💬 # welcome", font=("Arial", 14, "bold"))
        self.channel_name.pack(side=tk.LEFT, padx=15, pady=10)
        
        # Add host status indicator in channel header
        self.host_status_frame = ttk.Frame(self.channel_header)
        self.host_status_frame.pack(side=tk.RIGHT, padx=10)
        
        self.host_status_canvas = tk.Canvas(self.host_status_frame, width=12, height=12, 
                                         bg="#2f3136", highlightthickness=0)
        self.host_status_canvas.pack(side=tk.LEFT, padx=2)
        self.host_indicator = self.host_status_canvas.create_oval(2, 2, 10, 10, fill="gray")
        
        self.host_label = ttk.Label(self.host_status_frame, text="No host", foreground="#ffffff")
        self.host_label.pack(side=tk.LEFT, padx=2)
        
        # Add host/connection status indicator in channel header
        self.connection_frame = ttk.Frame(self.channel_header)
        self.connection_frame.pack(side=tk.RIGHT, padx=10)
        
        self.connection_label = ttk.Label(self.connection_frame, text="🔌 Connection: ", foreground="#ffffff")
        self.connection_label.pack(side=tk.LEFT)
        
        self.connection_type = ttk.Label(self.connection_frame, text="Server", foreground="#ffffff")
        self.connection_type.pack(side=tk.LEFT, padx=5)
        
        # Add livestream buttons in channel header
        self.stream_btn = ttk.Button(self.channel_header, text="🖥 Start Stream", 
                                   command=self.start_livestream)
        self.stream_btn.pack(side=tk.RIGHT, padx=10)
        
        self.view_stream_btn = ttk.Button(self.channel_header, text="👀 View Stream", 
                                        command=self.view_livestream)
        self.view_stream_btn.pack(side=tk.RIGHT, padx=10)
        
        # Add separator below channel header
        separator_header = tk.Canvas(self.content, height=2, bg="#5c5c5e", highlightthickness=0)
        separator_header.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Content area - Messages
        self.messages_frame = ttk.Frame(self.content, style='TFrame')
        self.messages_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a canvas for messages
        self.messages_canvas = tk.Canvas(self.messages_frame, bg="#2f3136", highlightthickness=0)
        self.messages_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add a single scrollbar
        self.scrollbar = ttk.Scrollbar(self.messages_frame, orient=tk.VERTICAL, command=self.messages_canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure canvas scrolling
        self.messages_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Create a frame inside the canvas to hold the messages
        self.messages_inner = ttk.Frame(self.messages_canvas, style='TFrame')
        self.messages_window = self.messages_canvas.create_window((0, 0), window=self.messages_inner, anchor=tk.NW)
        
        # Content area - Message input
        self.message_input_frame = ttk.Frame(self.content, style='TFrame', height=80)
        self.message_input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        
        # Create a container for the message entry
        self.entry_container = ttk.Frame(self.message_input_frame, style='TFrame')
        self.entry_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Add message entry
        self.message_entry = tk.Text(self.entry_container, height=3, bg="#444444", fg="#ffffff", 
                                 insertbackground="#000000", relief=tk.FLAT, font=("Arial", 10), width=50)
        self.message_entry.pack(fill=tk.BOTH, expand=True)
        self.message_entry.bind("<Return>", self.send_message_event)
        
        # Create a container for the icon button and message entry
        self.icon_container = ttk.Frame(self.message_input_frame, style='TFrame')
        self.entry_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Create a container for icon buttons
        self.button_container = ttk.Frame(self.message_input_frame, style='TFrame')
        self.button_container.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        # Add send button
        self.send_btn = ttk.Button(self.message_input_frame, text="Send", 
                                  command=self.send_message, style='Action.TButton')
        self.send_btn.pack(fill=tk.X, pady=(5, 5))
        
        # Add icon picker button below the send button
        self.icon_btn = ttk.Button(self.button_container, text="😀", command=self.open_icon_picker, style='TButton')
        self.icon_btn.pack(fill=tk.X, pady=(5, 5))  # Place below the send button
        
        # Add file upload button next to send button
        self.upload_btn = ttk.Button(self.message_input_frame, text="Upload", 
                                   command=self.upload_file, style='TButton')
        self.upload_btn.pack(fill=tk.X, pady=(5, 5))
        
        # Configure canvas scrolling    
        self.messages_inner.bind("<Configure>", lambda e: self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all")))
        self.messages_canvas.bind("<Configure>", lambda e: self.messages_canvas.itemconfig(self.messages_window, width=e.width))
        self.messages_canvas.bind_all("<MouseWheel>", lambda e: self.messages_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))
        
    def open_icon_picker(self):
        """Open a popup window to select an icon."""
        icon_window = tk.Toplevel(self.root)
        icon_window.title("Select an Icon")
        icon_window.geometry("320x200")
        icon_window.configure(bg="#2f3136")

        # List of icons (you can add more)
        icons = ["😀", "😂", "😍", "😎", "😢", "😡", 
                "👍", "👎", "🎉", "❤️", "🔥", "✨", 
                "🎁", "🎶", "📚", "📷", "💻", "📱"]

        def select_icon(icon):
            """Insert the selected icon into the message entry."""
            self.message_entry.insert(tk.END, icon)
            icon_window.destroy()
            
        # Create a canvas to hold the icons
        canvas = tk.Canvas(icon_window, bg="#2f3136", highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(icon_window, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure canvas scrolling
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Create a frame inside the canvas to hold the icons
        icon_frame = ttk.Frame(canvas, style='TFrame')
        canvas.create_window((0, 0), window=icon_frame, anchor="nw")
        
        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        icon_window.bind_all("<MouseWheel>", _on_mousewheel)
            
        # Calculate rows and columns dynamically
        max_columns = 3  # Maximum number of columns per row
        for index, icon in enumerate(icons):
            row = index // max_columns
            col = index % max_columns
            btn = ttk.Button(icon_frame, text=icon, command=lambda i=icon: select_icon(i), style='TButton')
            btn.grid(row=row, column=col, padx=5, pady=5)
    
    def on_frame_configure(self, event):
        self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        self.messages_canvas.yview_moveto(1.0)  # Scroll to bottom
    
    def on_canvas_configure(self, event):
        self.messages_canvas.itemconfig(self.messages_window, width=event.width)
    
    def on_mousewheel(self, event):
        self.messages_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def show_login_frame(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_chat_frame(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        # Refresh channels list
        self.client.get_channels()
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        log_connection(f"User attempting login: {username}")
        self.client.login(username, password)
        
        # # Initialize offline storage after login
        # if self.client.authenticated:
        #     self.client.initialize_offline_storage()

    def admin_login(self):
        """Login as an admin and access the chat application."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        log_connection(f"Admin attempting login: {username}")
        self.client.admin_login(username, password)
        
        # # Initialize offline storage after login
        # if self.client.authenticated:
        #     self.client.initialize_offline_storage()
    
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        log_connection(f"User attempting registration: {username}")
        self.client.register(username, password)
    
    def continue_as_visitor(self):
        log_connection("User continuing as visitor")
        # Sinh username dạng anonymous_{UUID}
        self.visitor_username = f"anonymous_{uuid.uuid4().hex[:8]}"
        self.client.username = self.visitor_username  # Gán cho client
        self.client.authenticated = False  # Đảm bảo không phải user đăng nhập
        self.show_chat_frame()
        self.user_label.config(text=f"Visitor: {self.visitor_username}")
        # Disable message entry for visitors
        self.message_entry.config(state="disabled")
        self.send_btn.config(state="disabled")
        # Clear message entry
        self.message_entry.delete("1.0", tk.END)
        # Optionally: thông báo cho user biết tên visitor
        messagebox.showinfo("Visitor Mode", f"You are using the name: {self.visitor_username}")
    
    def logout(self):
        log_connection("User logging out")
        self.stop_message_polling()
        self.client.logout()
        self.show_login_frame()
        
    def toggle_invisible_mode(self):
        if self.profile_status_var.get() == "Invisible":
            self.client.set_invisible(False)
            # UI sẽ cập nhật khi nhận response từ server
        else:
            self.client.set_invisible(True)
            # UI sẽ cập nhật khi nhận response từ server
    
    def update_connection_status(self, is_connected):
        """Update connection status UI."""
        if is_connected:
            self.status_var.set("Connected to server")
            self.status_label.configure(foreground="#43b581")
            self.status_canvas.itemconfig(self.status_indicator, fill="#43b581")
            log_connection("Connected to server")
        else:
            self.status_var.set("Disconnected from server")
            self.status_label.configure(foreground="#f04747")
            self.status_canvas.itemconfig(self.status_indicator, fill="#f04747")
            log_connection("Disconnected from server")
    
    def update_auth_status(self, success, message):
        if success:
            # Initialize offline storage after login
            self.client.initialize_offline_storage()
            if message == "Registration successful":
                log_connection("User registration successful")
                messagebox.showinfo("Success", "Registration successful! You can now login.")
            else:
                log_connection(f"User logged in: {self.client.username}")
                self.show_chat_frame()
                self.user_label.config(text=f"Profile: {self.client.username}")
                # Enable message entry for authenticated users
                self.message_entry.config(state="normal")
                self.send_btn.config(state="normal")
        else:
            log_connection(f"Authentication failed: {message}")
            messagebox.showerror("Error", message)
    
    def update_channels(self, channels):
        # Clear existing channels
        for widget in self.channels_frame.winfo_children():
            widget.destroy()
        
        # Add channels to the sidebar
        for channel in channels:
            channel_id = channel['id']
            is_public = channel['is_public']
            icon = "#" if is_public else "🔒"
            btn = ttk.Button(self.channels_frame, text=f"{icon} {channel_id}", 
                            style='Channel.TButton',
                            command=lambda cid=channel_id: self.join_channel(cid))
            btn.pack(fill=tk.X, pady=2)
            
    def handle_set_invisible_response(self, success, invisible):
        if success:
            if invisible:
                self.profile_status_var.set("Invisible")
                self.invisible_btn.config(text="Go Online")
            else:
                self.profile_status_var.set("Online")
                self.invisible_btn.config(text="Go Invisible")
        else:
            messagebox.showerror("Error", "Failed to change invisible mode")
    
    def join_channel(self, channel_id):
        log_connection(f"Joining channel: {channel_id}")
        
        # Clear existing messages from the UI first
        for widget in self.messages_inner.winfo_children():
            widget.destroy()
        # Reset last message count to ensure update happens
        self.last_message_count = 0
        # Clear temporary message cache
        if hasattr(self.client, '_temp_messages'):
            self.client._temp_messages = []

        self.client.join_channel(channel_id)
        self.channel_name.config(text=f"# {channel_id}")
        
        # Reset connection status
        self.connection_type.config(text="Server", foreground="#ffffff")
        
        # Stop existing update job if any
        self.stop_message_polling()
            
        # Start polling for new messages
        self.start_message_polling()
        
        # Update peers list for this channel
        self.client.current_channel = channel_id
        
        # Request the list of users in this channel
        self.client.get_channel_users(channel_id)
        
        # Update peers list with any existing data we have
        self.update_peers_list()
    
    def create_channel(self):
        if not self.client.authenticated:
            messagebox.showerror("Error", "You must be logged in to create channels")
            return
        
        channel_name = simpledialog.askstring("Create Channel", "Enter channel name:")
        if channel_name:
            is_public = messagebox.askyesno("Channel Type", "Make this channel public?")
            log_connection(f"Creating channel: {channel_name} (Public: {is_public})")
            self.client.create_channel(channel_name, is_public)
    
    def start_message_polling(self):
        """Start periodic polling for new messages"""
        if self.client.current_channel:
            log_connection(f"Starting message polling for channel {self.client.current_channel}")
            self.poll_messages()
            # Reduce polling frequency since we now have server push notifications
            self.update_interval = 3000  # 3 seconds should be sufficient as a backup
            self.update_job = self.root.after(self.update_interval, self.start_message_polling)

    def stop_message_polling(self):
        """Stop periodic polling for new messages"""
        log_connection("Stopping message polling")
        if self.update_job:
            self.root.after_cancel(self.update_job)
            self.update_job = None

    def poll_messages(self):
        """Poll for new messages in the current channel."""
        if not self.client.current_channel:
            return
        
        log_connection(f"Polling messages for channel {self.client.current_channel}")
        channel_id = self.client.current_channel
        
        # Retry limit
        retry_limit = 3
        retries = 0
        
        while retries < retry_limit:
            success = self.client.get_messages(channel_id)
            if success:
                break
            retries += 1
            time.sleep(1)  # Wait before retrying
        
        if retries == retry_limit:
            log_connection(f"Failed to poll messages for channel {channel_id} after {retry_limit} retries")

    def update_messages(self, messages):
        """Update the UI with new messages, including support for images."""
        if not messages:
            log_connection("Received empty messages list")
            return
        
        try:
            log_connection(f"Updating UI with {len(messages)} messages")
            
            # Only update if there are new messages to avoid UI flicker
            if len(messages) != self.last_message_count:
                self.last_message_count = len(messages)
                
                # Clear existing messages
                for widget in self.messages_inner.winfo_children():
                    widget.destroy()
                
                # Store messages temporarily for sending new ones - with safer initialization
                if not hasattr(self.client, '_temp_messages'):
                    self.client._temp_messages = []
                self.client._temp_messages = messages
                
                # Create a container to store PhotoImage references to prevent garbage collection
                if not hasattr(self, '_image_references'):
                    self._image_references = []
                else:
                    self._image_references.clear()
                
                # Add messages to the chat area
                for msg in messages:
                    message_frame = ttk.Frame(self.messages_inner, style='TFrame')
                    message_frame.pack(fill=tk.X, pady=5, padx=5, anchor=tk.W)
                    
                    sender = msg.get('sender', 'Unknown')
                    content = msg.get('content', '')
                    timestamp = msg.get('timestamp', 0)
                    is_offline = msg.get('offline', False)
                    
                    # Format timestamp
                    time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%I:%M %p')
                    
                    # Show sender with offline indicator if needed
                    sender_text = f"{sender}{' (sent offline)' if is_offline else ''}"
                    sender_label = ttk.Label(message_frame, text=sender_text, 
                                          foreground="#7289da", font=("Arial", 10, "bold"))
                    sender_label.pack(anchor=tk.W)
                    
                    time_label = ttk.Label(message_frame, text=time_str, 
                                         foreground="#b9bbbe", font=("Arial", 8))
                    time_label.pack(anchor=tk.W)
                    
                    # Check if the content is an icon
                    if content in ["😀", "😂", "😍", "😎", "😢", "😡", "👍", "👎", "🎉", "❤️", "🔥", "✨", "🎁", "🎶", "📚", "📷", "💻", "📱"]:
                    # Display icon with a larger font size and centered
                        icon_label = ttk.Label(message_frame, text=content, 
                                           font=("Arial", 20), foreground="#ffffff", background="#40444b")
                        icon_label.pack(anchor=tk.W, pady=(5, 0))
                    
                    # Check content structure and log it for debugging
                    log_connection(f"Message content type: {type(content)}")
                    if isinstance(content, dict):
                        log_connection(f"Message content keys: {content.keys()}") 
                        
                    # Check if content itself is a dict and has file_type (direct message format)
                    if isinstance(content, dict) and 'file_type' in content:
                        file_type = content.get('file_type')
                        file_name = content.get('file_name', 'unknown')
                        file_data = content.get('file_data', '')
                        
                        # Show file info
                        file_info = ttk.Label(message_frame, text=f"Shared file: {file_name}",
                                           foreground="#000000")
                        file_info.pack(anchor=tk.W, pady=(2, 0))
                        
                        # For images, try to display them
                        if file_type == 'image' and file_data:
                            log_connection(f"Found image in message: {file_name}")
                            self._display_image(message_frame, file_data, file_info)
                    
                    # Regular text message
                    elif isinstance(content, str):
                        content_label = ttk.Label(message_frame, text=content, 
                                              wraplength=500, foreground="#ffffff", background="#40444b")
                        content_label.pack(anchor=tk.W, pady=(2, 0))
                    
                    # Handle case where the message itself might have file data
                    elif isinstance(msg, dict) and 'file_type' in msg:
                        file_type = msg.get('file_type')
                        file_name = msg.get('file_name', 'unknown')
                        file_data = msg.get('file_data', '')
                        
                        # Show file info
                        file_info = ttk.Label(message_frame, text=f"Shared file: {file_name}",
                                           foreground="#000000")
                        file_info.pack(anchor=tk.W, pady=(2, 0))
                        
                        # For images, try to display them
                        if file_type == 'image' and file_data:
                            log_connection(f"Found image in message object: {file_name}")
                            self._display_image(message_frame, file_data, file_info)
                    else:
                        # Fallback for any other type of content
                        content_str = str(content)
                        content_label = ttk.Label(message_frame, text=content_str, 
                                              wraplength=500, foreground="#000000")
                        content_label.pack(anchor=tk.W, pady=(2, 0))
                
                # Scroll to bottom            
                self.messages_canvas.update_idletasks()
                self.messages_canvas.yview_moveto(1.0)
        except Exception as e:
            log_connection(f"Error updating messages: {str(e)}")

    def _display_image(self, message_frame, file_data, file_info):
        """Helper function to display an image from base64 data."""
        try:
            import base64
            from io import BytesIO
            
            # Decode image data
            log_connection(f"Decoding image data of length: {len(file_data)}")
            image_data = base64.b64decode(file_data)
            
            # Create a BytesIO object and open with PIL
            img_io = BytesIO(image_data)
            image = Image.open(img_io)
            
            # Log image details for debugging
            log_connection(f"Successfully decoded image: {image.format}, {image.size}, {image.mode}")
            
            # Resize if too large
            max_width = 300
            if image.width > max_width:
                ratio = max_width / image.width
                new_height = int(image.height * ratio)
                image = image.resize((max_width, new_height), Image.Resampling.LANCZOS)
                log_connection(f"Resized image to: {image.width}x{new_height}")
            
            # Convert to Tkinter image
            tk_image = ImageTk.PhotoImage(image=image)
            
            # Store reference to prevent garbage collection
            self._image_references.append(tk_image)
            
            # Display image
            image_label = ttk.Label(message_frame, image=tk_image)
            image_label.image = tk_image  # Keep additional reference
            image_label.pack(anchor=tk.W, pady=(5, 0))
            
            log_connection("Image displayed successfully")
        except Exception as e:
            log_connection(f"Error displaying image: {str(e)}")
            error_label = ttk.Label(message_frame, 
                                 text=f"Error displaying image: {str(e)}",
                                 foreground="#ff0000")
            error_label.pack(anchor=tk.W, pady=(2, 0))

    def upload_file(self):
        """Handle file upload and sharing."""
        if not self.client.current_channel:
            messagebox.showerror("Error", "Please join a channel first")
            return
        
        # Only allow authenticated users to upload files
        if not self.client.authenticated:
            messagebox.showerror("Error", "You must be logged in to share files")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select Image to Share",
            filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.gif")]
        )
        
        if not file_path:
            return
            
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > 5 * 1024 * 1024:  # 5MB limit
            messagebox.showerror("Error", "File is too large (max 5MB)")
            return
            
        # Show loading indicator
        self.upload_btn.config(state="disabled", text="Uploading...")
        
        # Process in a separate thread to avoid freezing UI
        def process_upload():
            try:
                # Validate the image file
                try:
                    img = Image.open(file_path)
                    img.verify()  # Verify it's a valid image
                    
                    # Re-open because verify closes the file
                    img = Image.open(file_path)
                    
                    # Resize if too large to reduce file size
                    max_size = (800, 800)
                    if img.width > max_size[0] or img.height > max_size[1]:
                        img.thumbnail(max_size, Image.Resampling.LANCZOS)
                        
                    # Save to a temporary BytesIO object
                    from io import BytesIO
                    img_byte_arr = BytesIO()
                    save_format = img.format if img.format else "JPEG"
                    img.save(img_byte_arr, format=save_format)
                    img_byte_arr.seek(0)
                    img_data = img_byte_arr.read()
                    
                    # Log image details for debugging
                    #log_connection(f"Processing image: {img.format}, {img.size}, {img.mode}")
                    
                except Exception as e:
                    log_connection(f"Error processing image: {str(e)}")
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Invalid image file: {str(e)}"))
                    self.root.after(0, lambda: self.upload_btn.config(state="normal", text="Upload"))
                    return
                
                # Encode the image data
                import base64
                file_data = base64.b64encode(img_data).decode('utf-8')
                
                filename = os.path.basename(file_path)
                
                # Log upload attempt with more detailed info
                #log_connection(f"Uploading image: {filename} ({len(file_data)} bytes encoded)")
                
                # Send as a special message type with more explicit structure
                message_data = {
                    "file_type": "image",
                    "file_data": file_data,
                    "file_name": filename,
                    "image_format": save_format,
                    "image_width": img.width,
                    "image_height": img.height
                }
                
                # Send the message to the server
                success = self.client.send_message(self.client.current_channel, message_data)
                
                if success:
                    log_connection(f"Image upload successful: {filename}")
                    # Force a refresh of the messages to ensure our image appears
                    self.client.get_messages(self.client.current_channel)
                    self.root.after(0, lambda: self.update_messages(self.client._temp_messages))
                else:
                    #log_connection(f"Image upload failed: {filename}")
                    self.root.after(0, lambda: messagebox.showerror("Error", "Failed to send image. The server may have rejected it."))
                
                # Re-enable the upload button
                self.root.after(0, lambda: self.upload_btn.config(state="normal", text="Upload"))
                
            except Exception as e:
                log_connection(f"Error in file upload: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to upload file: {str(e)}"))
                self.root.after(0, lambda: self.upload_btn.config(state="normal", text="Upload"))
        
        # Start the upload process in a background thread
        threading.Thread(target=process_upload, daemon=True).start()

    def update_online_status(self, is_online, username=None):
        """Update UI based on online status events."""
        if username:
            self.online_users[username] = is_online
            if is_online:
                self.show_info_message(f"{username} is now online")
            else:
                self.show_info_message(f"{username} went offline")
    
    def update_host_status(self, channel_id, is_online):
        """Update UI when channel host status changes."""
        self.channel_hosts[channel_id] = is_online
        
        # Update UI if this is the current channel
        if self.client.current_channel == channel_id:
            if is_online:
                self.host_status_canvas.itemconfig(self.host_indicator, fill="green")
                self.host_label.config(text="Host Online")
            else:
                self.host_status_canvas.itemconfig(self.host_indicator, fill="red")
                self.host_label.config(text="Host Offline")
            
            self.show_info_message(f"Channel host is {'online' if is_online else 'offline'}")
    
    def handle_peer_content(self, channel_id, content, source):
        """Handles content updates from peers (called by background thread)."""
        # Schedule the UI update on the main thread
        self.root.after(0, lambda: self._update_ui_peer_content(channel_id, content, source))

    def _update_ui_peer_content(self, channel_id, content, source):
        """Updates the UI with peer content (runs on main thread)."""
        # Update UI with new content - Assuming update_messages is safe or handles its own scheduling
        # If update_messages directly manipulates UI heavily, it might also need scheduling,
        # but let's assume it's designed to handle list updates safely for now.
        self.update_messages(content) # Check if this needs scheduling too

        # Update connection indicator
        source_type = source.split(':', 1)[0]
        source_name = source.split(':', 1)[1]

        if source_type == 'host':
            self.connection_type.config(text=f"Host ({source_name})", foreground="#00ff00")
        elif source_type == 'peer':
            self.connection_type.config(text=f"Peer ({source_name})", foreground="#00ff00")

    def handle_peer_status(self, channel_id, username, online, is_host=False):
        """Handles peer status updates (called by background thread)."""
        # Schedule the UI update on the main thread
        self.root.after(0, lambda: self._update_ui_peer_status(channel_id, username, online, is_host))

    def _update_ui_peer_status(self, channel_id, username, online, is_host=False):
        """Updates the UI with peer status (runs on main thread)."""
        if channel_id not in self.online_peers:
            self.online_peers[channel_id] = {}

        # Update peer status (data structure update is safe)
        self.online_peers[channel_id][username] = {
            'online': online,
            'is_host': is_host
        }

        # Update UI if this is the current channel
        if self.client.current_channel == channel_id:
            self.update_peers_list() # Assumes this UI update is safe

            # Show notification
            status = "online" if online else "offline"
            role = " (host)" if is_host else ""
            # Don't show notifications for self
            if username != self.client.username:
                self.show_info_message(f"{username}{role} is now {status}") # Assumes this UI update is safe
    
    def update_channel_users(self, channel_id, users, event=None, username=None):
        """Handle channel users updates and notifications."""
        # Only update UI if this is the current channel
        if channel_id != self.client.current_channel:
            return
        
        # Update peers list
        self.update_peers_list()
        
        # Show notification for join/leave events
        if event == 'join' and username:
            # Don't notify about our own join
            if username != self.client.username:
                self.show_info_message(f"{username} joined the channel")
        elif event == 'leave' and username:
            # Don't notify about our own leave
            if username != self.client.username:
                self.show_info_message(f"{username} left the channel")
    
    def update_peers_list(self):
        """Update the list of online peers in the UI based on server data."""
        for widget in self.peers_frame.winfo_children():
            widget.destroy()

        channel_id = self.client.current_channel
        if not channel_id:
            return

        current_channel_users = self.client.channel_users.get(channel_id, [])

        log_connection(f"Updating peers list for {channel_id}. Server reports users: {current_channel_users}")

        displayed_count = 0
        for username in current_channel_users:
            # Determine if the user is the host (only reliably known for self)
            is_host = False
            if username == self.client.username and self.client.is_channel_host.get(channel_id, False):
                 is_host = True

            if username == self.client.username:
                # Display self with appropriate indicator
                label_text = f"👤 {username} (You)"
                if is_host:
                    label_text = f"👑 {username} (You, Host)"
                    label_color = "#ffd700" # Gold for host
                else:
                    label_color = "#7289da" # Special color for self
            else:
                    label_text = f"👤 {username}"
                    label_color = "#ffffff" # Default white for others

            peer_label = ttk.Label(self.peers_frame, text=label_text, foreground=label_color)
            peer_label.pack(fill=tk.X, padx=5, pady=2)
            displayed_count += 1

        if displayed_count == 0:
             no_peers_label = ttk.Label(self.peers_frame, text="No users in channel", foreground="#999999")
             no_peers_label.pack(fill=tk.X, padx=5, pady=2)

        log_connection(f"Displayed {displayed_count} users in peers list.")
    
    def view_livestream(self):
        """View a livestream for the current channel."""
        if not self.client.current_channel:
            messagebox.showerror("Error", "Please join a channel first")
            return
        
        if hasattr(self.client, 'get_active_streams'):
            if not self.client.get_active_streams(self.client.current_channel):
                 # Show error if sending the request failed immediately (e.g., not connected)
                 self.show_error("Failed to send request for active streams.")
        else:
             self.show_error("Client does not support getting active streams.")
    
    def update_active_streams(self, channel_id, streams):
        """Handle active streams information received from the server."""
        # Ensure this runs on the main thread if called from background
        log_connection(f"Received streams update for channel {channel_id}: {streams}")

        if channel_id != self.client.current_channel:
             log_connection("Received stream info for a different channel, ignoring.")
             return # Ignore if not for the current channel

        if self.livestream_client and self.livestream_client.streaming:
            is_own_stream = False
            if streams and self.livestream_client.host_port:
                for stream in streams:
                    if stream.get('livestream_port') == self.livestream_client.host_port:
                         is_own_stream = True
                         break
            if is_own_stream:
                log_connection("Stream update is for own hosted stream. Ignoring for auto-view.")
                return
            else:
                 log_connection("Stream update is for another host while we are hosting. Ignoring for auto-view.")
                 return

        if not streams:
            messagebox.showinfo("No Streams", "No active streams found for this channel.", parent=self.root)
            return
        
        # Now, launch the window based on the received streams
        try:
            if len(streams) == 1:
                # Single stream - show directly
                stream = streams[0]
                host_ip = stream.get('host_ip', 'localhost') # Use localhost as fallback? Or show error?
                host_port = stream.get('livestream_port')
                username = stream.get('username', 'Unknown')
                if not host_port:
                     messagebox.showerror("Stream Error", f"Stream data from {username} is missing port information.", parent=self.root)
                     return
                
                log_connection(f"Opening single stream from {username} at {host_ip}:{host_port}")
                LivestreamWindow(self.root, self.livestream_client, channel_id, (host_ip, host_port))
            else:
                # Multiple streams - create window that can show all of them
                # NOTE: The current LivestreamWindow might not fully support multiple simultaneous views easily.
                # This part might need significant rework in LivestreamWindow itself.
                # For now, let's just open the first one as an example.
                messagebox.showinfo("Multiple Streams", "Multiple streams found. Displaying the first one.", parent=self.root)
                stream = streams[0]
                host_ip = stream.get('host_ip', 'localhost')
                host_port = stream.get('livestream_port')
                username = stream.get('username', 'Unknown')
                if not host_port:
                     messagebox.showerror("Stream Error", f"Stream data from {username} is missing port information.", parent=self.root)
                     return

                log_connection(f"Opening first stream from {username} at {host_ip}:{host_port}")
                LivestreamWindow(self.root, self.livestream_client, channel_id, (host_ip, host_port))

                # Proper multi-stream handling would require changes in LivestreamWindow:
                # window = LivestreamWindow(self.root, self.livestream_client, channel_id) # Create empty window
                # for stream in streams:
                #     host_ip = stream.get('host_ip', 'localhost')
                #     host_port = stream.get('livestream_port')
                #     username = stream.get('username', 'Unknown')
                #     if host_port:
                #         log_connection(f"Adding stream view for {username} at {host_ip}:{host_port}")
                #         window.add_stream_view(username, host_ip, host_port) # This method needs robust implementation
        except Exception as e:
             log_connection(f"Error launching livestream window: {e}")
             traceback.print_exc()
             self.show_error(f"Failed to display livestream: {e}")
    
    def show_info_message(self, message):
        """Show system message in the chat."""
        info_frame = ttk.Frame(self.messages_inner, style='TFrame')
        info_frame.pack(fill=tk.X, pady=5, padx=5)
        
        time_str = datetime.datetime.now().strftime('%I:%M %p')
        
        info_label = ttk.Label(info_frame, text=f"[{time_str}] {message}", 
                             foreground="#bbbbbb", font=("Arial", 9, "italic"))
        info_label.pack(anchor=tk.CENTER)
        
        # Scroll to bottom            
        self.messages_canvas.update_idletasks()
        self.messages_canvas.yview_moveto(1.0)
    
    def reconnect(self):
        """Manually attempt to reconnect to server."""
        if not self.client.connected:
            self.status_var.set("Reconnecting...")
            threading.Thread(target=self.client.connect, daemon=True).start()
    
    def send_message_event(self, event):
        if not event.state & 0x1:  # Check if Shift key is not pressed
            self.send_message()
            return "break"  # Prevent default behavior (newline)
    
    def send_message(self):
        if not self.client.current_channel:
            messagebox.showerror("Error", "Please join a channel first")
            return
        
        # Prevent visitors from sending messages
        if not self.client.authenticated or (
            self.client.username and self.client.username.startswith("anonymous_")
        ):
            messagebox.showerror("Error", "Visitors are not allowed to send messages")
            return

        content = self.message_entry.get("1.0", tk.END).strip()
        if not content:
            return
        
        log_connection(f"Sending message in channel {self.client.current_channel}")
        self.client.send_message(self.client.current_channel, content)
        self.message_entry.delete("1.0", tk.END)
    
    def show_error(self, message):
        log_connection(f"Error: {message}")
        messagebox.showerror("Error", message)
    
    def start_livestream(self):
        """Start a livestream for the current channel."""
        if not self.client.current_channel:
            messagebox.showerror("Error", "Please join a channel first")
            return
        
        if not self.client.authenticated:
            messagebox.showerror("Error", "You must be logged in to start a livestream")
            return
        
        # Set username for the livestream
        self.livestream_client.username = self.client.username
        
        # Create livestream window
        LivestreamWindow(self.root, self.livestream_client, self.client.current_channel)

    def on_closing(self):
        """Handle window close event."""
        log_connection("Chat application closing")
        self.stop_message_polling()
        
        # Safely close livestream resources
        try:
            self.livestream_client.cleanup()
        except Exception as e:
            log_connection(f"Error cleaning up livestream: {str(e)}")
            
        # Make sure peer connections are closed
        if hasattr(self.client, 'peer_manager'):
            self.client.peer_manager.shutdown()
        
        # Leave current channel if we're in one
        if hasattr(self.client, 'current_channel') and self.client.current_channel:
            try:
                self.client.leave_channel(self.client.current_channel)
            except:
                pass
        
        # Disconnect from server
        try:
            self.client.disconnect()
        except:
            pass
            
        self.root.destroy()

def main():
    # --- Add argument parsing ---
    parser = argparse.ArgumentParser(description="SegmentChat Client")
    parser.add_argument('--host', type=str, default='localhost',
                        help='The IP address of the server to connect to.')
    args = parser.parse_args()
    # --- End argument parsing ---

    root = tk.Tk()
    app = ChatApp(root, host=args.host) # Pass host to ChatApp
    root.mainloop()

if __name__ == "__main__":
    main()