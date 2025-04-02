import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import threading
import time
import datetime
import os
from PIL import Image, ImageTk
from client import ChatClient
from utils import log_connection
from livestream import LivestreamClient, LivestreamWindow

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SegmentChat")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Configure style with black text for better readability
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#36393f')
        self.style.configure('TLabel', background='#36393f', foreground='#000000')
        
        # Enhanced button styles with more contrast and visibility
        self.style.configure('TButton', 
                          background='#7289da', 
                          foreground='#000000',
                          font=('Arial', 10, 'bold'),
                          padding=6)
        
        self.style.configure('Channel.TButton', 
                          background='#2f3136', 
                          foreground='#000000',
                          font=('Arial', 10),
                          padding=8)
        
        # Create a distinct style for important buttons
        self.style.configure('Action.TButton', 
                          background='#5865f2',
                          foreground='#000000',
                          font=('Arial', 10, 'bold'),
                          padding=6)
        
        # Add hover-like effect for buttons
        self.style.map('Channel.TButton',
                    foreground=[('active', '#ffffff'), ('pressed', '#ffffff')],
                    background=[('active', '#393c43'), ('pressed', '#393c43')])
        
        self.style.map('TButton',
                    foreground=[('active', '#ffffff'), ('pressed', '#ffffff')],
                    background=[('active', '#5865f2'), ('pressed', '#5865f2')])
        
        # Real-time updates
        self.update_interval = 1000  # Update every 1 second (1000ms)
        self.update_job = None
        self.last_message_count = 0
        
        # Initialize client
        self.client = ChatClient()
        self.client.set_message_callback(self.update_messages)
        self.client.set_channels_callback(self.update_channels)
        self.client.set_connection_callback(self.update_connection_status)
        self.client.set_auth_callback(self.update_auth_status)
        self.client.set_error_callback(self.show_error)
        self.client.set_online_status_callback(self.update_online_status)
        self.client.set_host_status_callback(self.update_host_status)
        self.client.set_peer_content_callback(self.update_peer_content)
        self.client.set_peer_status_callback(self.update_peer_status)
        self.client.set_channel_users_callback(self.update_channel_users)
        
        # Initialize livestream client with server connection
        self.livestream_client = LivestreamClient()
        self.livestream_client.set_server_client(self.client)
        
        # Add callback for active streams
        self.client.set_active_streams_callback(self.update_active_streams)
        
        # Network status tracking
        self.online_users = {}  # Track online users
        self.channel_hosts = {}  # Track channel host status
        self.online_peers = {}  # {channel_id: {username: status}}
        
        # Create main frames
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.login_frame = ttk.Frame(self.main_frame, padding=20)
        self.chat_frame = ttk.Frame(self.main_frame)
        
        # Initialize login UI
        self.setup_login_ui()
        
        # Initialize chat UI
        self.setup_chat_ui()
        
        # Show login frame by default
        self.show_login_frame()
        
        # Connection status
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(root, textvariable=self.status_var, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
        
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
        self.reconnect_btn = ttk.Button(self.connection_frame, text="Reconnect", 
                                      command=self.reconnect, width=10)
        self.reconnect_btn.pack(side=tk.RIGHT, padx=10)
    
    def setup_login_ui(self):
        ttk.Label(self.login_frame, text="SegmentChat", font=("Arial", 24)).pack(pady=20)
        
        ttk.Label(self.login_frame, text="Username").pack(pady=(10, 2))
        self.username_entry = ttk.Entry(self.login_frame, width=30)
        self.username_entry.pack(pady=(0, 10))
        
        ttk.Label(self.login_frame, text="Password").pack(pady=(10, 2))
        self.password_entry = ttk.Entry(self.login_frame, width=30, show="*")
        self.password_entry.pack(pady=(0, 10))
        
        btn_frame = ttk.Frame(self.login_frame)
        btn_frame.pack(pady=20)
        
        self.login_btn = ttk.Button(btn_frame, text="Login", command=self.login)
        self.login_btn.pack(side=tk.LEFT, padx=5)
        
        self.register_btn = ttk.Button(btn_frame, text="Register", command=self.register)
        self.register_btn.pack(side=tk.LEFT, padx=5)
        
        self.visitor_btn = ttk.Button(self.login_frame, text="Continue as Visitor", command=self.continue_as_visitor)
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
        
        self.user_label = ttk.Label(self.user_frame, text="Visitor Mode", font=("Arial", 10, "bold"))
        self.user_label.pack(side=tk.LEFT, padx=5)
        
        self.logout_btn = ttk.Button(self.user_frame, text="Logout", width=8, command=self.logout)
        self.logout_btn.pack(side=tk.RIGHT, padx=5)
        
        # Sidebar - Channels
        ttk.Label(self.sidebar, text="CHANNELS", font=("Arial", 9, "bold")).pack(fill=tk.X, padx=10, pady=(10, 5), anchor=tk.W)
        
        self.channels_frame = ttk.Frame(self.sidebar, style='TFrame')
        self.channels_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.create_channel_btn = ttk.Button(self.sidebar, text="+ Create Channel", 
                                           command=self.create_channel, style='Action.TButton')
        self.create_channel_btn.pack(fill=tk.X, padx=5, pady=5)
        
        # Add peer status frame to sidebar
        ttk.Label(self.sidebar, text="ONLINE PEERS", font=("Arial", 9, "bold")).pack(
            fill=tk.X, padx=10, pady=(10, 5), anchor=tk.W)
        
        self.peers_frame = ttk.Frame(self.sidebar, style='TFrame')
        self.peers_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        # Content area - Channel name
        self.channel_header = ttk.Frame(self.content, style='TFrame', height=50)
        self.channel_header.pack(fill=tk.X)
        self.channel_header.pack_propagate(False)
        
        self.channel_name = ttk.Label(self.channel_header, text="# welcome", font=("Arial", 14, "bold"))
        self.channel_name.pack(side=tk.LEFT, padx=15, pady=10)
        
        # Add host status indicator in channel header
        self.host_status_frame = ttk.Frame(self.channel_header)
        self.host_status_frame.pack(side=tk.RIGHT, padx=10)
        
        self.host_status_canvas = tk.Canvas(self.host_status_frame, width=12, height=12, 
                                         bg="#36393f", highlightthickness=0)
        self.host_status_canvas.pack(side=tk.LEFT, padx=2)
        self.host_indicator = self.host_status_canvas.create_oval(2, 2, 10, 10, fill="gray")
        
        self.host_label = ttk.Label(self.host_status_frame, text="No host", foreground="#ffffff")
        self.host_label.pack(side=tk.LEFT, padx=2)
        
        # Add host/connection status indicator in channel header
        self.connection_frame = ttk.Frame(self.channel_header)
        self.connection_frame.pack(side=tk.RIGHT, padx=10)
        
        self.connection_label = ttk.Label(self.connection_frame, text="Connection: ", foreground="#ffffff")
        self.connection_label.pack(side=tk.LEFT)
        
        self.connection_type = ttk.Label(self.connection_frame, text="Server", foreground="#ffffff")
        self.connection_type.pack(side=tk.LEFT, padx=5)
        
        # Add livestream buttons in channel header
        self.stream_btn = ttk.Button(self.channel_header, text="Start Stream", 
                                   command=self.start_livestream)
        self.stream_btn.pack(side=tk.RIGHT, padx=10)
        
        self.view_stream_btn = ttk.Button(self.channel_header, text="View Stream", 
                                        command=self.view_livestream)
        self.view_stream_btn.pack(side=tk.RIGHT, padx=10)
        
        # Content area - Messages
        self.messages_frame = ttk.Frame(self.content, style='TFrame')
        self.messages_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.messages_canvas = tk.Canvas(self.messages_frame, bg="#36393f", highlightthickness=0)
        self.messages_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.scrollbar = ttk.Scrollbar(self.messages_frame, orient=tk.VERTICAL, command=self.messages_canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.messages_canvas.configure(yscrollcommand=self.scrollbar.set)
        self.messages_inner = ttk.Frame(self.messages_canvas, style='TFrame')
        self.messages_window = self.messages_canvas.create_window((0, 0), window=self.messages_inner, anchor=tk.NW)
        
        # Content area - Message input
        self.message_input_frame = ttk.Frame(self.content, style='TFrame', height=80)
        self.message_input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.message_entry = tk.Text(self.message_input_frame, height=3, bg="#ffffff", fg="#000000", 
                                     insertbackground="black", relief=tk.FLAT, font=("Arial", 10))
        self.message_entry.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=(0, 10))
        self.message_entry.bind("<Return>", self.send_message_event)
        
        self.send_btn = ttk.Button(self.message_input_frame, text="Send", 
                                  command=self.send_message, style='Action.TButton')
        self.send_btn.pack(side=tk.RIGHT, padx=5)
        
        # Add file upload button next to send button
        self.upload_btn = ttk.Button(self.message_input_frame, text="Upload", 
                                   command=self.upload_file, style='TButton')
        self.upload_btn.pack(side=tk.RIGHT, padx=5)
        
        # Configure canvas scrolling    
        self.messages_inner.bind("<Configure>", self.on_frame_configure)
        self.messages_canvas.bind("<Configure>", self.on_canvas_configure)
        self.messages_canvas.bind_all("<MouseWheel>", self.on_mousewheel)
    
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
        
        # Initialize offline storage after login
        if self.client.authenticated:
            self.client.initialize_offline_storage()
    
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
        self.show_chat_frame()
        self.user_label.config(text="Visitor Mode")
        # Disable message entry for visitors
        self.message_entry.config(state="disabled")
        self.send_btn.config(state="disabled")
        # Clear message entry
        self.message_entry.delete("1.0", tk.END)
    
    def logout(self):
        log_connection("User logging out")
        self.stop_message_polling()
        self.client.logout()
        self.show_login_frame()
    
    def update_connection_status(self, is_connected):
        """Update connection status UI."""
        if is_connected:
            self.status_var.set("Connected to server")
            self.status_canvas.itemconfig(self.status_indicator, fill="green")
            log_connection("Connected to server")
        else:
            self.status_var.set("Disconnected from server")
            self.status_canvas.itemconfig(self.status_indicator, fill="red")
            log_connection("Disconnected from server")
    
    def update_auth_status(self, success, message):
        if success:
            if message == "Registration successful":
                log_connection("User registration successful")
                messagebox.showinfo("Success", "Registration successful! You can now login.")
            else:
                log_connection(f"User logged in: {self.client.username}")
                self.show_chat_frame()
                self.user_label.config(text=f"Logged in as: {self.client.username}")
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
    
    def join_channel(self, channel_id):
        log_connection(f"Joining channel: {channel_id}")
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
            self.update_job = self.root.after(self.update_interval, self.start_message_polling)

    def stop_message_polling(self):
        """Stop periodic polling for new messages"""
        log_connection("Stopping message polling")
        if self.update_job:
            self.root.after_cancel(self.update_job)
            self.update_job = None

    def poll_messages(self):
        """Poll for new messages in the current channel"""
        if not self.client.current_channel:
            return
        
        log_connection(f"Polling messages for channel {self.client.current_channel}")
        
        # Make sure we're fetching for the correct current channel
        channel_id = self.client.current_channel
        
        # Clear previous update job to avoid race conditions
        if self.update_job:
            self.root.after_cancel(self.update_job)
            self.update_job = None
        
        # Request messages from the server
        success = self.client.get_messages(channel_id)
        if not success:
            log_connection(f"Failed to request messages for channel {channel_id}")
            
            # Try again in a moment if still connected
            if self.client.connected:
                self.update_job = self.root.after(self.update_interval, self.start_message_polling)

    def update_messages(self, messages):
        """Update the UI with new messages, including support for images."""
        if not messages:
            log_connection("Received empty messages list")
            return
            
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
                                      foreground="#0000ff", font=("Arial", 10, "bold"))
                sender_label.pack(anchor=tk.W)
                
                time_label = ttk.Label(message_frame, text=time_str, 
                                     foreground="#000000", font=("Arial", 8))
                time_label.pack(anchor=tk.W)
                
                # Check if this is a file message
                if isinstance(content, dict) and 'file_type' in content:
                    file_type = content.get('file_type')
                    file_name = content.get('file_name', 'unknown')
                    
                    # Show file info
                    file_info = ttk.Label(message_frame, text=f"Shared file: {file_name}",
                                       foreground="#000000")
                    file_info.pack(anchor=tk.W, pady=(2, 0))
                    
                    # For images, try to display them
                    if file_type == 'image' and 'file_data' in content:
                        try:
                            import base64
                            from io import BytesIO
                            
                            # Decode image data
                            image_data = base64.b64decode(content['file_data'])
                            image = Image.open(BytesIO(image_data))
                            
                            # Resize if too large
                            max_width = 300
                            if image.width > max_width:
                                ratio = max_width / image.width
                                new_height = int(image.height * ratio)
                                image = image.resize((max_width, new_height))
                                
                            # Convert to Tkinter image
                            tk_image = ImageTk.PhotoImage(image)
                            
                            # Store reference to prevent garbage collection
                            setattr(file_info, 'image', tk_image)
                            
                            # Display image
                            image_label = ttk.Label(message_frame, image=tk_image)
                            image_label.pack(anchor=tk.W, pady=(5, 0))
                        except Exception as e:
                            error_label = ttk.Label(message_frame, 
                                                 text=f"Error displaying image: {str(e)}",
                                                 foreground="#ff0000")
                            error_label.pack(anchor=tk.W, pady=(2, 0))
                else:
                    # Regular text message
                    content_label = ttk.Label(message_frame, text=content, 
                                           wraplength=500, foreground="#000000")
                    content_label.pack(anchor=tk.W, pady=(2, 0))
            
            # Scroll to bottom            
            self.messages_canvas.update_idletasks()
            self.messages_canvas.yview_moveto(1.0)
    
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
    
    def update_peer_content(self, content, source):
        """Handle content updates from peers."""
        # Update UI with new content
        self.update_messages(content)
        
        # Update connection indicator
        source_type = source.split(':', 1)[0]
        source_name = source.split(':', 1)[1]
        
        if source_type == 'host':
            self.connection_type.config(text=f"Host ({source_name})", foreground="#00ff00")
        elif source_type == 'peer':
            self.connection_type.config(text=f"Peer ({source_name})", foreground="#00ff00")
    
    def update_peer_status(self, channel_id, username, online, is_host=False):
        """Handle peer status updates."""
        if channel_id not in self.online_peers:
            self.online_peers[channel_id] = {}
        
        # Update peer status
        self.online_peers[channel_id][username] = {
            'online': online,
            'is_host': is_host
        }
        
        # Update UI if this is the current channel
        if self.client.current_channel == channel_id:
            self.update_peers_list()
            
            # Show notification
            status = "online" if online else "offline"
            role = "host" if is_host else "peer"
            self.show_info_message(f"{username} ({role}) is now {status}")
    
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
        """Update the list of online peers in the UI."""
        # Clear current list
        for widget in self.peers_frame.winfo_children():
            widget.destroy()
        
        # Get peers for current channel
        channel_id = self.client.current_channel
        if not channel_id:
            return
        
        peers = []
        
        # Get users from channel_users tracking
        if channel_id in self.client.channel_users:
            channel_users = self.client.channel_users[channel_id]
            for username in channel_users:
                # Skip our own username
                if username == self.client.username:
                    continue
                    
                # Check if user is a host
                is_host = False
                if channel_id in self.online_peers and username in self.online_peers[channel_id]:
                    is_host = self.online_peers[channel_id][username].get('is_host', False)
                    
                peers.append({
                    'username': username,
                    'is_host': is_host
                })
        
        # Add ourselves if we're in the channel and authenticated
        if self.client.authenticated and self.client.username:
            # Check if we're the host
            is_host = channel_id in self.client.is_channel_host and self.client.is_channel_host[channel_id]
            
            peers.append({
                'username': self.client.username,
                'is_host': is_host
            })
        
        # Display peers
        if not peers:
            no_peers_label = ttk.Label(self.peers_frame, text="No online peers", foreground="#999999")
            no_peers_label.pack(fill=tk.X, padx=5, pady=2)
        else:
            for peer in peers:
                username = peer['username']
                is_host = peer['is_host']
                
                if is_host:
                    label_text = f"👑 {username} (Host)"
                    label_color = "#ffd700"  # Gold for host
                else:
                    label_text = f"👤 {username}"
                    label_color = "#ffffff"
                    
                peer_label = ttk.Label(self.peers_frame, text=label_text, foreground=label_color)
                peer_label.pack(fill=tk.X, padx=5, pady=2)
    
    def view_livestream(self):
        """View a livestream for the current channel."""
        if not self.client.current_channel:
            messagebox.showerror("Error", "Please join a channel first")
            return
        
        # Query for active streams in this channel
        if hasattr(self.client, 'get_active_streams'):
            self.client.get_active_streams(self.client.current_channel)
        
        # Check if we have livestream information in the client
        if hasattr(self.client, 'livestream_ports') and self.client.current_channel in self.client.livestream_ports:
            # We have a registered livestream port
            host_ip = "localhost"  # Assuming local testing
            host_port = self.client.livestream_ports[self.client.current_channel]
            
            # Create livestream window with host info
            LivestreamWindow(self.root, self.livestream_client, self.client.current_channel, (host_ip, host_port))
        else:
            # No registered livestream, check with server
            cursor = self.client.get_channel_host(self.client.current_channel)
            
            # Log debug info
            print(f"Channel hosts data: {self.client.channel_hosts}")
            
            # For debugging, check peer manager host info
            if hasattr(self.client, 'peer_manager') and hasattr(self.client.peer_manager, 'channel_hosts'):
                peer_host_info = self.client.peer_manager.channel_hosts.get(self.client.current_channel)
                print(f"Peer manager host info: {peer_host_info}")
                
                if peer_host_info and len(peer_host_info) >= 2:
                    host_ip, host_port, is_connected = peer_host_info
                    if is_connected:
                        print(f"Using peer manager host: {host_ip}:{host_port}")
                        # Create livestream window with host info
                        LivestreamWindow(self.root, self.livestream_client, self.client.current_channel, (host_ip, host_port))
                        return
            
            # Last resort - try localhost with default ports
            messagebox.showinfo("Checking for Stream", 
                             "Checking for active stream... Try again in a moment if there is one.")
    
    def update_active_streams(self, channel_id, streams):
        """Handle active streams information from server."""
        if not streams:
            messagebox.showinfo("No Streams", "No active streams found for this channel")
            return
        
        print(f"Received streams information for channel {channel_id}: {streams}")
        
        if len(streams) == 1:
            # Single stream - show directly
            stream = streams[0]
            host_ip = stream.get('host_ip', 'localhost')
            host_port = stream.get('livestream_port', 6000)
            
            print(f"Opening single stream from {host_ip}:{host_port}")
            LivestreamWindow(self.root, self.livestream_client, channel_id, (host_ip, host_port))
        else:
            # Multiple streams - create window that can show all of them
            window = LivestreamWindow(self.root, self.livestream_client, channel_id)
            
            # Add each stream
            for stream in streams:
                host_ip = stream.get('host_ip', 'localhost')
                host_port = stream.get('livestream_port', 6000)
                username = stream.get('username', 'Unknown')
                
                print(f"Adding stream from {username} at {host_ip}:{host_port}")
                window.add_stream_view(username, host_ip, host_port)
    
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
            
        # For images, we'll implement a base64 encoding schema
        # In a real app, you might want to upload to an external service
        try:
            with open(file_path, "rb") as file:
                import base64
                file_data = base64.b64encode(file.read()).decode('utf-8')
                
            filename = os.path.basename(file_path)
            
            # Send as a special message type
            content = f"[Shared image: {filename}]"
            message_data = {
                "content": content,
                "file_type": "image",
                "file_data": file_data,
                "file_name": filename
            }
            
            self.client.send_message(self.client.current_channel, message_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload file: {str(e)}")
    
    def send_message_event(self, event):
        if not event.state & 0x1:  # Check if Shift key is not pressed
            self.send_message()
            return "break"  # Prevent default behavior (newline)
    
    def send_message(self):
        if not self.client.current_channel:
            messagebox.showerror("Error", "Please join a channel first")
            return
        
        # Prevent visitors from sending messages
        if not self.client.authenticated:
            messagebox.showerror("Error", "You must be logged in to send messages")
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
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
