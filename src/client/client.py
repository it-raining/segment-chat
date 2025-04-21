import socket
import json
import threading
import time
import os
import struct
import traceback
import io
from src.client.offline_storage import OfflineStorage
from src.p2p.peer_manager import PeerConnectionManager
from src.common.utils import log_connection

class ChatClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.authenticated = False
        self.username = None
        self.current_channel = None
        self.message_callback = None
        self.channels_callback = None
        self.connection_callback = None
        self.auth_callback = None
        self.error_callback = None
        
        # Network status tracking
        self.online = False  # System online status (can be offline even when socket is connected)
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 2  # seconds
        self.heartbeat_interval = 30  # seconds
        
        # Offline support
        self.offline_storage = None
        self.pending_sync = False
        
        # Channel hosting
        self.hosted_channels = {}  # Channels this client is hosting
        self.channel_hosts = {}    # Known hosts for channels
        
        # Additional callbacks
        self.online_status_callback = None
        self.host_status_callback = None
        
        # Initialize peer manager
        self.peer_manager = PeerConnectionManager()
        self.peer_manager.set_content_callback(self.handle_peer_content)
        self.peer_manager.set_peer_status_callback(self.handle_peer_status)
        self.peer_listener_port = None
        
        # Track current role - host or regular user
        self.is_channel_host = {}  # {channel_id: bool}
        
        # Add callbacks for peer-to-peer communication
        self.peer_content_callback = None
        self.peer_status_callback = None
        
        # Add callback for active streams
        self.active_streams_callback = None
        
        # Initialize empty message storage for current channel
        self._temp_messages = []
        
        # Track users in channels
        self.channel_users = {}  # {channel_id: [usernames]}
        self.channel_users_callback = None

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.online = True
            
            # Initialize offline storage with username if authenticated
            if self.connection_callback:
                self.connection_callback(True)
            if self.authenticated and self.username:
                self.initialize_offline_storage()
                
            # Start listening for responses
            self.listen_thread = threading.Thread(target=self._receive_messages)
            self.listen_thread.daemon = True
            self.listen_thread.start()
            
            # Start heartbeat thread
            self.heartbeat_thread = threading.Thread(target=self._send_heartbeats)
            self.heartbeat_thread.daemon = True
            self.heartbeat_thread.start()
                
            # Try to sync any pending offline messages
            if self.offline_storage:
                self._sync_offline_messages()
                
            # Start peer listener
            if self.connected:
                self.peer_listener_port = self.peer_manager.start_listener()
                
            return True
        except Exception as e:
            self.online = False
            if self.error_callback:
                self.error_callback(f"Connection error: {str(e)}")
            if self.connection_callback:
                self.connection_callback(False)
                    
            # Schedule reconnection attempt
            self._schedule_reconnect()
            return False

    def handle_peer_content(self, channel_id, content, source):
        """Handle content updates from peers."""
        # Update local storage
        if self.offline_storage:
            self.offline_storage.cache_channel_content(channel_id, content)
        
        # Notify UI if this is the current channel
        if channel_id == self.current_channel and self.peer_content_callback:
            self.peer_content_callback(content, source)
    
    def handle_peer_status(self, channel_id, username, online, is_host=False):
        """Handle peer status updates."""
        if self.peer_status_callback:
            self.peer_status_callback(channel_id, username, online, is_host)
    
    def set_message_callback(self, callback):
        """Set callback for receiving messages: callback(messages)"""
        self.message_callback = callback
        
    def set_channels_callback(self, callback):
        """Set callback for receiving channel list: callback(channels)"""
        self.channels_callback = callback
            
    def set_connection_callback(self, callback):
        """Set callback for connection status changes: callback(is_connected)"""
        self.connection_callback = callback
        
    def set_auth_callback(self, callback):
        """Set callback for authentication results: callback(success, message)"""
        self.auth_callback = callback
        
    def set_error_callback(self, callback):
        """Set callback for error messages: callback(error_message)"""
        self.error_callback = callback
        
    def set_online_status_callback(self, callback):
        """Set callback for online status updates: callback(is_online, username)"""
        self.online_status_callback = callback
        
    def set_host_status_callback(self, callback):
        """Set callback for host status updates: callback(channel_id, is_online)"""
        self.host_status_callback = callback
    
    def set_peer_content_callback(self, callback):
        """Set callback for peer content updates: callback(content, source)"""
        self.peer_content_callback = callback
        
    def set_peer_status_callback(self, callback):
        """Set callback for peer status updates: callback(channel_id, username, online, is_host)"""
        self.peer_status_callback = callback
        
    def set_active_streams_callback(self, callback):
        """Set callback for active streams updates: callback(channel_id, streams)"""
        self.active_streams_callback = callback
    
    def set_channel_users_callback(self, callback):
        """Set callback for channel users updates: callback(channel_id, users, event=None, username=None)"""
        self.channel_users_callback = callback

    def _schedule_reconnect(self):
        """Schedule a reconnection attempt with exponential backoff."""
        if hasattr(self, '_reconnect_thread') and self._reconnect_thread.is_alive():
            return  # Avoid multiple reconnection threads
            
        self.reconnect_attempts += 1
        if self.reconnect_attempts > self.max_reconnect_attempts:
            if self.error_callback:
                self.error_callback("Maximum reconnection attempts reached")
            return
        
        delay = self.reconnect_delay * (2 ** (self.reconnect_attempts - 1))
        if self.error_callback:
            self.error_callback(f"Reconnecting in {delay} seconds (attempt {self.reconnect_attempts})")
        
        self._reconnect_thread = threading.Thread(
            target=lambda: (time.sleep(delay), self.connect())
        )
        self._reconnect_thread.daemon = True
        self._reconnect_thread.start()

    def _send_heartbeats(self):
        """Send periodic heartbeats to the server."""
        while self.connected:
            time.sleep(self.heartbeat_interval)
            
            if not self.connected:
                break
                
            # Send heartbeat for hosted channels
            for channel_id in self.hosted_channels:
                self._send_host_heartbeat(channel_id)
                
            # Send general client heartbeat
            try:
                request = {
                    "type": "heartbeat",
                    "username": self.username if self.authenticated else None
                }
                # self.socket.send(json.dumps(request).encode('utf-8'))
                self._send_request(request)
            except:
                # Connection possibly lost
                self._handle_connection_loss()
                break

    def _send_host_heartbeat(self, channel_id):
        """Send a heartbeat to the server for a channel this client is hosting."""
        if not self.connected:
            return
            
        try:
            request = {
                "type": "host_heartbeat",
                "channel_id": channel_id,
                "host_ip": socket.gethostbyname(socket.gethostname()),
                "host_port": 0,  # Not used directly for P2P
                "timestamp": time.time()
            }
            # self.socket.send(json.dumps(request).encode('utf-8'))
            self._send_request(request)
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error sending host heartbeat: {str(e)}")
    def _send_request(self, request_dict):
        """Sends a request dictionary to the server with framing."""
        if not self.connected:
            log_connection("Cannot send request: Not connected.")
            return False
        try:
            if isinstance(request_dict, str):
                 request_dict = json.loads(request_dict)

            message_json = json.dumps(request_dict)
            message_bytes = message_json.encode('utf-8')
            header = struct.pack('>I', len(message_bytes))
            self.socket.sendall(header + message_bytes)
            log_connection(f"Sent framed request '{request_dict.get('type', 'unknown')}' to server")
            return True
        except (BrokenPipeError, ConnectionResetError, socket.error) as e: # Added socket.error
            log_connection(f"Failed to send request (server disconnected?): {e}")
            self._handle_connection_loss() # Use central handler
            return False
        except Exception as e:
            log_connection(f"Error sending request: {e}")
            self._handle_connection_loss() # Assume connection issue
            return False

    def _handle_connection_loss(self):
        """Handle loss of connection to server."""
        if self.connected:
            self.connected = False
            self.online = False
            self.authenticated = False  # Reset authentication state
            self.username = None  # Clear username
            self.current_channel = None # Clear current channel
            self.channel_users = {} # Clear channel users
            
            if self.connection_callback:
                self.connection_callback(False)
                
            if self.online_status_callback:
                self.online_status_callback(False)
                
            # Schedule reconnection
            self._schedule_reconnect()

    def initialize_offline_storage(self):
        """Initialize or update offline storage with current username."""
        username = self.username if self.authenticated else 'anonymous'
        if self.offline_storage:
            self.offline_storage.close()
        self.offline_storage = OfflineStorage(username)

    def _sync_offline_messages(self):
        """Attempt to sync pending offline messages with the server."""
        if not self.offline_storage or not self.online:
            return
            
        # Get all pending messages
        offline_messages = self.offline_storage.get_offline_messages()
        if not offline_messages:
            return
        
        self.pending_sync = True
        
        # Group messages by channel for efficient syncing
        by_channel = {}
        for msg in offline_messages:
            if msg['channel_id'] not in by_channel:
                by_channel[msg['channel_id']] = []
            by_channel[msg['channel_id']].append(msg)
            
        # For each channel, get current content and merge with offline messages
        for channel_id, messages in by_channel.items():
            # Get current channel content
            self.get_messages(channel_id)
            time.sleep(0.5)  # Wait a bit for server response
            
            # Try to apply offline changes
            self._apply_offline_changes(channel_id, messages)
            
        self.pending_sync = False

    def _apply_offline_changes(self, channel_id, offline_messages):
        """Apply offline changes to channel content with conflict resolution."""
        try:
            # Get the most recent server content
            cached_content = self.offline_storage.get_cached_content(channel_id)
            if not cached_content:
                log_connection(f"No cached content found for channel {channel_id} to apply offline changes.")
                return

            current_content = cached_content['content']
            offline_content = []

            for msg in offline_messages:
                if 'content' in msg and isinstance(msg['content'], dict):
                    offline_content.append(msg['content'])
                else:
                    log_connection(f"Skipping invalid offline message structure: {msg}")

            merged_content = current_content + offline_content
            merged_content.sort(key=lambda x: x.get('timestamp', 0))

            request = {
                "type": "sync_offline_content",
                "channel_id": channel_id,
                "content": merged_content,
                "client_timestamp": time.time()
            }
            # self.socket.send(json.dumps(request).encode('utf-8')) # OLD WAY
            success = self._send_request(request) 

            if success:
                self.offline_storage.mark_messages_synced([msg['id'] for msg in offline_messages if 'id' in msg])
                log_connection(f"Successfully sent offline changes sync request for channel {channel_id}")
            else:
                log_connection(f"Failed to send offline changes sync request for channel {channel_id}")

        except Exception as e:
            log_connection(f"Error applying offline changes for channel {channel_id}: {str(e)}")
            traceback.print_exc() # Log full traceback for debugging
            if self.error_callback:
                self.error_callback(f"Error applying offline changes: {str(e)}")

    def _receive_messages(self):
        """Receive messages from the server in a loop."""
        buffer = b""
        header_size = 4 # Size of the message length header

        while self.connected:
            try:
                # --- Receive Header ---
                while len(buffer) < header_size:
                    chunk = self.socket.recv(header_size - len(buffer))
                    if not chunk:
                        log_connection("Server disconnected (no header chunk).")
                        self.connected = False
                        break
                    buffer += chunk
                if not self.connected: break

                # Unpack header to get message length
                msg_length = struct.unpack('>I', buffer[:header_size])[0]
                buffer = buffer[header_size:] # Remove header from buffer

                # --- Receive Message Body ---
                while len(buffer) < msg_length:
                    bytes_to_read = min(4096, msg_length - len(buffer))
                    chunk = self.socket.recv(bytes_to_read)
                    if not chunk:
                        log_connection("Server disconnected (no body chunk).")
                        self.connected = False
                        break
                    buffer += chunk
                if not self.connected: break

                # --- Process Complete Message ---
                message_json = buffer[:msg_length].decode('utf-8')
                buffer = buffer[msg_length:] # Remove processed message from buffer


                try:
                    message_data = json.loads(message_json)
                    # Optional: Log the received framed message
                    log_connection(f"Received framed response '{message_data.get('type', 'unknown')}' from server")
                    self.handle_server_message(message_data)
                except json.JSONDecodeError as e:
                    log_connection(f"Received invalid JSON from server: {e}")
                    log_connection(f"Invalid JSON data: {message_json[:200]}...") # Log beginning of bad data
                except Exception as e:
                    log_connection(f"Error handling server message: {e}")
                    traceback.print_exc() # Print full traceback for debugging

            except ConnectionResetError:
                log_connection("Connection reset by server.")
                self.connected = False
                break
            except ConnectionAbortedError:
                log_connection("Connection aborted.")
                self.connected = False
                break
            except socket.timeout:
                 # This shouldn't happen if not set, but good practice
                 continue
            except struct.error as e:
                 log_connection(f"Header unpack error (server disconnected?): {e}")
                 self.connected = False
                 break
            except Exception as e:
                if self.connected: # Avoid logging error if we intentionally disconnected
                    log_connection(f"Receiving error: {e}")
                    traceback.print_exc()
                self.connected = False
                break

        log_connection("Message receiving loop stopped.")
        # Trigger reconnection or UI update if needed
        # Call _handle_connection_loss instead of directly calling callback
        if not self.connected: # Check if it wasn't an intentional disconnect
             self._handle_connection_loss()
    # ^^^ End of _receive_messages method ^^^

    # *** Add a message handler method if you don't have one ***
    def handle_server_message(self, message_data):
        """Processes messages received from the server."""
        msg_type = message_data.get('type')
        log_connection(f"Handling server message type: {msg_type}")

        if msg_type == 'login_response':
            self.update_auth_status(message_data['success'], message_data['message'])
            if self.auth_callback:
                self.auth_callback(message_data['success'], message_data['message'])
        elif msg_type == 'register_response':
            if self.auth_callback: # Use auth_callback or a dedicated register callback
                self.auth_callback(message_data['success'], message_data['message'])
        elif msg_type == 'get_channels_response':
            if self.channels_callback:
                self.channels_callback(message_data.get('channels', []))
        elif msg_type == 'join_channel_response':
            # Handle join response (e.g., update UI, request messages)
            if message_data['success']:
                log_connection(f"Successfully joined channel {self.current_channel}")
                self.get_messages(self.current_channel) # Request messages after joining
                self.get_channel_users(self.current_channel) # Request user list
            else:
                if self.error_callback:
                    self.error_callback(f"Failed to join channel: {message_data.get('message')}")
        elif msg_type == 'leave_channel_response':
             log_connection(f"Left channel {message_data.get('channel_id')}") # Assuming server sends channel_id back
        elif msg_type == 'create_channel_response':
             if message_data['success']:
                  log_connection("Channel created successfully.")
                  self.get_channels() # Refresh channel list
             else:
                  if self.error_callback:
                       self.error_callback(f"Failed to create channel: {message_data.get('message')}")
        elif msg_type == 'get_messages_response':
            if message_data['success']:
                if self.message_callback:
                    self.message_callback(message_data.get('messages', []))
                # Cache content if offline storage is enabled
                if self.offline_storage and self.current_channel:
                     self.offline_storage.cache_channel_content(self.current_channel, message_data.get('messages', []))
            else:
                if self.error_callback:
                    self.error_callback(f"Failed to get messages: {message_data.get('message')}")
        elif msg_type == 'message_update': # Handle broadcasted message updates
            if self.current_channel == message_data.get('channel_id') and self.message_callback:
                self.message_callback(message_data.get('content', []))
            # Cache content if offline storage is enabled
            if self.offline_storage:
                 self.offline_storage.cache_channel_content(message_data.get('channel_id'), message_data.get('content', []))
        elif msg_type == 'channel_users_response':
             if self.channel_users_callback:
                  self.channel_users_callback(message_data['channel_id'], message_data['users'])
        elif msg_type == 'user_channel_event': # Handle join/leave broadcasts
             if self.channel_users_callback:
                  self.channel_users_callback(message_data['channel_id'], [], event=message_data['event'], username=message_data['username'])
        elif msg_type == 'channel_host_info':
             # Handle host info update (for P2P)
             self.peer_manager.update_host_status(
                  message_data['channel_id'],
                  message_data['is_online'],
                  message_data.get('host_ip'),
                  message_data.get('peer_port') # Use peer_port from server
             )
             if self.host_status_callback:
                  self.host_status_callback(message_data['channel_id'], message_data['is_online'])
        elif msg_type == 'active_streams_response':
             if self.active_streams_callback:
                  self.active_streams_callback(message_data['channel_id'], message_data['streams'])
        elif msg_type == 'livestream_update': # Handle broadcasted stream updates
             if self.active_streams_callback:
                  self.active_streams_callback(message_data['channel_id'], message_data['streams'])
        elif msg_type == 'logout_response': # Assuming server sends a response
             log_connection("Logout successful.")
             self.authenticated = False
             self.username = None
             # Potentially trigger UI update via auth_callback or connection_callback
             if self.auth_callback:
                  self.auth_callback(False, "Logged out") # Indicate logout
        elif msg_type == 'error':
            if self.error_callback:
                self.error_callback(f"Server error: {message_data.get('message')}")
        else:
            log_connection(f"Received unhandled message type: {msg_type}")


    def login(self, username, password):
        """Authenticate with the server using username and password."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        # Store username temporarily until we get confirmation
        self._temp_username = username
        request = {
            "type": "login",
            "username": username,
            "password": password
        }
        return self._send_request(request)
        # try:
        #     self.socket.send(json.dumps(request).encode('utf-8'))
        #     return True
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Login error: {str(e)}")
        #     return False

    def admin_login(self, username, password):
        """Authenticate as an admin with the server."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        # Store username temporarily until we get confirmation
        self._temp_username = username
        request = {
            "type": "admin_login",
            "username": username,
            "password": password
        }
        return self._send_request(request)
        # try:
        #     self.socket.send(json.dumps(request).encode('utf-8'))
        #     return True
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Admin login error: {str(e)}")
        #     return False

    def update_auth_status(self, success, message, is_admin=False):
        """Update authentication status."""
        if success:
            self.authenticated = True
            self.username = self._temp_username
            self.is_admin = is_admin  # Track if the user is an admin
            if self.auth_callback:
                self.auth_callback(success, message)
        else:
            self.authenticated = False
            self.username = None
            self.is_admin = False
            if self.auth_callback:
                self.auth_callback(success, message)

    def register(self, username, password):
        """Register a new user with the server."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        request = {
            "type": "register",
            "username": username,
            "password": password
        }
        return self._send_request(request)
        # try:
        #     self.socket.send(json.dumps(request).encode('utf-8'))
        #     return True
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Registration error: {str(e)}")
        #     return False

    def get_channels(self):
        """Get list of available channels from server."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        request = {
            "type": "get_channels"
        }
        return self._send_request(request)
        # try:
        #     # self.socket.send(json.dumps(request).encode('utf-8')) # OLD WAY
        #     return self._send_request(request)
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Error getting channels: {str(e)}")
        #     return False

    def create_channel(self, channel_id, is_public=True):
        """Create a new channel on the server."""
        if not self.connected or not self.authenticated:
            if self.error_callback:
                self.error_callback("Must be authenticated to create a channel")
            return False
        # Use local IP as host
        host_ip = socket.gethostbyname(socket.gethostname())
        request = {
            "type": "create_channel",
            "channel_id": channel_id,
            "host_ip": host_ip,
            "host_port": 0,  # Not used directly
            "is_public": is_public
        }
        return self._send_request(request)
        # try:
        #     # self.socket.send(json.dumps(request).encode('utf-8')) # OLD WAY
        #     return self._send_request(request)
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Error creating channel: {str(e)}")
        #     return False

    def join_channel(self, channel_id):
        """Join a channel."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False

        # Update current channel
        self.current_channel = channel_id

        # Create request
        request = {
            "type": "join_channel",
            "channel_id": channel_id,
            "username": self.username if self.authenticated else "visitor",
            "is_visitor": not self.authenticated
        }

        success = self._send_request(request)
        if success:
            # Request list of users in this channel only if join request was sent successfully
            self.get_channel_users(channel_id)
        return success
        # try:
        #     # self.socket.send(json.dumps(request).encode('utf-8')) # OLD WAY
        #     success = self._send_request(request)
        #     if success:
        #         # Request list of users in this channel
        #         self.get_channel_users(channel_id)
        #     return success
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Error joining channel: {str(e)}")
        #     return False

    def leave_channel(self, channel_id):
        """Leave a channel."""
        if not self.connected:
            return False

        request = {
            "type": "leave_channel",
            "channel_id": channel_id
        }

        success = self._send_request(request)
        if success:
            # If this is the current channel, reset it
            if self.current_channel == channel_id:
                self.current_channel = None
        return success
        # try:
        #     # self.socket.send(json.dumps(request).encode('utf-8')) # OLD WAY
        #     success = self._send_request(request)
        #     if success:
        #         # If this is the current channel, reset it
        #         if self.current_channel == channel_id:
        #             self.current_channel = None
        #     return success
        # except Exception as e:
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Error leaving channel: {str(e)}")
        #     return False

    def get_messages(self, channel_id):
        """Get messages for a channel with improved error handling."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False

        # If we're offline, try to retrieve cached messages
        if not self.online and self.offline_storage:
            cached_content = self.offline_storage.get_cached_content(channel_id)
            if cached_content and self.message_callback:
                log_connection(f"Using cached messages for channel {channel_id}")
                self.message_callback(cached_content['content'])
                return True # Indicate success (used cache)

        # Create request
        request = {
            "type": "get_messages",
            "channel_id": channel_id
        }

        log_connection(f"Requesting messages for channel {channel_id}")
        return self._send_request(request)
        # try:
        #     log_connection(f"Requesting messages for channel {channel_id}")
        #     # self.socket.send(json.dumps(request).encode('utf-8')) # OLD WAY
        #     return self._send_request(request)
        # except Exception as e:
        #     log_connection(f"Error requesting messages: {str(e)}")
        #     self._handle_connection_loss()
        #     if self.error_callback:
        #         self.error_callback(f"Error getting messages: {str(e)}")
        #     return False

    def send_message(self, channel_id, content):
        """Send a message to a channel."""
        if not self.connected and not self.offline_storage:
            if self.error_callback:
                self.error_callback("Not connected to server and offline storage not available")
            return False
        
        # Store current time
        timestamp = time.time()
        
        # Create message object
        if isinstance(content, dict):
            # Content is already a structured message (e.g., file data)
            message = content
            if 'timestamp' not in message:
                message['timestamp'] = timestamp
            if 'sender' not in message:
                message['sender'] = self.username if self.authenticated else "visitor"
        else:
            # Plain text message
            message = {
                'content': content,
                'sender': self.username if self.authenticated else "visitor",
                'timestamp': timestamp
            }
        
        # If offline or we're a channel host, handle differently
        if channel_id in self.is_channel_host and self.is_channel_host[channel_id]:
            # We're the host, broadcast to peers directly
            if self._temp_messages:
                new_messages = self._temp_messages + [message]
                self.peer_manager.broadcast_content_to_peers(channel_id, new_messages)
                # Also update UI
                if self.message_callback:
                    self.message_callback(new_messages)
                # Store for future use
                self._temp_messages = new_messages
                return True
        elif not self.online and self.offline_storage:
            # Store for later sync
            log_connection(f"Storing offline message for channel {channel_id}")
            message['offline'] = True
            self.offline_storage.store_offline_message(
                channel_id,
                message,
                timestamp
            )
            
            # Update local cache
            cached_content = self.offline_storage.get_cached_content(channel_id)
            if cached_content:
                new_messages = cached_content['content'] + [message]
                self.offline_storage.cache_channel_content(channel_id, new_messages)
                # Update UI
                if self.message_callback:
                    self.message_callback(new_messages)
            return True
        
        try:
            # If we have cached messages, update them and sync the entire content
            if self._temp_messages:
                new_messages = self._temp_messages + [message]
                request = {
                    "type": "sync_content",
                    "channel_id": channel_id,
                    "content": new_messages
                }
            else:
                # No cached messages, send just this message
                request = {
                    "type": "sync_content",
                    "channel_id": channel_id,
                    "content": [message]
                }

            # self.socket.send(json.dumps(request).encode('utf-8')) # OLD LINE
            success = self._send_request(request) # NEW LINE
            return success # Return the result of _send_request
        except Exception as e:
            if self.error_callback:
                self.error_callback(f"Error sending message: {str(e)}")
            if not self.connected and self.offline_storage:
                 log_connection("Connection lost during send, storing message offline.")
                 message['offline'] = True
                 self.offline_storage.store_offline_message(channel_id, message, timestamp)
                 cached_content = self.offline_storage.get_cached_content(channel_id)
                 if cached_content:
                     new_messages = cached_content['content'] + [message]
                     self.offline_storage.cache_channel_content(channel_id, new_messages)
                     if self.message_callback:
                         self.message_callback(new_messages)
                 return True # Indicate success (stored offline)
            return False

    def get_channel_host(self, channel_id):
        """Get information about the host of a channel."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        
        request = {
            "type": "get_channel_host_info",
            "channel_id": channel_id
        }
        
        return self._send_request(request)

    def register_livestream(self, channel_id, livestream_port):
        """Register a livestream with the server."""
        if not self.connected or not self.authenticated:
            if self.error_callback:
                self.error_callback("Must be authenticated to register a livestream")
            return False
        
        request = {
            "type": "register_livestream",
            "channel_id": channel_id,
            "host_ip": socket.gethostbyname(socket.gethostname()),
            "livestream_port": livestream_port,
            "username": self.username
        }
        
        success = self._send_request(request)
        if success:
            # Store locally too
            if not hasattr(self, 'livestream_ports'):
                self.livestream_ports = {}
            self.livestream_ports[channel_id] = livestream_port
            
        return success

    def unregister_livestream(self, livestream_port=None):
        """Unregister a livestream with the server."""
        if not self.connected:
            return False
        
        channel_id = self.current_channel
        if not channel_id:
            return False
        
        request = {
            "type": "unregister_livestream",
            "channel_id": channel_id,
            "username": self.username
        }
        
        success = self._send_request(request)
        if success:
            # Remove from local storage
            if hasattr(self, 'livestream_ports') and channel_id in self.livestream_ports:
                del self.livestream_ports[channel_id]
                
        return success

    def get_active_streams(self, channel_id):
        """Get active livestreams for a channel."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        
        request = {
            "type": "get_active_streams",
            "channel_id": channel_id
        }
        
        return self._send_request(request)

    def get_channel_users(self, channel_id):
        """Get users in a channel."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        
        request = {
            "type": "get_channel_users",
            "channel_id": channel_id
        }
        
        log_connection(f"Requesting user list for channel {channel_id}")
        return self._send_request(request)

    def logout(self):
        """Log out from the server."""
        if not self.connected:
            return False
        
        request = {
            "type": "logout"
        }
        
        success = self._send_request(request)
        if success:
            # Update local state immediately, even before server response (optional)
            # Server response 'logout_response' will confirm in handle_server_message
            self.authenticated = False
            self.username = None
        return success

    def disconnect(self):
        """Disconnect from the server."""
        self.connected = False
        self.online = False
        self.authenticated = False
        self.username = None
        
        # Close socket
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                log_connection(f"Error closing socket: {str(e)}")
        
        # Close offline storage
        if self.offline_storage:
            try:
                self.offline_storage.close()
            except Exception as e:
                log_connection(f"Error closing offline storage: {str(e)}")
        
        # End peer manager
        try:
            self.peer_manager.shutdown()
        except Exception as e:
            log_connection(f"Error shutting down peer manager: {str(e)}")
        
        if self.connection_callback:
            self.connection_callback(False)