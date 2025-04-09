import socket
import json
import threading
import time
import os
from offline_storage import OfflineStorage
from peer_manager import PeerConnectionManager  # Add this import
from utils import log_connection  # Add missing import

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
            self.listen_thread = threading.Thread(target=self._listen_for_messages)
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
                self.socket.send(json.dumps(request).encode('utf-8'))
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
            self.socket.send(json.dumps(request).encode('utf-8'))
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error sending host heartbeat: {str(e)}")

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
                return
                
            current_content = cached_content['content']
            offline_content = []
            
            # Extract message content from offline messages
            for msg in offline_messages:
                offline_content.append(msg['content'])
                    
            # Simple merge strategy - append offline content to current content
            # In a real app, you might want a more sophisticated conflict resolution
            merged_content = current_content + offline_content
            
            # Sort by timestamp
            merged_content.sort(key=lambda x: x.get('timestamp', 0))
            
            # Sync merged content with server
            request = {
                "type": "sync_offline_content",
                "channel_id": channel_id,
                "content": merged_content,
                "client_timestamp": time.time()
            }
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # Mark messages as synced
            self.offline_storage.mark_messages_synced([msg['id'] for msg in offline_messages])
        except Exception as e:
            if self.error_callback:
                self.error_callback(f"Error applying offline changes: {str(e)}")

    def _listen_for_messages(self):
        """Thread that listens for incoming messages from the server."""
        while self.connected:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    log_connection("Empty data received from server, disconnecting")
                    break
                    
                try:
                    # Handle potential multiple JSON responses in one packet
                    if data.count('}{') > 0:
                        log_connection("Detected multiple JSON objects in response, splitting")
                        json_start = data.find('{')
                        json_end = data.rfind('}') + 1
                        if json_start >= 0 and json_end > json_start:
                            data = data[json_start:json_end]
                    
                    response = json.loads(data)
                    
                except json.JSONDecodeError as e:
                    log_connection(f"Received invalid JSON from server: {e}")
                    log_connection(f"Invalid JSON data: {data[:100]}...")  # Log partial data for debugging
                    # if self.error_callback:
                    #     self.error_callback("Received invalid data from server")
                    continue
                    
                response_type = response.get('type', 'unknown')
                log_connection(f"Received {response_type} from server")
                
                # Handle existing message types
                if response['type'] == 'login_response':
                    self.authenticated = response['success']
                    if self.authenticated:
                        self.username = self._temp_username
                    if self.auth_callback:
                        self.auth_callback(response['success'], response['message'])
                
                elif response['type'] == 'register_response':
                    if self.auth_callback:
                        self.auth_callback(response['success'], response['message'])
                
                elif response['type'] == 'get_messages_response':
                    if response['success']:
                        # Store the current channel messages
                        channel_id = self.current_channel
                        messages = response['messages']
                        log_connection(f"Received {len(messages)} messages for channel {channel_id}")
                        
                        # Cache content for offline use
                        if self.offline_storage:
                            self.offline_storage.cache_channel_content(
                                channel_id,
                                messages
                            )
                        # Update UI
                        if self.message_callback:
                            self.message_callback(messages)
                            # Store messages for future sending
                            self._temp_messages = messages
                    else:
                        log_connection(f"Failed to get messages: {response.get('message', 'Unknown error')}")
                
                elif response['type'] == 'get_channels_response':
                    if self.channels_callback:
                        self.channels_callback(response['channels'])
                
                elif response['type'] == 'join_channel_response':
                    if response['success']:
                        self.get_messages(self.current_channel)
                    elif self.error_callback:
                        self.error_callback(response['message'])
                        
                elif response['type'] == 'create_channel_response':
                    if self.error_callback and not response['success']:
                        self.error_callback(response['message'])
                    self.get_channels()
                
                elif response['type'] == 'logout' and response['success']:
                    self.authenticated = False
                    self.username = None
                
                # Handle new message types for connection status
                elif response['type'] == 'connection_status':
                    if self.online_status_callback:
                        self.online_status_callback(
                            response['status'] == 'online',
                            response.get('username')
                        )
                
                # Handle host status updates
                elif response['type'] == 'host_status_update':
                    channel_id = response['channel_id']
                    is_online = response['is_online']
                    
                    self.channel_hosts[channel_id] = {
                        'online': is_online,
                        'updated': response.get('timestamp', time.time())
                    }
                    
                    if self.host_status_callback:
                        self.host_status_callback(channel_id, is_online)
                
                # Handle offline content sync responses
                elif response['type'] == 'sync_offline_content_response':
                    if not response['success'] and self.error_callback:
                        self.error_callback(f"Offline sync error: {response.get('message')}")
                
                # Handle conflict resolution
                elif response['type'] == 'sync_conflict_resolution':
                    channel_id = response['channel_id']
                    resolved_content = response['resolved_content']
                    
                    # Update local cache with server-resolved content
                    if self.offline_storage:
                        self.offline_storage.cache_channel_content(channel_id, resolved_content)
                    
                    # Update UI if this is the current channel
                    if self.current_channel == channel_id and self.message_callback:
                        self.message_callback(resolved_content)
                
                # Add handler for host info
                elif response['type'] == 'channel_host_info':
                    channel_id = response['channel_id']
                    host_ip = response['host_ip']
                    peer_port = response['peer_port']
                    is_online = response['is_online']
                    
                    if is_online and peer_port:
                        # Update host status in peer manager
                        self.peer_manager.update_host_status(
                            channel_id, True, host_ip, peer_port
                        )
                    else:
                        self.peer_manager.update_host_status(channel_id, False)
                
                # Add handler for host registration response
                elif response['type'] == 'host_register_response':
                    if response['success']:
                        channel_id = response.get('channel_id')
                        if channel_id:
                            self.is_channel_host[channel_id] = True
                            if self.peer_status_callback:
                                self.peer_status_callback(
                                    channel_id, self.username, True, is_host=True
                                )
                    elif self.error_callback:
                        self.error_callback(response['message'])
                
                # Handle active streams response
                elif response['type'] == 'active_streams_response':
                    channel_id = response.get('channel_id')
                    streams = response.get('streams', [])
                    
                    if self.active_streams_callback:
                        self.active_streams_callback(channel_id, streams)
                
                # Channel users response
                elif response['type'] == 'channel_users_response':
                    channel_id = response.get('channel_id')
                    users = response.get('users', [])
                    
                    # Update local tracking with more detailed logging
                    log_connection(f"Received user list for channel {channel_id}: {users}")
                    self.channel_users[channel_id] = users
                        
                    # Notify UI
                    if self.channel_users_callback:
                        self.channel_users_callback(channel_id, users)
                
                # User join/leave events
                elif response['type'] == 'user_channel_event':
                    channel_id = response['channel_id']
                    username = response['username']
                    event = response['event']
                    
                    # Update local tracking
                    if channel_id not in self.channel_users:
                        self.channel_users[channel_id] = []
                    
                    if event == 'join':
                        if username not in self.channel_users[channel_id]:
                            self.channel_users[channel_id].append(username)
                    elif event == 'leave':
                        if username in self.channel_users[channel_id]:
                            self.channel_users[channel_id].remove(username)
                    
                    # Notify UI
                    if self.channel_users_callback:
                        self.channel_users_callback(channel_id, self.channel_users[channel_id], event, username)
                
                # Add handler for direct message updates from server
                elif response['type'] == 'message_update':
                    channel_id = response['channel_id']
                    messages = response['content']
                    
                    # Only update UI if this is the current channel
                    if self.current_channel == channel_id:
                        # Cache content for offline use
                        if self.offline_storage:
                            self.offline_storage.cache_channel_content(
                                channel_id,
                                messages
                            )
                        # Update UI
                        if self.message_callback:
                            self.message_callback(messages)
                            # Store messages for future sending
                            self._temp_messages = messages
                    else:
                        # Still update cache for non-current channels
                        if self.offline_storage:
                            self.offline_storage.cache_channel_content(
                                channel_id,
                                messages
                            )
            
            except json.JSONDecodeError as e:
                log_connection(f"JSON decode error: {e}")
                if self.error_callback:
                    self.error_callback("Received invalid data from server")
            except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                log_connection("Connection error detected")
                self._handle_connection_loss()
                break
            except Exception as e:
                log_connection(f"Error in message listener: {str(e)}")
                if self.error_callback:
                    self.error_callback(f"Error receiving data: {str(e)}")
                self._handle_connection_loss()
                break
                
        # Connection lost
        if self.connected:
            self._handle_connection_loss()

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
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Login error: {str(e)}")
            return False

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
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Admin login error: {str(e)}")
            return False

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
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Registration error: {str(e)}")
            return False

    def get_channels(self):
        """Get list of available channels from server."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
        request = {
            "type": "get_channels"
        }
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting channels: {str(e)}")
            return False

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
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error creating channel: {str(e)}")
            return False

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
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # Request list of users in this channel
            self.get_channel_users(channel_id)
            
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error joining channel: {str(e)}")
            return False

    def leave_channel(self, channel_id):
        """Leave a channel."""
        if not self.connected:
            return False
        
        request = {
            "type": "leave_channel",
            "channel_id": channel_id
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # If this is the current channel, reset it
            if self.current_channel == channel_id:
                self.current_channel = None
                
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error leaving channel: {str(e)}")
            return False

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
                return True
        
        # Create request
        request = {
            "type": "get_messages",
            "channel_id": channel_id
        }
        
        try:
            log_connection(f"Requesting messages for channel {channel_id}")
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            log_connection(f"Error requesting messages: {str(e)}")
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting messages: {str(e)}")
            return False

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
        
        # Normal online operation - send to server
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
            
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error sending message: {str(e)}")
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
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting channel host: {str(e)}")
            return False

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
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # Store locally too
            if not hasattr(self, 'livestream_ports'):
                self.livestream_ports = {}
            self.livestream_ports[channel_id] = livestream_port
            
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error registering livestream: {str(e)}")
            return False

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
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # Remove from local storage
            if hasattr(self, 'livestream_ports') and channel_id in self.livestream_ports:
                del self.livestream_ports[channel_id]
                
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error unregistering livestream: {str(e)}")
            return False

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
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting active streams: {str(e)}")
            return False

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
        
        try:
            log_connection(f"Requesting user list for channel {channel_id}")
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting channel users: {str(e)}")
            return False

    def logout(self):
        """Log out from the server."""
        if not self.connected:
            return False
        
        request = {
            "type": "logout"
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.authenticated = False
            self.username = None
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error logging out: {str(e)}")
            return False

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
