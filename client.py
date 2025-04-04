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
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            delay = self.reconnect_delay * (2 ** (self.reconnect_attempts - 1))
            
            if self.error_callback:
                self.error_callback(f"Reconnecting in {delay} seconds (attempt {self.reconnect_attempts})")
                
            reconnect_thread = threading.Thread(
                target=lambda: (time.sleep(delay), self.connect())
            )
            reconnect_thread.daemon = True
            reconnect_thread.start()
        else:
            if self.error_callback:
                self.error_callback("Maximum reconnection attempts reached")

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
                    
                response = json.loads(data)
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
                    
                    # Update local tracking
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
            
            except json.JSONDecodeError:
                log_connection("Received invalid JSON from server")
                if self.error_callback:
                    self.error_callback("Received invalid data from server")
            except ConnectionError:
                self._handle_connection_loss()
                break
            except Exception as e:
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

    def get_channel_host(self, channel_id):
        """Get host information for a channel."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return None
                
        request = {
            "type": "get_channel_host",
            "channel_id": channel_id
        }
            
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            # This should be handled asynchronously via callback
            return {"success": True}
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting channel host: {str(e)}")
            return None

    def logout(self):
        """Logout from the server."""
        if not self.connected:
            self.authenticated = False
            self.username = None
            return True
                
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
            self.authenticated = False
            self.username = None
            return False

    def send_message(self, channel_id, content):
        """Send a message to a channel."""
        # Check if we're the host for this channel
        if channel_id in self.is_channel_host and self.is_channel_host[channel_id]:
            # We're the host - broadcast to peers and sync with server
            # Check if message contains file data
            if isinstance(content, dict) and 'file_type' in content:
                # For file messages, keep content structure intact
                message = {
                    "content": content,  # Keep the complete content dict
                    "timestamp": time.time(),
                    "sender": self.username or "visitor"
                }
            else:
                # Regular text message
                message = {
                    "content": content,
                    "timestamp": time.time(),
                    "sender": self.username or "visitor"
                }
            
            # Get current content and add our message
            current_content = getattr(self, '_temp_messages', []) if hasattr(self, '_temp_messages') else []
            updated_content = current_content + [message]
            
            # Broadcast to peers
            self.peer_manager.broadcast_content_to_peers(channel_id, updated_content)
            
            # Also sync with server for backup and broadcasting to other clients
            self._sync_with_server(channel_id, updated_content)
            
            return True
        
        # Check if we have a connection to the host
        elif self.online and self.peer_manager.channel_hosts.get(channel_id, (None, None, False))[2]:
            # We can send directly to host
            # Check if message contains file data
            if isinstance(content, dict) and 'file_type' in content:
                # Keep complete file data structure
                message = {
                    "content": content,
                    "timestamp": time.time(),
                    "sender": self.username or "visitor"
                }
            else:
                # Regular text message
                message = {
                    "content": content,
                    "timestamp": time.time(),
                    "sender": self.username or "visitor"
                }
            
            # Get current content with safer access
            current_content = getattr(self, '_temp_messages', []) if hasattr(self, '_temp_messages') else []
            updated_content = current_content + [message]
                
            # Send to host
            if self.peer_manager.send_content_to_host(channel_id, updated_content):
                return True
        
        # Fall back to server if offline or no host connection
        if not self.online:
            # Store message locally if offline
            if self.offline_storage:
                # Check if message contains file data
                if isinstance(content, dict) and 'file_type' in content:
                    # For file messages, keep complete structure
                    message = {
                        "content": content,
                        "timestamp": time.time(),
                        "sender": self.username or "visitor",
                        "offline": True
                    }
                else:
                    # Regular text message
                    message = {
                        "content": content,
                        "timestamp": time.time(),
                        "sender": self.username or "visitor",
                        "offline": True
                    }
                
                self.offline_storage.store_offline_message(channel_id, message)
                
                # Update local cache with this message for immediate display
                cached = self.offline_storage.get_cached_content(channel_id)
                if cached:
                    updated_content = cached['content'] + [message]
                    self.offline_storage.cache_channel_content(channel_id, updated_content)
                    
                    # Notify UI about new message
                    if self.message_callback:
                        self.message_callback(updated_content)
                        
                return True
            return False
            
        # Online - normal flow
        try:
            # Make sure _temp_messages exists and is a list
            if not hasattr(self, '_temp_messages') or not isinstance(self._temp_messages, list):
                self._temp_messages = []
                
            # Check if message contains file data
            if isinstance(content, dict) and 'file_type' in content:
                # For file messages, keep complete content structure
                message = {
                    "content": content,
                    "timestamp": time.time(),
                    "sender": self.username or "visitor"
                }
                log_connection(f"Sending image message with structure: {list(content.keys())}") 
            else:
                # Regular text message
                message = {
                    "content": content,
                    "timestamp": time.time(),
                    "sender": self.username or "visitor"
                }
            
            updated_content = self._temp_messages + [message]
            
            request = {
                "type": "sync_content",
                "channel_id": channel_id,
                "content": updated_content
            }
            
            # Log the message size for debugging
            request_json = json.dumps(request)
            msg_size = len(request_json)
            log_connection(f"Sending message with size: {msg_size} bytes")
            
            # Check if message is too large - typically socket buffers are ~64KB
            if msg_size > 1024 * 1024:  # 1MB
                log_connection(f"Warning: Very large message ({msg_size/1024/1024:.2f} MB)")
            
            self.socket.send(request_json.encode('utf-8'))
            
            # Also update local cache
            if self.offline_storage:
                self.offline_storage.cache_channel_content(channel_id, updated_content)
                
            return True
        except Exception as e:
            log_connection(f"Error sending message: {str(e)}")
            if self.error_callback:
                self.error_callback(f"Error sending message: {str(e)}")
            return False

    def _sync_with_server(self, channel_id, content):
        """Sync content with the server for backup."""
        if not self.connected:
            return False
            
        request = {
            "type": "sync_content",
            "channel_id": channel_id,
            "content": content
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            return False

    def get_messages(self, channel_id):
        """Get messages for a channel."""
        # Set the current channel to ensure responses go to the right place
        self.current_channel = channel_id
        
        # First try to get from host if we're connected
        if self.online and self.peer_manager.channel_hosts.get(channel_id, (None, None, False))[2]:
            # We're connected to host - messages should come through the peer connection
            # Still request from server as a fallback
            log_connection(f"Requesting messages for channel {channel_id} from peer host")
            # Let peer connection handle it, but still fetch from server as backup
        
        # Then try cached content if offline
        if not self.online and self.offline_storage:
            cached = self.offline_storage.get_cached_content(channel_id)
            if cached and self.message_callback:
                log_connection(f"Using cached content for channel {channel_id}")
                self.message_callback(cached['content'])
                return True
        
        # Finally, fetch from server
        log_connection(f"Requesting messages for channel {channel_id} from server")
        request = {
            "type": "get_messages",
            "channel_id": channel_id
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting messages: {str(e)}")
            return False

    def join_channel(self, channel_id):
        """Join a channel."""
        # Try to get cached content if offline
        if not self.online and self.offline_storage:
            cached = self.offline_storage.get_cached_content(channel_id)
            if cached and self.message_callback:
                self.message_callback(cached['content'])
                return True
                
        # Online - normal flow
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
                
        request = {
            "type": "join_channel",
            "channel_id": channel_id
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # After joining, check if there's a host and connect if available
            self._check_and_connect_to_host(channel_id)
            
            # Request users for new channel
            self.get_channel_users(channel_id)
            
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error joining channel: {str(e)}")
            return False

    def _check_and_connect_to_host(self, channel_id):
        """Check if there's a host for this channel and connect to it."""
        request = {
            "type": "get_channel_host_info",
            "channel_id": channel_id
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
        except:
            self._handle_connection_loss()

    def get_channel_users(self, channel_id):
        """Get the list of users in a channel."""
        if not self.connected:
            if self.error_callback:
                self.error_callback("Not connected to server")
            return False
            
        request = {
            "type": "get_channel_users",
            "channel_id": channel_id
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            self._handle_connection_loss()
            if self.error_callback:
                self.error_callback(f"Error getting channel users: {str(e)}")
            return False

    def disconnect(self):
        """Disconnect from the server and clean up resources."""
        if self.connected:
            self.connected = False
            self.online = False
            try:
                self.socket.close()
            except:
                pass
            
            if self.connection_callback:
                self.connection_callback(False)
                
            # Close offline storage
            if self.offline_storage:
                self.offline_storage.close()
                
            # Also shut down peer manager
            self.peer_manager.shutdown()

    def register_livestream(self, channel_id, livestream_port):
        """Register a livestream with the server."""
        if not self.connected or not self.authenticated:
            if self.error_callback:
                self.error_callback("Must be authenticated to start a livestream")
            return False
            
        # Get local IP address
        host_ip = socket.gethostbyname(socket.gethostname())
        
        request = {
            "type": "register_livestream",
            "channel_id": channel_id,
            "host_ip": host_ip,
            "livestream_port": livestream_port,
            "username": self.username
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
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
            
        request = {
            "type": "unregister_livestream",
            "channel_id": self.current_channel,
            "username": self.username
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            return True
        except Exception as e:
            if self.error_callback:
                self.error_callback(f"Error unregistering livestream: {str(e)}")
            return False

    def get_active_streams(self, channel_id):
        """Get list of active livestreams for a channel."""
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
