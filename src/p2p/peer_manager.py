import socket
import threading
import json
import time
import struct
from src.common.utils import log_connection

class PeerConnectionManager:
    def __init__(self, username="anonymous"):
        self.username = username
        self.peer_connections = {}  # {channel_id: {peer_username: connection}} Outgoing connections to hosts
        self.channel_hosts = {}     # {channel_id: (host_ip, host_port, online)} Info about known hosts
        self.listeners = {}         # {channel_id: listener_socket} Not currently used, but could be for channel-specific listening
        self.incoming_connections = {} # {channel_id: [(peer_username, connection)]} Incoming connections from peers when hosting
        self.content_callback = None
        self.peer_status_callback = None
        self.listener_port = None
        self.running = True
        self.connections_lock = threading.Lock() # Lock for peer_connections and incoming_connections
        self.hosts_lock = threading.Lock()       # Lock for channel_hosts
        
    def start_listener(self, port=0):
        """Start listening for incoming peer connections."""
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('0.0.0.0', port))
            listener.listen(10)
            
            self.listener_port = listener.getsockname()[1]
            log_connection(f"Peer listener started on port {self.listener_port}")
            
            # Start a thread to accept connections
            threading.Thread(target=self._accept_connections, 
                          args=(listener,), daemon=True).start()
            
            return self.listener_port
        except Exception as e:
            log_connection(f"Error starting peer listener: {e}")
            return None
    
    def _accept_connections(self, listener):
        """Accept incoming peer connections."""
        listener.settimeout(1.0)  # Non-blocking with timeout
        
        while self.running:
            try:
                client_socket, addr = listener.accept()
                log_connection(f"New peer connection from {addr}")
                
                # Start a thread to handle this connection
                threading.Thread(target=self._handle_peer_connection, 
                              args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log_connection(f"Error accepting peer connection: {e}")
                break
        
        try:
            listener.close()
        except:
            pass
    
    def _handle_peer_connection(self, client_socket):
        """Handle data from peer connection."""
        channel_id = None
        peer_username = None
        try:
            # First message should be identification
            data = client_socket.recv(4096)
            if not data:
                return
                
            intro = json.loads(data.decode('utf-8'))
            if intro['type'] != 'peer_intro':
                raise ValueError("Expected peer introduction")
                
            channel_id = intro['channel_id']
            peer_username = intro['username']
            
            # Send acknowledgment
            response = json.dumps({
                'type': 'peer_intro_ack',
                'username': self.username,
                'timestamp': time.time()
            })
            client_socket.send(response.encode('utf-8'))
            
            # Store connection under lock
            with self.connections_lock:
                if channel_id not in self.incoming_connections:
                    self.incoming_connections[channel_id] = []
                # Avoid adding duplicates if the same peer connects multiple times quickly
                if not any(sock == client_socket for _, sock in self.incoming_connections.get(channel_id, [])):
                    self.incoming_connections.setdefault(channel_id, []).append((peer_username, client_socket))
                else:
                    log_connection(f"Duplicate incoming connection ignored for {peer_username} on {channel_id}")
                    # Optionally close the new socket immediately if duplicate
                    # client_socket.close()
                    # return # Exit thread if closing duplicate
            
            # Notify about new peer (outside lock)
            if self.peer_status_callback:
                self.peer_status_callback(channel_id, peer_username, True)
            
            # Loop to handle incoming data
            while self.running:
                try:
                    # Get message length first
                    length_data = client_socket.recv(4)
                    if not length_data:
                        log_connection(f"Peer {peer_username} disconnected (no length data).")
                        break # Clean disconnect
                        
                    msg_length = struct.unpack(">I", length_data)[0]
                    
                    # Get full message
                    chunks = []
                    bytes_received = 0
                    while bytes_received < msg_length:
                        chunk = client_socket.recv(min(msg_length - bytes_received, 4096))
                        if not chunk:
                            raise RuntimeError("Socket connection closed")
                        chunks.append(chunk)
                        bytes_received += len(chunk)
                    
                    msg_data = b''.join(chunks).decode('utf-8')
                    message = json.loads(msg_data)
                    
                    # Handle message based on type
                    if message['type'] == 'content_update' and self.content_callback:
                        self.content_callback(channel_id, message['content'], 
                                           source=f"peer:{peer_username}")
                
                except struct.error as e:
                    log_connection(f"Peer struct unpack error ({peer_username}/{channel_id}): {e}")
                    break # Corrupted stream or closed connection
                except json.JSONDecodeError as e:
                    log_connection(f"Peer JSON decode error ({peer_username}/{channel_id}): {e}")
                    break
                except (socket.error, ConnectionResetError, BrokenPipeError, RuntimeError) as e:
                    log_connection(f"Peer socket error ({peer_username}/{channel_id}): {e}")
                    break
                except Exception as e:
                    log_connection(f"Unexpected peer error ({peer_username}/{channel_id}): {e}")
                    break
                
        except (json.JSONDecodeError, ValueError, socket.error) as e:
            log_connection(f"Peer handshake/initialization error: {e}")
        except Exception as e:
            log_connection(f"Unexpected error handling peer connection: {e}")
        finally:
            # Use the cleanup method
            self._cleanup_peer_connection(channel_id, peer_username, client_socket)
            # Notify about peer disconnect (outside lock, after cleanup)
            if channel_id and peer_username and self.peer_status_callback:
                self.peer_status_callback(channel_id, peer_username, False)
            elif not channel_id or not peer_username:
                 log_connection("Peer disconnected before identification during cleanup.")
    
    def connect_to_host(self, channel_id, host_ip, host_port):
        """Connect to a channel host."""
        # Check if already connected under lock
        with self.connections_lock:
            if channel_id in self.peer_connections and self.peer_connections[channel_id]:
                # Already connected to a host for this channel
                log_connection(f"Already connected to host for channel {channel_id}")
                return True

        try:
            # Create new connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host_ip, int(host_port)))
            
            # Send introduction
            intro = json.dumps({
                'type': 'peer_intro',
                'channel_id': channel_id,
                'username': self.username,
                'timestamp': time.time()
            })
            sock.send(intro.encode('utf-8'))
            
            # Wait for acknowledgment
            ack_data = sock.recv(4096).decode('utf-8')
            ack = json.loads(ack_data)
            
            if ack['type'] != 'peer_intro_ack':
                raise ValueError("Invalid response from host")
            
            host_username = ack['username']
            
            # Store connection under lock
            with self.connections_lock:
                # Ensure dict exists
                self.peer_connections.setdefault(channel_id, {})[host_username] = sock
            
            # Start thread to handle incoming data (outside lock)
            threading.Thread(target=self._handle_host_data, 
                          args=(channel_id, host_username, sock), 
                          daemon=True).start()
            
            # Update host status (might be redundant if called elsewhere, but ensures consistency)
            with self.hosts_lock:
                self.channel_hosts[channel_id] = (host_ip, host_port, True)
            log_connection(f"Connected to host {host_username} for channel {channel_id}")
            
            return True
        except Exception as e:
            log_connection(f"Error connecting to host for channel {channel_id}: {e}")
            # Clean up socket if connection failed partially
            try: sock.close()
            except: pass
            return False
    
    def _handle_host_data(self, channel_id, host_username, sock):
        """Handle data from host connection."""
        try:
            while self.running:
                try:
                    # Get message length first
                    length_data = sock.recv(4)
                    if not length_data:
                        log_connection(f"Host {host_username} disconnected (no length data).")
                        break # Clean disconnect
                    
                    msg_length = struct.unpack(">I", length_data)[0]
                    
                    # Get full message
                    chunks = []
                    bytes_received = 0
                    while bytes_received < msg_length:
                        chunk = sock.recv(min(msg_length - bytes_received, 4096))
                        if not chunk:
                            raise RuntimeError("Socket connection closed")
                        chunks.append(chunk)
                        bytes_received += len(chunk)
                    
                    msg_data = b''.join(chunks).decode('utf-8')
                    message = json.loads(msg_data)
                    
                    # Handle message based on type
                    if message['type'] == 'content_update' and self.content_callback:
                        self.content_callback(channel_id, message['content'], 
                                           source=f"host:{host_username}")
            
                except struct.error as e:
                    log_connection(f"Host struct unpack error ({host_username}/{channel_id}): {e}")
                    break # Corrupted stream or closed connection
                except json.JSONDecodeError as e:
                    log_connection(f"Host JSON decode error ({host_username}/{channel_id}): {e}")
                    break
                except (socket.error, ConnectionResetError, BrokenPipeError, RuntimeError) as e:
                    log_connection(f"Host socket error ({host_username}/{channel_id}): {e}")
                    break
                except Exception as e:
                    log_connection(f"Unexpected host error ({host_username}/{channel_id}): {e}")
                    break
            
        except Exception as e:
            log_connection(f"Unexpected error handling host data ({host_username}/{channel_id}): {e}")
        finally:
            # Use the cleanup method
            self._cleanup_peer_connection(channel_id, host_username, sock)
            # Update host status and notify (outside lock, after cleanup)
            with self.hosts_lock:
                if channel_id in self.channel_hosts:
                    host_ip, host_port, _ = self.channel_hosts[channel_id]
                    self.channel_hosts[channel_id] = (host_ip, host_port, False) # Mark as offline

            if self.peer_status_callback:
                self.peer_status_callback(channel_id, host_username, False, is_host=True)
    
    def _cleanup_peer_connection(self, channel_id, peer_username, client_socket):
         """Safely close socket and remove from connection dictionaries."""
         # Close socket first (outside lock)
         try: client_socket.close()
         except: pass

         if not channel_id or not peer_username:
             log_connection("Cleanup skipped: Missing channel_id or peer_username.")
             return

         # Remove from dictionaries under lock
         with self.connections_lock:
             # Remove from outgoing (peer_connections - if it was a host connection)
             if channel_id in self.peer_connections and peer_username in self.peer_connections.get(channel_id, {}):
                 # Check if the socket matches before deleting
                 if self.peer_connections[channel_id].get(peer_username) == client_socket:
                     del self.peer_connections[channel_id][peer_username]
                     log_connection(f"Removed outgoing connection to {peer_username} for {channel_id}")
                     if not self.peer_connections[channel_id]:
                         del self.peer_connections[channel_id] # Remove channel entry if empty

             # Remove from incoming (incoming_connections - if we were hosting)
             if channel_id in self.incoming_connections:
                 initial_len = len(self.incoming_connections[channel_id])
                 self.incoming_connections[channel_id] = [
                     (user, sock) for user, sock in self.incoming_connections[channel_id]
                     if sock != client_socket # Remove based on socket object
                 ]
                 if len(self.incoming_connections[channel_id]) < initial_len:
                      log_connection(f"Removed incoming connection from {peer_username} for {channel_id}")
                 if not self.incoming_connections[channel_id]:
                     del self.incoming_connections[channel_id] # Remove channel entry if empty
    
    def send_content_to_host(self, channel_id, content):
        """Send content to the channel host."""
        host_connection = None
        # Get host connection under lock
        with self.connections_lock:
            if channel_id in self.peer_connections:
                # Assuming only one host connection per channel
                host_connection = next(iter(self.peer_connections[channel_id].values()), None)

        if not host_connection:
            log_connection(f"No host connection found for channel {channel_id} to send content.")
            return False

        try:
            # Send content update
            message = json.dumps({
                'type': 'content_update',
                'channel_id': channel_id,
                'content': content,
                'timestamp': time.time()
            })
            # Send data (outside lock)
            msg_length = len(message)
            host_connection.sendall(struct.pack(">I", msg_length))
            host_connection.sendall(message.encode('utf-8'))

            return True
        except (socket.error, BrokenPipeError) as e:
            log_connection(f"Error sending content to host: {e}. Cleaning up connection.")
            # Get username associated with this socket for cleanup
            host_username = None
            with self.connections_lock:
                 if channel_id in self.peer_connections:
                     for uname, sock in self.peer_connections[channel_id].items():
                         if sock == host_connection:
                             host_username = uname
                             break
            # Cleanup the broken connection
            self._cleanup_peer_connection(channel_id, host_username, host_connection)
            # Notify status
            if host_username and self.peer_status_callback:
                 self.peer_status_callback(channel_id, host_username, False, is_host=True)
            return False
        except Exception as e:
            log_connection(f"Unexpected error sending content to host: {e}")
            return False
    
    def broadcast_content_to_peers(self, channel_id, content):
        """Broadcast content to all connected peers."""
        sockets_to_broadcast = []
        # Get a copy of sockets under lock
        with self.connections_lock:
            if channel_id in self.incoming_connections:
                # Create a list of tuples (username, socket) to broadcast to
                sockets_to_broadcast = list(self.incoming_connections[channel_id])

        if not sockets_to_broadcast:
            return

        message_bytes = json.dumps({
            'type': 'content_update',
            'channel_id': channel_id,
            'content': content,
            'timestamp': time.time()
        }).encode('utf-8')
        message_length_bytes = struct.pack(">I", len(message_bytes))

        # Send to all peers (outside lock)
        # Use threading for potentially better performance if many peers
        def send_to_peer(username, sock):
            try:
                sock.sendall(message_length_bytes)
                sock.sendall(message_bytes)
            except (socket.error, BrokenPipeError) as e:
                log_connection(f"Error sending broadcast to peer {username}: {e}. Cleaning up.")
                # Cleanup the broken connection
                self._cleanup_peer_connection(channel_id, username, sock)
                # Notify status
                if self.peer_status_callback:
                    self.peer_status_callback(channel_id, username, False)
            except Exception as e:
                 log_connection(f"Unexpected error broadcasting to peer {username}: {e}")

        threads = []
        for username, sock in sockets_to_broadcast:
             thread = threading.Thread(target=send_to_peer, args=(username, sock), daemon=True)
             threads.append(thread)
             thread.start()

        # Optionally join threads if blocking is desired, but usually not for broadcast
        # for thread in threads:
        #     thread.join(timeout=1.0) # Add timeout
    
    def update_host_status(self, channel_id, is_online, host_ip=None, host_port=None):
        """Update the status of a channel host."""
        should_connect = False
        current_host_ip = None
        current_host_port = None

        with self.hosts_lock:
            if host_ip and host_port: # If new host info is provided
                 self.channel_hosts[channel_id] = (host_ip, host_port, is_online)
                 current_host_ip, current_host_port = host_ip, host_port
                 log_connection(f"Updated host status for {channel_id}: IP={host_ip}, Port={host_port}, Online={is_online}")
            elif channel_id in self.channel_hosts: # If updating existing entry
                 current_host_ip, current_host_port, _ = self.channel_hosts[channel_id]
                 self.channel_hosts[channel_id] = (current_host_ip, current_host_port, is_online)
                 log_connection(f"Updated host status for {channel_id}: Online={is_online}")
            else: # No existing entry and no new info provided
                 log_connection(f"Cannot update host status for {channel_id}: No existing info.")
                 return

            # Check if we should attempt connection outside the lock
            if is_online and current_host_ip and current_host_port:
                 with self.connections_lock:
                     # Check if not already connected
                     if channel_id not in self.peer_connections or not self.peer_connections.get(channel_id):
                         should_connect = True

        # If host is online and we're not connected, try to connect (outside lock)
        if should_connect:
            log_connection(f"Host for {channel_id} is online, attempting connection...")
            threading.Thread(target=self.connect_to_host,
                          args=(channel_id, current_host_ip, current_host_port),
                          daemon=True).start()
    
    def set_content_callback(self, callback):
        """Set callback for content updates: callback(channel_id, content, source)"""
        self.content_callback = callback
    
    def set_peer_status_callback(self, callback):
        """Set callback for peer status updates: callback(channel_id, username, online, is_host)"""
        self.peer_status_callback = callback
    
    def shutdown(self):
        """Close all connections and stop threads."""
        log_connection("Shutting down PeerConnectionManager...")
        self.running = False
        sockets_to_close = []

        with self.connections_lock:
            # Collect all sockets from peer_connections
            for channel_id, peers in self.peer_connections.items():
                for username, sock in peers.items():
                    sockets_to_close.append(sock)
            self.peer_connections.clear() # Clear the dictionary

            # Collect all sockets from incoming_connections
            for channel_id, connections in self.incoming_connections.items():
                for username, sock in connections:
                    sockets_to_close.append(sock)
            self.incoming_connections.clear() # Clear the dictionary

        # Close sockets outside the lock
        closed_count = 0
        for sock in sockets_to_close:
            try:
                sock.shutdown(socket.SHUT_RDWR) # Attempt graceful shutdown
            except:
                 pass # Ignore errors if already closed or not connected
            try:
                sock.close()
                closed_count += 1
            except:
                pass # Ignore errors if already closed

        log_connection(f"Closed {closed_count} peer sockets.")
        # Note: Listener socket closing is handled in _accept_connections thread exit
