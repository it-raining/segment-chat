import socket
import threading
import json
import time
import struct
from utils import log_connection

class PeerConnectionManager:
    def __init__(self, username="anonymous"):
        self.username = username
        self.peer_connections = {}  # {channel_id: {peer_username: connection}}
        self.channel_hosts = {}     # {channel_id: (host_ip, host_port, online)}
        self.listeners = {}         # {channel_id: listener_socket}
        self.incoming_connections = {} # {channel_id: [connections]}
        self.content_callback = None
        self.peer_status_callback = None
        self.listener_port = None
        self.running = True
        
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
            
            # Store connection
            if channel_id not in self.incoming_connections:
                self.incoming_connections[channel_id] = []
            self.incoming_connections[channel_id].append((peer_username, client_socket))
            
            # Notify about new peer
            if self.peer_status_callback:
                self.peer_status_callback(channel_id, peer_username, True)
            
            # Loop to handle incoming data
            while self.running:
                try:
                    # Get message length first
                    length_data = client_socket.recv(4)
                    if not length_data:
                        break
                        
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
                
                except Exception as e:
                    log_connection(f"Error receiving from peer {peer_username}: {e}")
                    break
                
        except Exception as e:
            log_connection(f"Peer connection error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            # Remove from connections
            if channel_id in self.incoming_connections:
                self.incoming_connections[channel_id] = [
                    (u, s) for u, s in self.incoming_connections[channel_id] 
                    if u != peer_username
                ]
            
            # Notify about peer disconnect
            if self.peer_status_callback:
                self.peer_status_callback(channel_id, peer_username, False)
    
    def connect_to_host(self, channel_id, host_ip, host_port):
        """Connect to a channel host."""
        if channel_id in self.peer_connections:
            # Already connected to this host
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
            
            # Store connection
            host_username = ack['username']
            self.peer_connections[channel_id] = {host_username: sock}
            
            # Start thread to handle incoming data
            threading.Thread(target=self._handle_host_data, 
                          args=(channel_id, host_username, sock), 
                          daemon=True).start()
            
            self.channel_hosts[channel_id] = (host_ip, host_port, True)
            log_connection(f"Connected to host for channel {channel_id}")
            
            return True
        except Exception as e:
            log_connection(f"Error connecting to host for channel {channel_id}: {e}")
            return False
    
    def _handle_host_data(self, channel_id, host_username, sock):
        """Handle data from host connection."""
        try:
            while self.running:
                # Get message length first
                length_data = sock.recv(4)
                if not length_data:
                    break
                    
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
            
        except Exception as e:
            log_connection(f"Error receiving from host {host_username}: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            
            # Remove from connections
            if channel_id in self.peer_connections:
                if host_username in self.peer_connections[channel_id]:
                    del self.peer_connections[channel_id][host_username]
                if not self.peer_connections[channel_id]:
                    del self.peer_connections[channel_id]
            
            # Update host status
            if channel_id in self.channel_hosts:
                host_ip, host_port, _ = self.channel_hosts[channel_id]
                self.channel_hosts[channel_id] = (host_ip, host_port, False)
            
            # Notify about host disconnect
            if self.peer_status_callback:
                self.peer_status_callback(channel_id, host_username, False, is_host=True)
    
    def send_content_to_host(self, channel_id, content):
        """Send content to the channel host."""
        if channel_id not in self.peer_connections:
            return False
            
        # Get host connection
        host_connection = next(iter(self.peer_connections[channel_id].values()), None)
        if not host_connection:
            return False
            
        try:
            # Send content update
            message = json.dumps({
                'type': 'content_update',
                'channel_id': channel_id,
                'content': content,
                'timestamp': time.time()
            })
            
            # Send length prefix then data
            msg_length = len(message)
            host_connection.sendall(struct.pack(">I", msg_length))
            host_connection.sendall(message.encode('utf-8'))
            
            return True
        except Exception as e:
            log_connection(f"Error sending content to host: {e}")
            return False
    
    def broadcast_content_to_peers(self, channel_id, content):
        """Broadcast content to all connected peers."""
        if channel_id not in self.incoming_connections or not self.incoming_connections[channel_id]:
            return
            
        message = json.dumps({
            'type': 'content_update',
            'channel_id': channel_id,
            'content': content,
            'timestamp': time.time()
        })
        
        # Send to all peers
        for username, sock in self.incoming_connections[channel_id]:
            try:
                # Send length prefix then data
                msg_length = len(message)
                sock.sendall(struct.pack(">I", msg_length))
                sock.sendall(message.encode('utf-8'))
            except Exception as e:
                log_connection(f"Error sending to peer {username}: {e}")
    
    def update_host_status(self, channel_id, is_online, host_ip=None, host_port=None):
        """Update the status of a channel host."""
        if channel_id not in self.channel_hosts and not host_ip:
            return
            
        if host_ip:
            self.channel_hosts[channel_id] = (host_ip, host_port, is_online)
        else:
            host_ip, host_port, _ = self.channel_hosts[channel_id]
            self.channel_hosts[channel_id] = (host_ip, host_port, is_online)
        
        # If host is online and we're not connected, try to connect
        if is_online and channel_id not in self.peer_connections:
            threading.Thread(target=self.connect_to_host, 
                          args=(channel_id, host_ip, host_port), 
                          daemon=True).start()
    
    def set_content_callback(self, callback):
        """Set callback for content updates: callback(channel_id, content, source)"""
        self.content_callback = callback
    
    def set_peer_status_callback(self, callback):
        """Set callback for peer status updates: callback(channel_id, username, online, is_host)"""
        self.peer_status_callback = callback
    
    def shutdown(self):
        """Close all connections and stop threads."""
        self.running = False
        
        # Close all peer connections
        for channel_id, peers in self.peer_connections.items():
            for username, sock in peers.items():
                try:
                    sock.close()
                except:
                    pass
        
        # Close all incoming connections
        for channel_id, connections in self.incoming_connections.items():
            for username, sock in connections:
                try:
                    sock.close()
                except:
                    pass
        
        self.peer_connections = {}
        self.incoming_connections = {}
