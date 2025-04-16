import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import json
import struct
import traceback
from src.common.utils import log_connection

class AdminClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.authenticated = False
        # Add a timeout to prevent hanging
        self.timeout = 10  # 10 seconds timeout
        
    def connect(self):
        try:
            if self.socket:
                try:
                    self.socket.close()
                except: pass
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            self.connected = True
            log_connection("Admin client connected to server.")
            return True
        except Exception as e:
            log_connection(f"Admin connection error: {str(e)}")
            self.connected = False
            self.authenticated = False
            return False
        
    def _send_framed_request(self, request_dict):
        """Encodes, frames, and sends a request dictionary."""
        if not self.connected or not self.socket:
             log_connection("Admin cannot send request: Not connected.")
             return False
        try:
            message_json = json.dumps(request_dict)
            message_bytes = message_json.encode('utf-8')
            header = struct.pack('>I', len(message_bytes))
            self.socket.sendall(header + message_bytes)
            # log_connection(f"Admin sent framed request: {request_dict.get('type', 'unknown')}")
            return True
        except (BrokenPipeError, ConnectionResetError, socket.error) as e:
            log_connection(f"Admin failed to send request (disconnected?): {e}")
            self.connected = False
            self.authenticated = False
            return False
        except Exception as e:
            log_connection(f"Admin error sending request: {e}")
            self.connected = False
            self.authenticated = False
            return False

    def _receive_framed_response(self):
        """Receives, unframes, and decodes a response dictionary."""
        if not self.connected or not self.socket:
             log_connection("Admin cannot receive response: Not connected.")
             return None

        buffer = b""
        header_size = 4
        try:
            # Receive Header
            self.socket.settimeout(self.timeout) # Ensure timeout is set for recv
            while len(buffer) < header_size:
                chunk = self.socket.recv(header_size - len(buffer))
                if not chunk:
                    log_connection("Admin server disconnected (no header).")
                    self.connected = False
                    self.authenticated = False
                    return None
                buffer += chunk

            msg_length = struct.unpack('>I', buffer[:header_size])[0]
            buffer = buffer[header_size:]

            # Receive Body
            while len(buffer) < msg_length:
                bytes_to_read = min(4096, msg_length - len(buffer))
                chunk = self.socket.recv(bytes_to_read)
                if not chunk:
                    log_connection("Admin server disconnected (no body).")
                    self.connected = False
                    self.authenticated = False
                    return None
                buffer += chunk

            message_json = buffer[:msg_length].decode('utf-8')
            # Keep remaining buffer data if any (though less likely in req/res pattern)
            # buffer = buffer[msg_length:]

            response_dict = json.loads(message_json)
            log_connection(f"Admin received framed response: {response_dict.get('type', 'unknown')}")
            return response_dict

        except (ConnectionResetError, ConnectionAbortedError, socket.error) as e:
            log_connection(f"Admin connection error receiving response: {e}")
            self.connected = False
            self.authenticated = False
            return None
        except socket.timeout:
            log_connection("Admin connection timed out waiting for server response")
            # Don't necessarily disconnect on timeout, maybe retry later
            return None
        except (struct.error, json.JSONDecodeError) as e:
            log_connection(f"Admin error decoding/unpacking response: {e}")
            self.connected = False # Assume corrupted stream
            self.authenticated = False
            return None
        except Exception as e:
            log_connection(f"Admin unexpected error receiving response: {e}")
            traceback.print_exc()
            self.connected = False
            self.authenticated = False
            return None
        
    def admin_login(self, username, password):
        if not self.connected:
            return False, "Not connected to server"
            
        request = {
            "type": "admin_login",
            "username": username,
            "password": password
        }
        
        try:
            if not self._send_framed_request(request):
                return False, "Failed to send login request"

            response = self._receive_framed_response()

            if response is None:
                # Error logged in _receive_framed_response
                return False, "Failed to receive login response or connection lost"

            log_connection(f"Admin login response: {response}")

            if response.get('type') == 'admin_login_response':
                self.authenticated = response.get('success', False)
                return self.authenticated, response.get('message', 'No message received.')
            else:
                log_connection(f"Received unexpected response type: {response.get('type')}")
                return False, "Invalid response type from server"

        except Exception as e:
            log_connection(f"Admin login unexpected error: {str(e)}")
            traceback.print_exc()
            self.connected = False # Assume connection is compromised
            self.authenticated = False
            return False, f"An unexpected error occurred: {str(e)}"
    
    def get_users(self):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {"type": "get_users"}
        if not self._send_framed_request(request):
             return False, "Failed to send request" # Error sending

        response = self._receive_framed_response()
        if response and response.get('type') == 'get_users_response':
            # Assuming success is implied if type matches and users key exists
            return True, response.get('users', []) # Return empty list if key missing
        elif response is None and not self.connected:
             return False, "Connection lost" # Error receiving (connection lost)
        elif response is None:
             return False, "No response from server (timeout?)" # Error receiving (timeout)
        else:
            # Invalid response type or structure
            return False, f"Invalid response from server: {str(response)[:100]}"

    def create_user(self, username, password, is_admin=False):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {
            "type": "admin_create_user",
            "username": username,
            "password": password,
            "is_admin": is_admin
        }
        if not self._send_framed_request(request):
             return False, "Failed to send request"

        response = self._receive_framed_response()
        if response and response.get('type') == 'admin_create_user_response':
            return response.get('success', False), response.get('message', 'Unknown response')
        elif response is None and not self.connected:
             return False, "Connection lost"
        elif response is None:
             return False, "No response from server (timeout?)"
        else:
            return False, f"Invalid response from server: {str(response)[:100]}"

    def delete_user(self, username):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {"type": "admin_delete_user", "username": username}
        if not self._send_framed_request(request):
             return False, "Failed to send request"

        response = self._receive_framed_response()
        if response and response.get('type') == 'admin_delete_user_response':
            return response.get('success', False), response.get('message', 'Unknown response')
        elif response is None and not self.connected:
             return False, "Connection lost"
        elif response is None:
             return False, "No response from server (timeout?)"
        else:
            return False, f"Invalid response from server: {str(response)[:100]}"

    def get_channels(self):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {"type": "get_channels"} # Server should handle filtering for admin if needed
        if not self._send_framed_request(request):
             return False, "Failed to send request"

        response = self._receive_framed_response()
        # Assuming server sends 'get_channels_response' for admin too
        if response and response.get('type') == 'get_channels_response':
             # Assuming success is implied if type matches and channels key exists
            return True, response.get('channels', [])
        elif response is None and not self.connected:
             return False, "Connection lost"
        elif response is None:
             return False, "No response from server (timeout?)"
        else:
            return False, f"Invalid response from server: {str(response)[:100]}"

    def create_channel(self, channel_id, is_public=True):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {
            "type": "admin_create_channel",
            "channel_id": channel_id,
            "is_public": is_public
        }
        if not self._send_framed_request(request):
             return False, "Failed to send request"

        response = self._receive_framed_response()
        if response and response.get('type') == 'admin_create_channel_response':
            return response.get('success', False), response.get('message', 'Unknown response')
        elif response is None and not self.connected:
             return False, "Connection lost"
        elif response is None:
             return False, "No response from server (timeout?)"
        else:
            return False, f"Invalid response from server: {str(response)[:100]}"

    def delete_channel(self, channel_id):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {"type": "admin_delete_channel", "channel_id": channel_id}
        if not self._send_framed_request(request):
             return False, "Failed to send request"

        response = self._receive_framed_response()
        if response and response.get('type') == 'admin_delete_channel_response':
            return response.get('success', False), response.get('message', 'Unknown response')
        elif response is None and not self.connected:
             return False, "Connection lost"
        elif response is None:
             return False, "No response from server (timeout?)"
        else:
            return False, f"Invalid response from server: {str(response)[:100]}"

    def shutdown_server(self):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"

        request = {"type": "admin_shutdown_server"}
        if not self._send_framed_request(request):
             return False, "Failed to send shutdown request"
        response = self._receive_framed_response()

        if response and response.get('type') == 'admin_shutdown_server_response':
            return response.get('success', False), response.get('message', 'Server acknowledged shutdown.')
        elif response is None and not self.connected:
             log_connection("Server connection closed, likely due to shutdown.")
             return True, "Shutdown initiated, server connection closed."
        elif response is None:
             log_connection("Timeout waiting for shutdown response, assuming shutdown initiated.")
             return True, "Shutdown initiated, no confirmation received (timeout)."
        else:
            return False, f"Invalid response from server: {str(response)[:100]}"

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        self.authenticated = False