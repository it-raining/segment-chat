import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import json
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
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)  # Set a timeout for operations
            self.socket.connect((self.host, self.port))
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False
            
    def admin_login(self, username, password):
        if not self.connected:
            return False, "Not connected to server"
            
        request = {
            "type": "admin_login",
            "username": username,
            "password": password
        }
        
        try:
            # Increase timeout for more reliable operation
            self.socket.settimeout(15.0)  # 15 seconds timeout for login
            self.socket.send(json.dumps(request).encode('utf-8'))
            
            # Wait for response
            response_data = self.socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            
            log_connection(f"Admin login response: {response}")
            
            if response['type'] == 'admin_login_response':
                self.authenticated = response['success']
                return response['success'], response['message']
            return False, "Invalid response from server"
        except socket.timeout:
            log_connection("Admin login timed out")
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            log_connection(f"Admin login connection error: {str(e)}")
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            log_connection(f"Admin login error: {str(e)}")
            return False, str(e)
    
    def get_users(self):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {"type": "get_users"}
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'get_users_response':
                return True, response['users']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def create_user(self, username, password, is_admin=False):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {
            "type": "admin_create_user",
            "username": username,
            "password": password,
            "is_admin": is_admin
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'admin_create_user_response':
                return response['success'], response['message']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def delete_user(self, username):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {
            "type": "admin_delete_user",
            "username": username
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'admin_delete_user_response':
                return response['success'], response['message']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def get_channels(self):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {"type": "get_channels"}
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'get_channels_response':
                return True, response['channels']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def create_channel(self, channel_id, is_public=True):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {
            "type": "admin_create_channel",
            "channel_id": channel_id,
            "is_public": is_public
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'admin_create_channel_response':
                return response['success'], response['message']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def delete_channel(self, channel_id):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {
            "type": "admin_delete_channel",
            "channel_id": channel_id
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'admin_delete_channel_response':
                return response['success'], response['message']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def shutdown_server(self):
        if not self.connected or not self.authenticated:
            return False, "Not authenticated as admin"
            
        request = {"type": "admin_shutdown_server"}
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            self.socket.settimeout(self.timeout)
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['type'] == 'admin_shutdown_server_response':
                return response['success'], response['message']
            return False, "Invalid response from server"
        except socket.timeout:
            return False, "Connection timed out waiting for server response"
        except ConnectionError as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        self.authenticated = False