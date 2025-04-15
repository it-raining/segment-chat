import socket
import threading
import json
import sqlite3
import os
from src.common.protocols import (
    create_submit_info_response, create_get_list_response,
    create_login_response, create_sync_content_response,
    create_create_channel_response, create_join_channel_response,
    create_get_channel_host_response, create_register_response,
    create_get_channels_response, create_get_messages_response
)
from src.common.utils import log_connection
import signal
import sys
import time
import datetime

HOST = '0.0.0.0'
PORT = 5000
peers = []
active_users = {}  # Track active users and their authentication status
peers_lock = threading.Lock()
users_lock = threading.Lock()

server_socket = None  # Global reference to the server socket
shutdown_flag = threading.Event()

channel_hosts = {}  # Track channel hosts and their status
channel_hosts_lock = threading.Lock()
host_timeout = 60  # Consider host offline after 60 seconds without heartbeat

active_sockets = {}  # Track active client sockets by client_id

# Add tracking for livestreams
active_livestreams = {}  # {channel_id: [{username, host_ip, livestream_port}]}
livestreams_lock = threading.Lock()

# Add channel users tracking
channel_users = {}  # {channel_id: {username: client_id}}
channel_users_lock = threading.Lock()

# Database setup
conn = sqlite3.connect('data/segment_chat.db', check_same_thread=False)
cursor = conn.cursor()

# Create channels table with host information
cursor.execute('''
CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    host_ip TEXT,
    host_port INTEGER,
    content TEXT,
    is_public INTEGER DEFAULT 1,
    peer_port INTEGER DEFAULT NULL,
    last_host_ping REAL DEFAULT NULL
)
''')

# Users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)
''')

# Admin users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY,
    password TEXT
)
''')

# Add to the schema
cursor.execute('''
CREATE TABLE IF NOT EXISTS livestreams (
    channel_id TEXT,
    username TEXT,
    host_ip TEXT,
    livestream_port INTEGER,
    created_at REAL,
    PRIMARY KEY (channel_id, username)
)
''')

# Add a default admin user if none exists
cursor.execute("SELECT COUNT(*) FROM admin_users")
if cursor.fetchone()[0] == 0:
    cursor.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", 
                 ('admin', 'admin'))
    print("Created default admin user: admin/admin")

# Check if is_public column exists in channels table, add it if missing
try:
    cursor.execute("SELECT is_public FROM channels LIMIT 1")
except sqlite3.OperationalError:
    print("Adding 'is_public' column to channels table...")
    cursor.execute("ALTER TABLE channels ADD COLUMN is_public INTEGER DEFAULT 1")
    cursor.execute("SELECT is_public FROM channels LIMIT 1")

# Check if peer_port column exists in channels table, add it if missing
try:
    cursor.execute("SELECT peer_port FROM channels LIMIT 1")
except sqlite3.OperationalError:
    print("Adding 'peer_port' column to channels table...")
    cursor.execute("ALTER TABLE channels ADD COLUMN peer_port INTEGER DEFAULT NULL")
    cursor.execute("SELECT peer_port FROM channels LIMIT 1")

# Check if last_host_ping column exists in channels table, add it if missing
try:
    cursor.execute("SELECT last_host_ping FROM channels LIMIT 1")
except sqlite3.OperationalError:
    print("Adding 'last_host_ping' column to channels table...")
    cursor.execute("ALTER TABLE channels ADD COLUMN last_host_ping REAL DEFAULT NULL")
    cursor.execute("SELECT last_host_ping FROM channels LIMIT 1")

conn.commit()

def check_host_status():
    """Check status of all channel hosts and update if any have timed out."""
    while not shutdown_flag.is_set():
        current_time = time.time()
        channels_updated = []
        
        # Check all channels with hosts
        cursor.execute(
            "SELECT id, host_ip, host_port, peer_port, last_host_ping FROM channels " +
            "WHERE last_host_ping IS NOT NULL"
        )
        for row in cursor.fetchall():
            channel_id, host_ip, host_port, peer_port, last_ping = row
            
            # Check if host has timed out (60 seconds)
            if last_ping < current_time - host_timeout:
                # Mark host as offline
                cursor.execute(
                    "UPDATE channels SET last_host_ping = NULL WHERE id = ?",
                    (channel_id,)
                )
                conn.commit()
                channels_updated.append(channel_id)
                log_connection(f"Host for channel {channel_id} marked offline due to timeout")
        
        # Notify clients about host status changes
        for channel_id in channels_updated:
            broadcast_host_status(channel_id, False)
            
        time.sleep(10)  # Check every 10 seconds

def broadcast_host_status(channel_id, is_online):
    """Broadcast host status update to all connected clients."""
    cursor.execute(
        "SELECT host_ip, host_port, peer_port FROM channels WHERE id=?", 
        (channel_id,)
    )
    result = cursor.fetchone()
    if not result:
        return
    
    host_ip, host_port, peer_port = result
    notification = {
        "type": "channel_host_info",
        "channel_id": channel_id,
        "host_ip": host_ip,
        "host_port": host_port,
        "peer_port": peer_port,
        "is_online": is_online,
        "timestamp": time.time()
    }
    notification_json = json.dumps(notification)
    
    # Send to all active clients
    with users_lock:
        for client_id, client_socket in active_sockets.items():
            try:
                client_socket.send(notification_json.encode('utf-8'))
            except:
                # Skip failed sends, they'll be handled by connection loss detection
                pass

def handle_host_heartbeat(client_socket, client_id, data):
    """Handle heartbeat from channel host."""
    channel_id = data['channel_id']
    timestamp = data.get('timestamp', time.time())
    
    # Get username
    with users_lock:
        username = active_users.get(client_id, {}).get("username")
    
    if not username:
        # Not authenticated
        return
    
    # Update channel host timestamp
    cursor.execute(
        "UPDATE channels SET last_host_ping = ? WHERE id = ?",
        (timestamp, channel_id)
    )
    conn.commit()
    
    # Check if this is a new host coming online
    cursor.execute(
        "SELECT last_host_ping FROM channels WHERE id = ?",
        (channel_id,)
    )
    result = cursor.fetchone()
    if result and result[0] is None:
        # Host was previously offline, broadcast status change
        broadcast_host_status(channel_id, True)
        log_connection(f"Host for channel {channel_id} is now online")

def handle_host_register(client_socket, client_id, data):
    """Handle request to register as a channel host."""
    channel_id = data['channel_id']
    host_ip = data['host_ip']
    peer_port = data.get('peer_port')
    
    # Verify authentication
    with users_lock:
        is_authenticated = active_users.get(client_id, {}).get("authenticated", False)
        username = active_users.get(client_id, {}).get("username")
    
    if not is_authenticated:
        response = json.dumps({
            "type": "host_register_response",
            "success": False,
            "message": "Authentication required to be a host"
        })
        client_socket.send(response.encode('utf-8'))
        return
    
    # Check if channel exists
    cursor.execute("SELECT id FROM channels WHERE id = ?", (channel_id,))
    if not cursor.fetchone():
        response = json.dumps({
            "type": "host_register_response",
            "success": False,
            "message": "Channel does not exist"
        })
        client_socket.send(response.encode('utf-8'))
        return
    
    # Update channel with host info
    try:
        cursor.execute(
            "UPDATE channels SET host_ip = ?, peer_port = ?, last_host_ping = ? WHERE id = ?",
            (host_ip, peer_port, time.time(), channel_id)
        )
        conn.commit()
        
        # Notify clients of new host
        broadcast_host_status(channel_id, True)
        
        response = json.dumps({
            "type": "host_register_response",
            "success": True,
            "message": "Successfully registered as host",
            "channel_id": channel_id
        })
        client_socket.send(response.encode('utf-8'))
        
        log_connection(f"User {username} registered as host for channel {channel_id}")
    except Exception as e:
        response = json.dumps({
            "type": "host_register_response",
            "success": False,
            "message": f"Error: {str(e)}"
        })
        client_socket.send(response.encode('utf-8'))

def handle_get_channel_host_info(client_socket, data):
    """Handle request for channel host info."""
    channel_id = data['channel_id']
    
    cursor.execute(
        "SELECT host_ip, host_port, peer_port, last_host_ping FROM channels WHERE id = ?",
        (channel_id,)
    )
    result = cursor.fetchone()
    
    if not result:
        response = json.dumps({
            "type": "channel_host_info",
            "channel_id": channel_id,
            "is_online": False,
            "timestamp": time.time()
        })
    else:
        host_ip, host_port, peer_port, last_ping = result
        is_online = last_ping is not None and last_ping > time.time() - host_timeout
        response = json.dumps({
            "type": "channel_host_info",
            "channel_id": channel_id,
            "host_ip": host_ip,
            "host_port": host_port,
            "peer_port": peer_port,
            "is_online": is_online,
            "timestamp": time.time()
        })
    
    client_socket.send(response.encode('utf-8'))

def handle_join_channel(client_socket, client_id, data):
    """Handle request to join a channel with user tracking."""
    channel_id = data['channel_id']
    
    # Get username of the client
    with users_lock:
        username = active_users.get(client_id, {}).get("username", "visitor")
    
    # Check if channel exists and if it's public or user is authenticated
    cursor.execute("SELECT is_public FROM channels WHERE id=?", (channel_id,))
    result = cursor.fetchone()
    if not result:
        response = create_join_channel_response(False, "Channel not found")
    elif result[0] == 0:  # Private channel
        with users_lock:
            is_authenticated = active_users.get(client_id, {}).get("authenticated", False)
        if not is_authenticated:
            response = create_join_channel_response(False, "Authentication required for private channels")
        else:
            # Add user to channel users
            with channel_users_lock:
                if channel_id not in channel_users:
                    channel_users[channel_id] = {}
                channel_users[channel_id][username] = client_id
            
            # Broadcast join notification
            broadcast_user_join(channel_id, username)
            
            # Automatically send the list of users in this channel
            handle_get_channel_users(client_socket, {"channel_id": channel_id})
            
            response = create_join_channel_response(True, "Joined private channel")
    else:
        # Add user to channel users
        with channel_users_lock:
            if channel_id not in channel_users:
                channel_users[channel_id] = {}
            channel_users[channel_id][username] = client_id
        
        # Broadcast join notification
        broadcast_user_join(channel_id, username)
        
        # Automatically send the list of users in this channel
        handle_get_channel_users(client_socket, {"channel_id": channel_id})
        
        response = create_join_channel_response(True, "Joined channel")
    
    # Log the channel users for debugging
    with channel_users_lock:
        log_connection(f"Channel {channel_id} users: {list(channel_users.get(channel_id, {}).keys())}")
    
    client_socket.send(response.encode('utf-8'))

def handle_leave_channel(client_socket, client_id, data):
    """Handle request to leave a channel."""
    channel_id = data['channel_id']
    
    # Get username of the client
    with users_lock:
        username = active_users.get(client_id, {}).get("username", "visitor")
    
    # Remove user from channel users
    user_removed = False
    with channel_users_lock:
        if channel_id in channel_users and username in channel_users[channel_id]:
            del channel_users[channel_id][username]
            user_removed = True
            
            # Clean up empty channels
            if not channel_users[channel_id]:
                del channel_users[channel_id]
    
    # Broadcast leave notification if user was in the channel
    if user_removed:
        broadcast_user_leave(channel_id, username)
    
    response = json.dumps({
        "type": "leave_channel_response",
        "success": True
    })
    client_socket.send(response.encode('utf-8'))

def handle_get_channel_users(client_socket, data):
    """Handle request for channel users."""
    channel_id = data['channel_id']
    
    with channel_users_lock:
        users = list(channel_users.get(channel_id, {}).keys())
    
    log_connection(f"Sending user list for channel {channel_id}: {users}")
    
    response = json.dumps({
        "type": "channel_users_response",
        "channel_id": channel_id,
        "users": users
    })
    client_socket.send(response.encode('utf-8'))

def broadcast_user_join(channel_id, username):
    """Broadcast to all clients in a channel that a user has joined."""
    notification = json.dumps({
        "type": "user_channel_event",
        "event": "join",
        "channel_id": channel_id,
        "username": username,
        "timestamp": time.time()
    })
    
    # Send to all active clients
    with users_lock:
        for client_id, client_socket in active_sockets.items():
            try:
                client_socket.send(notification.encode('utf-8'))
            except:
                pass  # Skip failed sends

def broadcast_user_leave(channel_id, username):
    """Broadcast to all clients in a channel that a user has left."""
    notification = json.dumps({
        "type": "user_channel_event",
        "event": "leave",
        "channel_id": channel_id,
        "username": username,
        "timestamp": time.time()
    })
    
    # Send to all active clients
    with users_lock:
        for client_id, client_socket in active_sockets.items():
            try:
                client_socket.send(notification.encode('utf-8'))
            except:
                pass  # Skip failed sends

def remove_user_from_channels(client_id):
    """Remove a user from all channels when they disconnect."""
    with users_lock:
        username = active_users.get(client_id, {}).get("username")
    
    if not username:
        return
    
    channels_to_notify = []
    
    with channel_users_lock:
        for channel_id, users in list(channel_users.items()):
            if username in users:
                del users[username]
                channels_to_notify.append(channel_id)
                
                # Clean up empty channels
                if not users:
                    del channel_users[channel_id]
    
    # Notify about user leaving
    for channel_id in channels_to_notify:
        broadcast_user_leave(channel_id, username)

def handle_register_livestream(client_socket, client_id, data):
    """Handle request to register a livestream."""
    channel_id = data['channel_id']
    host_ip = data['host_ip']
    livestream_port = data['livestream_port']
    username = data.get('username', 'anonymous')
    
    # Verify authentication
    with users_lock:
        is_authenticated = active_users.get(client_id, {}).get("authenticated", False)
    
    if not is_authenticated:
        response = json.dumps({
            "type": "register_livestream_response",
            "success": False,
            "message": "Authentication required to host a livestream"
        })
        client_socket.send(response.encode('utf-8'))
        return
    
    # Add to tracking
    with livestreams_lock:
        if channel_id not in active_livestreams:
            active_livestreams[channel_id] = []
        
        # Remove any existing streams by this user
        active_livestreams[channel_id] = [s for s in active_livestreams[channel_id] 
                                       if s.get('username') != username]
        
        # Add new stream
        active_livestreams[channel_id].append({
            'username': username,
            'host_ip': host_ip,
            'livestream_port': livestream_port,
            'created_at': time.time()
        })
    
    # Store in database for persistence
    try:
        cursor.execute(
            "INSERT OR REPLACE INTO livestreams (channel_id, username, host_ip, livestream_port, created_at) VALUES (?, ?, ?, ?, ?)",
            (channel_id, username, host_ip, livestream_port, time.time())
        )
        conn.commit()
    except Exception as e:
        log_connection(f"Database error saving livestream: {e}")
    
    # Notify clients in this channel
    broadcast_livestream_update(channel_id)
    
    response = json.dumps({
        "type": "register_livestream_response",
        "success": True,
        "message": "Livestream registered successfully"
    })
    client_socket.send(response.encode('utf-8'))

def handle_unregister_livestream(client_socket, client_id, data):
    """Handle request to unregister a livestream."""
    channel_id = data['channel_id']
    username = data.get('username', 'anonymous')
    
    # Remove from tracking
    with livestreams_lock:
        if channel_id in active_livestreams:
            active_livestreams[channel_id] = [s for s in active_livestreams[channel_id] 
                                           if s.get('username') != username]
            if not active_livestreams[channel_id]:
                del active_livestreams[channel_id]
    
    # Remove from database
    try:
        cursor.execute(
            "DELETE FROM livestreams WHERE channel_id = ? AND username = ?",
            (channel_id, username)
        )
        conn.commit()
    except Exception as e:
        log_connection(f"Database error removing livestream: {e}")
    
    # Notify clients in this channel
    broadcast_livestream_update(channel_id)
    
    response = json.dumps({
        "type": "unregister_livestream_response",
        "success": True,
        "message": "Livestream unregistered successfully"
    })
    client_socket.send(response.encode('utf-8'))

def handle_get_active_streams(client_socket, data):
    """Handle request to get active streams for a channel."""
    channel_id = data['channel_id']
    
    with livestreams_lock:
        streams = active_livestreams.get(channel_id, [])
    
    # If no streams in memory, check database for any recent ones
    if not streams:
        try:
            # Get streams from last 5 minutes (they might still be active)
            five_mins_ago = time.time() - 300
            cursor.execute(
                "SELECT username, host_ip, livestream_port, created_at FROM livestreams WHERE channel_id = ? AND created_at > ?",
                (channel_id, five_mins_ago)
            )
            
            for row in cursor.fetchall():
                username, host_ip, livestream_port, created_at = row
                if channel_id not in active_livestreams:
                    active_livestreams[channel_id] = []
                
                active_livestreams[channel_id].append({
                    'username': username,
                    'host_ip': host_ip,
                    'livestream_port': livestream_port,
                    'created_at': created_at
                })
            
            streams = active_livestreams.get(channel_id, [])
        except Exception as e:
            log_connection(f"Database error fetching livestreams: {e}")
    
    response = json.dumps({
        "type": "active_streams_response",
        "channel_id": channel_id,
        "streams": streams
    })
    client_socket.send(response.encode('utf-8'))

def broadcast_livestream_update(channel_id):
    """Broadcast livestream updates to clients in a channel."""
    with livestreams_lock:
        streams = active_livestreams.get(channel_id, [])
    
    notification = json.dumps({
        "type": "livestream_update",
        "channel_id": channel_id,
        "streams": streams
    })
    
    # Send to all active clients that might be in this channel
    with users_lock:
        for client_id, client_socket in active_sockets.items():
            try:
                client_socket.send(notification.encode('utf-8'))
            except:
                pass

def broadcast_message_update(channel_id, content):
    """Broadcast message updates to all clients in a channel."""
    # Get client IDs for users in this channel
    client_ids = []
    with channel_users_lock:
        if channel_id in channel_users:
            client_ids = list(channel_users[channel_id].values())
    
    if not client_ids:
        return
    
    # Create message update notification
    notification = json.dumps({
        "type": "message_update",
        "channel_id": channel_id,
        "content": content,
        "timestamp": time.time()
    })
    
    # Send to all clients in this channel
    with users_lock:
        for client_id in client_ids:
            if client_id in active_sockets:
                try:
                    active_sockets[client_id].send(notification.encode('utf-8'))
                except:
                    # Skip failed sends, they'll be handled by connection loss detection
                    pass
    
    log_connection(f"Broadcasted message update for channel {channel_id} to {len(client_ids)} clients")

def create_get_messages_response(success, messages, message=None):
    response = {
        "type": "get_messages_response",
        "success": success,
        "messages": messages
    }
    if message:
        response["message"] = message
    return json.dumps(response)

def handle_get_messages(client_socket, channel_id):
    """Handle request to get messages for a channel with better error handling."""
    log_connection(f"Retrieving messages for channel {channel_id}")
    
    try:
        cursor.execute("SELECT content FROM channels WHERE id=?", (channel_id,))
        result = cursor.fetchone()
        
        if result:
            content = result[0]
            # Handle NULL/None content
            if content is None:
                log_connection(f"Channel {channel_id} has NULL content, initializing with empty array")
                # Initialize with empty array and update the database
                empty_content = json.dumps([])
                cursor.execute("UPDATE channels SET content=? WHERE id=?", (empty_content, channel_id))
                conn.commit()
                messages = []
            else:
                try:
                    messages = json.loads(content)
                except json.JSONDecodeError as e:
                    log_connection(f"Error parsing stored messages for channel {channel_id}: {e}")
                    # Reset to empty array on parsing error
                    messages = []
                    cursor.execute("UPDATE channels SET content=? WHERE id=?", (json.dumps(messages), channel_id))
                    conn.commit()
            
            log_connection(f"Sending {len(messages)} messages for channel {channel_id}")
            response = create_get_messages_response(True, messages)
        else:
            log_connection(f"Channel {channel_id} not found")
            response = create_get_messages_response(False, [], "Channel not found")
    except Exception as e:
        log_connection(f"Error getting messages from DB: {e}")
        response = create_get_messages_response(False, [], f"Error getting messages: {e}")
    
    try:
        client_socket.send(response.encode('utf-8'))
    except ConnectionError as e:
        log_connection(f"Failed to send messages to client: {e}")

def handle_admin_login(client_socket, client_id, data):
    """Handle admin login request."""
    with users_lock:
        if active_users.get(client_id, {}).get("authenticated", False):
            response = {
                "type": "admin_login_response",
                "success": False,
                "message": "Already authenticated"
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            return
    
    username = data['username']
    password = data['password']
    
    cursor.execute("SELECT * FROM admin_users WHERE username=? AND password=?", (username, password))
    if cursor.fetchone():
        with users_lock:
            active_users[client_id] = {
                "authenticated": True, 
                "username": username,
                "is_admin": True
            }
        response = {
            "type": "admin_login_response",
            "success": True,
            "message": "Admin login successful"
        }
    else:
        response = {
            "type": "admin_login_response",
            "success": False,
            "message": "Invalid admin credentials"
        }
    client_socket.send(json.dumps(response).encode('utf-8'))

def handle_get_users(client_socket, client_id):
    """Handle request to get all users."""
    # Verify admin authentication
    with users_lock:
        is_admin = active_users.get(client_id, {}).get("is_admin", False)
    
    if not is_admin:
        response = {
            "type": "get_users_response",
            "success": False,
            "message": "Admin privileges required"
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
        
    # Get users from database
    cursor.execute("SELECT username FROM users")
    regular_users = [{"username": row[0], "is_admin": False} for row in cursor.fetchall()]
    
    cursor.execute("SELECT username FROM admin_users")
    admin_users = [{"username": row[0], "is_admin": True} for row in cursor.fetchall()]
    
    # Combine and send
    response = {
        "type": "get_users_response",
        "success": True,
        "users": regular_users + admin_users
    }
    client_socket.send(json.dumps(response).encode('utf-8'))

def handle_admin_create_user(client_socket, client_id, data):
    """Handle request to create a new user by an admin."""
    # Verify admin authentication
    with users_lock:
        is_admin = active_users.get(client_id, {}).get("is_admin", False)
    
    if not is_admin:
        response = {
            "type": "admin_create_user_response",
            "success": False,
            "message": "Admin privileges required"
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
        
    username = data['username']
    password = data['password']
    is_admin_user = data.get('is_admin', False)
    
    try:
        if is_admin_user:
            cursor.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", 
                         (username, password))
        else:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                         (username, password))
        conn.commit()
        
        response = {
            "type": "admin_create_user_response",
            "success": True,
            "message": f"User {username} created successfully"
        }
    except sqlite3.IntegrityError:
        response = {
            "type": "admin_create_user_response",
            "success": False,
            "message": "Username already exists"
        }
    except Exception as e:
        response = {
            "type": "admin_create_user_response",
            "success": False,
            "message": f"Error creating user: {str(e)}"
        }
    
    client_socket.send(json.dumps(response).encode('utf-8'))

def handle_admin_delete_user(client_socket, client_id, data):
    """Handle request to delete a user by an admin."""
    # Verify admin authentication
    with users_lock:
        is_admin = active_users.get(client_id, {}).get("is_admin", False)
    
    if not is_admin:
        response = {
            "type": "admin_delete_user_response",
            "success": False,
            "message": "Admin privileges required"
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
    
    username = data['username']
    
    try:
        # Try to delete from regular users
        cursor.execute("DELETE FROM users WHERE username=?", (username,))
        regular_deleted = cursor.rowcount > 0
        
        # Also try admin users (if no regular user was found)
        cursor.execute("DELETE FROM admin_users WHERE username=?", (username,))
        admin_deleted = cursor.rowcount > 0
        
        if regular_deleted or admin_deleted:
            conn.commit()
            response = {
                "type": "admin_delete_user_response",
                "success": True,
                "message": f"User {username} deleted successfully"
            }
        else:
            response = {
                "type": "admin_delete_user_response",
                "success": False,
                "message": "User not found"
            }
    except Exception as e:
        response = {
            "type": "admin_delete_user_response",
            "success": False,
            "message": f"Error deleting user: {str(e)}"
        }
    
    client_socket.send(json.dumps(response).encode('utf-8'))

def handle_admin_shutdown_server(client_socket, client_id):
    """Handle request to shut down the server."""
    # Verify admin authentication
    with users_lock:
        is_admin = active_users.get(client_id, {}).get("is_admin", False)
    
    if not is_admin:
        response = {
            "type": "admin_shutdown_server_response",
            "success": False,
            "message": "Admin privileges required"
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
    
    # Send response before shutting down
    response = {
        "type": "admin_shutdown_server_response",
        "success": True,
        "message": "Server shutting down..."
    }
    client_socket.send(json.dumps(response).encode('utf-8'))
    
    # Set shutdown flag
    global shutdown_flag
    log_connection("Admin requested server shutdown")
    shutdown_flag.set()
    
    # Force exit after a few seconds
    threading.Timer(5, lambda: os._exit(0)).start()

def handle_admin_create_channel(client_socket, client_id, data):
    """Handle request to create a new channel by an admin."""
    # Verify admin authentication
    with users_lock:
        is_admin = active_users.get(client_id, {}).get("is_admin", False)
    
    if not is_admin:
        response = {
            "type": "admin_create_channel_response",
            "success": False,
            "message": "Admin privileges required"
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
    
    channel_id = data['channel_id']
    is_public = data.get('is_public', True)
    
    try:
        # Initialize with proper empty JSON array
        empty_content = json.dumps([])
        cursor.execute("INSERT INTO channels (id, is_public, content) VALUES (?, ?, ?)", 
                     (channel_id, int(is_public), empty_content))
        conn.commit()
        response = {
            "type": "admin_create_channel_response",
            "success": True,
            "message": f"Channel {channel_id} created successfully"
        }
    except sqlite3.IntegrityError:
        response = {
            "type": "admin_create_channel_response",
            "success": False,
            "message": "Channel ID already exists"
        }
    except Exception as e:
        response = {
            "type": "admin_create_channel_response",
            "success": False,
            "message": f"Error creating channel: {str(e)}"
        }
    
    client_socket.send(json.dumps(response).encode('utf-8'))

def handle_admin_delete_channel(client_socket, client_id, data):
    """Handle request to delete a channel by an admin."""
    # Verify admin authentication
    with users_lock:
        is_admin = active_users.get(client_id, {}).get("is_admin", False)
    
    if not is_admin:
        response = {
            "type": "admin_delete_channel_response",
            "success": False,
            "message": "Admin privileges required"
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
    
    channel_id = data['channel_id']
    
    try:
        cursor.execute("DELETE FROM channels WHERE id=?", (channel_id,))
        if cursor.rowcount > 0:
            conn.commit()
            response = {
                "type": "admin_delete_channel_response",
                "success": True,
                "message": f"Channel {channel_id} deleted successfully"
            }
        else:
            response = {
                "type": "admin_delete_channel_response",
                "success": False,
                "message": "Channel not found"
            }
    except Exception as e:
        response = {
            "type": "admin_delete_channel_response",
            "success": False,
            "message": f"Error deleting channel: {str(e)}"
        }
    
    client_socket.send(json.dumps(response).encode('utf-8'))

def handle_client(client_socket):
    client_id = f"{threading.current_thread().ident}"
    client_address = client_socket.getpeername()
    log_connection(f"New connection from {client_address} (Thread ID: {client_id})")
    
    with users_lock:
        active_users[client_id] = {"authenticated": False, "username": None}
        active_sockets[client_id] = client_socket
    
    # Set socket timeout to prevent hanging
    client_socket.settimeout(60.0)  # 60 seconds timeout
    
    while not shutdown_flag.is_set():
        try:
            message = client_socket.recv(4096).decode('utf-8')
            if not message:
                log_connection(f"Client {client_id} disconnected")
                break
            
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                log_connection(f"Received invalid JSON from client {client_id}")
                response = json.dumps({"type": "error", "message": "Invalid JSON"}).encode('utf-8')
                client_socket.send(response)
                continue
            
            request_type = data.get('type', 'unknown')
            log_connection(f"Received {request_type} request from client {client_id}")
            
            # Enforce authentication for sensitive operations
            if request_type in ['join_channel', 'send_message', 'create_channel']:
                with users_lock:
                    if not active_users.get(client_id, {}).get("authenticated", False):
                        response = {
                            "type": f"{request_type}_response",
                            "success": False,
                            "message": "Authentication required"
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        continue
            
            try:
                # Handle different message types
                if data['type'] == 'submit_info':
                    with peers_lock:
                        peers.append({'ip': data['ip'], 'port': data['port']})
                    response = create_submit_info_response(True, "Registration successful")
                    client_socket.send(response.encode('utf-8'))
                
                # Handle admin-specific message types
                elif data['type'] == 'admin_login':
                    handle_admin_login(client_socket, client_id, data)
                
                elif data['type'] == 'get_users':
                    handle_get_users(client_socket, client_id)
                    
                elif data['type'] == 'admin_create_user':
                    handle_admin_create_user(client_socket, client_id, data)
                    
                elif data['type'] == 'admin_delete_user':
                    handle_admin_delete_user(client_socket, client_id, data)
                    
                elif data['type'] == 'admin_shutdown_server':
                    handle_admin_shutdown_server(client_socket, client_id)
                    
                elif data['type'] == 'admin_create_channel':
                    handle_admin_create_channel(client_socket, client_id, data)
                    
                elif data['type'] == 'admin_delete_channel':
                    handle_admin_delete_channel(client_socket, client_id, data)
                    
                # Handle regular client message types
                elif data['type'] == 'get_list':
                    with peers_lock:
                        response = create_get_list_response(peers)
                    client_socket.send(response.encode('utf-8'))
                
                elif data['type'] == 'login':
                    username = data['username']
                    password = data['password']
                    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
                    if cursor.fetchone():
                        with users_lock:
                            active_users[client_id] = {"authenticated": True, "username": username}
                        response = create_login_response(True, "Login successful")
                    else:
                        response = create_login_response(False, "Invalid credentials")
                    client_socket.send(response.encode('utf-8'))
                
                elif data['type'] == 'register':
                    username = data['username']
                    password = data['password']
                    try:
                        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                        conn.commit()
                        response = create_register_response(True, "Registration successful")
                    except sqlite3.IntegrityError:
                        response = create_register_response(False, "Username already exists")
                    client_socket.send(response.encode('utf-8'))
                
                elif data['type'] == 'create_channel':
                    # Check if user is authenticated
                    with users_lock:
                        is_authenticated = active_users.get(client_id, {}).get("authenticated", False)
                    
                    if not is_authenticated:
                        response = create_create_channel_response(False, "Authentication required")
                    else:
                        channel_id = data['channel_id']
                        host_ip = data['host_ip']
                        host_port = data['host_port']
                        is_public = data.get('is_public', 1)  # Default to public
                        
                        try:
                            # Initialize with proper empty JSON array
                            empty_content = json.dumps([])
                            cursor.execute("INSERT INTO channels (id, host_ip, host_port, content, is_public) VALUES (?, ?, ?, ?, ?)", 
                                           (channel_id, host_ip, host_port, empty_content, is_public))
                            conn.commit()
                            response = create_create_channel_response(True, "Channel created")
                        except sqlite3.IntegrityError:
                            response = create_create_channel_response(False, "Channel already exists")
                    client_socket.send(response.encode('utf-8'))
                
                elif data['type'] == 'join_channel':
                    handle_join_channel(client_socket, client_id, data)
                
                elif data['type'] == 'leave_channel':
                    handle_leave_channel(client_socket, client_id, data)
                
                elif data['type'] == 'get_channel_users':
                    handle_get_channel_users(client_socket, data)
                
                elif data['type'] == 'get_channel_host':
                    channel_id = data['channel_id']
                    cursor.execute("SELECT host_ip, host_port FROM channels WHERE id=?", (channel_id,))
                    result = cursor.fetchone()
                    if result:
                        response = create_get_channel_host_response(True, result[0], result[1])
                    else:
                        response = create_get_channel_host_response(False, message="Channel not found")
                    client_socket.send(response.encode('utf-8'))
                
                elif data['type'] == 'sync_content':
                    channel_id = data['channel_id']
                    content = data['content']
                    
                    # Verify if user can post in this channel
                    cursor.execute("SELECT is_public FROM channels WHERE id=?", (channel_id,))
                    result = cursor.fetchone()
                    
                    with users_lock:
                        is_authenticated = active_users.get(client_id, {}).get("authenticated", False)
                        username = active_users.get(client_id, {}).get("username", "visitor")
                    
                    # Enforce authentication requirement for posting messages
                    if not is_authenticated:
                        response = create_sync_content_response(False, "Authentication required to post messages")
                        client_socket.send(response.encode('utf-8'))
                        continue
                    
                    # Add sender information to the message
                    for msg in content:
                        if 'sender' not in msg:
                            msg['sender'] = username
                    
                    cursor.execute("UPDATE channels SET content=? WHERE id=?", (json.dumps(content), channel_id))
                    conn.commit()
                    response = create_sync_content_response(True, "Content synced")
                    client_socket.send(response.encode('utf-8'))
                    
                    # Broadcast message update to all clients in this channel
                    broadcast_message_update(channel_id, content)
                
                elif data['type'] == 'get_channels':
                    # Return list of all channels, identifying which are public vs private
                    cursor.execute("SELECT id, is_public FROM channels")
                    channels = [{"id": row[0], "is_public": bool(row[1])} for row in cursor.fetchall()]
                    response = create_get_channels_response(channels)
                    client_socket.send(response.encode('utf-8'))
                
                elif data['type'] == 'get_messages':
                    channel_id = data['channel_id']
                    log_connection(f"Client {client_id} requested messages for channel {channel_id}")
                    handle_get_messages(client_socket, channel_id)
                
                elif data['type'] == 'logout':
                    with users_lock:
                        active_users[client_id] = {"authenticated": False, "username": None}
                    client_socket.send(json.dumps({"type": "logout", "success": True}).encode('utf-8'))
                
                elif data['type'] == 'host_heartbeat':
                    handle_host_heartbeat(client_socket, client_id, data)

                elif data['type'] == 'host_register':
                    handle_host_register(client_socket, client_id, data)

                elif data['type'] == 'get_channel_host_info':
                    handle_get_channel_host_info(client_socket, data)

                elif data['type'] == 'register_livestream':
                    handle_register_livestream(client_socket, client_id, data)
                    
                elif data['type'] == 'unregister_livestream':
                    handle_unregister_livestream(client_socket, client_id, data)
                    
                elif data['type'] == 'get_active_streams':
                    handle_get_active_streams(client_socket, data)
            
            except Exception as e:
                log_connection(f"Error processing request: {e}")
                try:
                    response = json.dumps({"type": "error", "message": f"Server error: {e}"}).encode('utf-8')
                    client_socket.send(response)
                except ConnectionError:
                    log_connection(f"Failed to send error response to client {client_id}")
                    break
        
        except socket.timeout:
            log_connection(f"Client {client_id} connection timed out")
            break
        except ConnectionResetError:
            log_connection(f"Connection reset by client {client_id}")
            break
        except ConnectionAbortedError:
            log_connection(f"Connection aborted for client {client_id}")
            break
        except json.JSONDecodeError:
            log_connection("Received invalid JSON")
        except Exception as e:
            log_connection(f"Error: {e}")
            break
    
    # Clean up when connection ends
    log_connection(f"Closing connection with client {client_id}")
    
    # Remove user from all channels
    remove_user_from_channels(client_id)
    
    with users_lock:
        if client_id in active_users:
            del active_users[client_id]
        if client_id in active_sockets:
            del active_sockets[client_id]
    
    try:
        client_socket.close()
    except:
        pass

def start_server():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Add socket reuse option to avoid "address already in use" errors
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        log_connection(f"Server listening on {HOST}:{PORT}")
        
        # Start host status checking thread
        host_status_thread = threading.Thread(target=check_host_status)
        host_status_thread.daemon = True
        host_status_thread.start()
        
        server_socket.settimeout(1.0)  # Set a timeout on accept to allow checking the shutdown flag
        while not shutdown_flag.is_set():
            try:
                client_socket, addr = server_socket.accept()
                log_connection(f"Accepted connection from {addr}")
                client_handler = threading.Thread(target=handle_client, args=(client_socket,))
                client_handler.daemon = True  # Make thread daemon so it exits when main thread exits
                client_handler.start()
            except socket.timeout:
                # This is expected, just check the shutdown flag and continue
                continue
            except KeyboardInterrupt:
                shutdown_flag.set()
                print("\nShutting down server...")
            except Exception as e:
                log_connection(f"Server error: {e}")
    except Exception as e:
        log_connection(f"Error starting server: {e}")
    finally:
        log_connection("Cleaning up server resources...")
        # Clean shutdown
        try:
            server_socket.close()
        except:
            pass
        conn.close()
        log_connection("Server shutdown complete")

def signal_handler(sig, frame):
    print("\nReceived shutdown signal. Closing server...")
    shutdown_flag.set()
    # Give a moment for threads to clean up
    time.sleep(1)
    # If server doesn't exit gracefully within 5 seconds, force exit
    threading.Timer(5, lambda: sys.exit(1)).start()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_server()