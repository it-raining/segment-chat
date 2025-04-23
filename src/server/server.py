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
import traceback
import struct
import datetime

HOST = '0.0.0.0'
PORT = 5000
peers = []
active_users = {}  # Track active users and their authentication status
peers_lock = threading.Lock()
users_lock = threading.Lock()

online_users = {} # Track online users
invisible_users = set()  # Set of usernames in invisible mode

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
conn = sqlite3.connect('segment_chat.db', check_same_thread=False)
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
    # notification_json = json.dumps(notification)
    
    # Send to all active clients
    with users_lock:
        for client_id, client_socket in active_sockets.items():
            try:
                # client_socket.send(notification_json.encode('utf-8'))
                send_framed_message(client_socket, notification)
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
        response_dict = {
            "type": "host_register_response",
            "success": False,
            "message": "Authentication required to be a host"
        }
        # client_socket.send(json.dumps(response_dict).encode('utf-8'))
        send_framed_message(client_socket, response_dict)
        return
    
    # Check if channel exists
    cursor.execute("SELECT id FROM channels WHERE id = ?", (channel_id,))
    if not cursor.fetchone():
        response_dict = {
            "type": "host_register_response",
            "success": False,
            "message": "Channel does not exist"
        }
        send_framed_message(client_socket, response_dict)
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
        
        response_dict = {
            "type": "host_register_response",
            "success": True,
            "message": "Successfully registered as host",
            "channel_id": channel_id
        }
        send_framed_message(client_socket, response_dict)
        
        log_connection(f"User {username} registered as host for channel {channel_id}")
    except Exception as e:
        log_connection(f"Error registering host for channel {channel_id}: {e}")
        response_dict = {
            "type": "host_register_response",
            "success": False,
            "message": f"Error registering host: {str(e)}"
        }
        try:
            # Use send_framed_message for consistency
            send_framed_message(client_socket, response_dict)
        except Exception as send_e:
            log_connection(f"Failed to send host registration error response: {send_e}")

def handle_get_channel_host_info(client_socket, data):
    """Handle request for channel host info."""
    channel_id = data['channel_id']
    
    cursor.execute(
        "SELECT host_ip, host_port, peer_port, last_host_ping FROM channels WHERE id = ?",
        (channel_id,)
    )
    result = cursor.fetchone()
    
    response_dict = {}
    if not result:
        response_dict = {
            "type": "channel_host_info",
            "channel_id": channel_id,
            "is_online": False,
            "message": "Channel or host information not found",
            "timestamp": time.time()
        }
    else:
        host_ip, host_port, peer_port, last_ping = result
        is_online = last_ping is not None and last_ping > (time.time() - host_timeout)
        response_dict = {
            "type": "channel_host_info",
            "channel_id": channel_id,
            "host_ip": host_ip,
            "host_port": host_port,
            "peer_port": peer_port,
            "is_online": is_online,
            "timestamp": time.time()
        }

    try:
        # Use the framed message sender for consistency
        send_framed_message(client_socket, response_dict)
    except Exception as e:
        log_connection(f"Failed to send channel host info for {channel_id}: {e}")

def handle_join_channel(client_socket, client_id, data):
    """Handle request to join a channel with user tracking."""
    channel_id = data['channel_id']
    response_dict = None # Initialize response dictionary

    # Get username of the client
    with users_lock:
        username = active_users.get(client_id, {}).get("username", "visitor")

    cursor.execute("SELECT is_public FROM channels WHERE id=?", (channel_id,))
    result = cursor.fetchone()
    if not result:
        # response = create_join_channel_response(False, "Channel not found") # OLD
        response_dict = json.loads(create_join_channel_response(False, "Channel not found")) # NEW: Parse to dict
    elif result[0] == 0:  # Private channel
        with users_lock:
            is_authenticated = active_users.get(client_id, {}).get("authenticated", False)
        if not is_authenticated:
            # response = create_join_channel_response(False, "Authentication required for private channels") # OLD
            response_dict = json.loads(create_join_channel_response(False, "Authentication required for private channels")) # NEW: Parse to dict
        else:
            with channel_users_lock:
                if channel_id not in channel_users:
                    channel_users[channel_id] = {}
                channel_users[channel_id][username] = client_id

            broadcast_user_join(channel_id, username)
            handle_get_channel_users(client_socket, {"channel_id": channel_id})

            # response = create_join_channel_response(True, "Joined private channel") # OLD
            response_dict = json.loads(create_join_channel_response(True, "Joined private channel")) # NEW: Parse to dict
    else: # Public channel
        with channel_users_lock:
            if channel_id not in channel_users:
                channel_users[channel_id] = {}
            channel_users[channel_id][username] = client_id
        broadcast_user_join(channel_id, username)
        handle_get_channel_users(client_socket, {"channel_id": channel_id})

        # response = create_join_channel_response(True, "Joined channel") # OLD
        response_dict = json.loads(create_join_channel_response(True, "Joined channel")) # NEW: Parse to dict

    with channel_users_lock:
        log_connection(f"Channel {channel_id} users: {list(channel_users.get(channel_id, {}).keys())}")

    if response_dict: # Ensure we have a response to send
        # client_socket.send(response.encode('utf-8')) # OLD LINE
        send_framed_message(client_socket, response_dict) # NEW LINE - Send the dictionary
    else:
        log_connection(f"Error: No response generated for join_channel request for {channel_id}")



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
    
    response_dict = {
        "type": "leave_channel_response",
        "success": True
    }
    try:
        send_framed_message(client_socket, response_dict)
    except Exception as e:
        log_connection(f"Failed to send leave channel response for {channel_id}: {e}")

def handle_get_channel_users(client_socket, data):
    """Handle request for channel users."""
    channel_id = data['channel_id']

    with channel_users_lock:
        users = list(channel_users.get(channel_id, {}).keys())
        
    # Lấy username của client đang yêu cầu
    with users_lock:
        client_username = None
        for cid, info in active_users.items():
            if active_sockets.get(cid) == client_socket:
                client_username = info.get("username")
                break
    # Ẩn invisible users với người khác
    visible_users = []
    for u in users:
        if u == client_username or u not in invisible_users:
            visible_users.append(u)

    log_connection(f"Sending user list for channel {channel_id}: {users}")

    response_dict = { # Create dictionary directly
        "type": "channel_users_response",
        "channel_id": channel_id,
        "users": users
    }
    # client_socket.send(response.encode('utf-8')) # OLD LINE
    try:
        send_framed_message(client_socket, response_dict) # NEW LINE
    except Exception as e:
        log_connection(f"Failed to send user list for {channel_id}: {e}")

def broadcast_user_join(channel_id, username):
    """Broadcast to all clients in a channel that a user has joined."""
    broadcast_user_channel_event(channel_id, "join", username)
    notification_dict = { # Create dictionary directly
        "type": "user_channel_event",
        "event": "join",
        "channel_id": channel_id,
        "username": username,
        "timestamp": time.time()
    }

    with users_lock:
        sockets_to_notify = list(active_sockets.values())

    for sock in sockets_to_notify:
        try:
            # client_socket.send(notification.encode('utf-8')) # OLD LINE
            send_framed_message(sock, notification_dict) # NEW LINE
        except Exception as e:
            log_connection(f"Failed to broadcast user join to a client: {e}")


def broadcast_user_leave(channel_id, username):
    """Broadcast to all clients in a channel that a user has left."""
    broadcast_user_channel_event(channel_id, "leave", username)
    notification_dict = { # Create dictionary directly
        "type": "user_channel_event",
        "event": "leave",
        "channel_id": channel_id,
        "username": username,
        "timestamp": time.time()
    }

    with users_lock:
        sockets_to_notify = list(active_sockets.values())

    for sock in sockets_to_notify:
        try:
            # client_socket.send(notification.encode('utf-8')) # OLD LINE
            send_framed_message(sock, notification_dict) # NEW LINE
        except Exception as e:
            log_connection(f"Failed to broadcast user leave to a client: {e}")
            
def broadcast_user_channel_event(channel_id, event, username):
    with channel_users_lock:
        users = list(channel_users.get(channel_id, {}).keys())
    # Lọc invisible users
    with users_lock:
        visible_users = [u for u in users if u not in invisible_users]
    message = {
        "type": "user_channel_event",
        "channel_id": channel_id,
        "event": event,
        "username": username,
        "users": visible_users
    }
    with channel_users_lock:
        client_ids = list(channel_users.get(channel_id, {}).values())
    with users_lock:
        for client_id in client_ids:
            client_socket = active_sockets.get(client_id)
            if client_socket:
                try:
                    send_framed_message(client_socket, message)
                except Exception as e:
                    log_connection(f"Failed to broadcast user_channel_event to client {client_id}: {e}")

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
        response_dict = {
            "type": "register_livestream_response",
            "success": False,
            "message": "Authentication required to host a livestream"
        }
        try:
            send_framed_message(client_socket, response_dict)
        except Exception as e:
            log_connection(f"Failed to send auth required response for livestream: {e}")
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
    
    response_dict = {
        "type": "register_livestream_response",
        "success": True,
        "message": "Livestream registered successfully"
    }
    try:
        send_framed_message(client_socket, response_dict)
    except Exception as e:
        log_connection(f"Failed to send livestream registration response: {e}")

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
    
    response_dict = {
        "type": "unregister_livestream_response",
        "success": True,
        "message": "Livestream unregistered successfully"
    }
    try:
        send_framed_message(client_socket, response_dict)
    except Exception as e:
        log_connection(f"Failed to send livestream unregistration response: {e}")

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
    
    response_dict = { # Create dictionary directly
        "type": "active_streams_response",
        "channel_id": channel_id,
        "streams": streams
    }
    try:
        # Use send_framed_message for consistency
        send_framed_message(client_socket, response_dict)
    except Exception as e:
        log_connection(f"Failed to send active streams response for {channel_id}: {e}")

def broadcast_livestream_update(channel_id):
    """Broadcast livestream updates to clients in a channel."""
    with livestreams_lock:
        streams = active_livestreams.get(channel_id, [])
    
    # Create the notification dictionary
    notification_dict = {
        "type": "livestream_update",
        "channel_id": channel_id,
        "streams": streams
    }

    with users_lock:
        active_sockets_copy = list(active_sockets.items())

    for client_id, client_socket in active_sockets_copy:
        try:
            # Use the framed message sender for consistency
            send_framed_message(client_socket, notification_dict)
        except Exception as e:
            log_connection(f"Failed to send livestream update to client {client_id}: {e}")
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
    # Create message update notification dictionary
    notification_dict = {
        "type": "message_update",
        "channel_id": channel_id,
        "content": content,
        "timestamp": time.time()
    }

    # Send to all clients in this channel using the framed message function
    with users_lock:
        sockets_to_notify = {cid: active_sockets[cid] for cid in client_ids if cid in active_sockets}

    for client_id, client_socket in sockets_to_notify.items():
        try:
            send_framed_message(client_socket, notification_dict)
        except Exception as e:
            log_connection(f"Failed to broadcast message update to client {client_id}: {e}")
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

    # Parse the JSON string response back into a dictionary
    try:
        response_dict = json.loads(response)
    except json.JSONDecodeError as e:
        log_connection(f"Error decoding response JSON in handle_get_messages: {e}")
        response_dict = {
            "type": "get_messages_response",
            "success": False,
            "messages": [],
            "message": "Internal server error creating response"
        }
    try:
        # client_socket.send(response.encode('utf-8')) # OLD LINE
        send_framed_message(client_socket, response_dict) # NEW LINE
    except (ConnectionError, BrokenPipeError, ConnectionResetError) as e: # Catch specific send errors
        log_connection(f"Failed to send messages to client: {e}")
    except Exception as e: # Catch other potential errors during send
        log_connection(f"Unexpected error sending messages: {e}")

def handle_admin_login(client_socket, client_id, data):
    """Handle admin login request."""
    response_dict = None # Initialize
    with users_lock:
        if active_users.get(client_id, {}).get("authenticated", False):
            response_dict = { # Use response_dict
                "type": "admin_login_response",
                "success": False,
                "message": "Already authenticated"
            }
            # client_socket.send(json.dumps(response_dict).encode('utf-8')) # OLD
            send_framed_message(client_socket, response_dict) # NEW
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
        response_dict = { # Use response_dict
            "type": "admin_login_response",
            "success": True,
            "message": "Admin login successful"
        }
    else:
        response_dict = { # Use response_dict
            "type": "admin_login_response",
            "success": False,
            "message": "Invalid admin credentials"
        }
    # client_socket.send(json.dumps(response_dict).encode('utf-8')) # OLD
    send_framed_message(client_socket, response_dict)

def handle_get_users(client_socket, client_id):
    """Handle request to get all users."""
    # Verify admin authentication
    with users_lock:
        # Ensure client_id is treated as string if keys are strings, or int if keys are ints
        is_admin = active_users.get(str(client_id), {}).get("is_admin", False) # Assuming client_id might be int from thread ID

    response = {} # Initialize response dict
    if not is_admin:
        response = {
            "type": "get_users_response",
            "success": False,
            "message": "Admin privileges required"
        }
        # client_socket.send(json.dumps(response).encode('utf-8')) # OLD WAY
        # return # Don't return here, send the response below
    else:
        try:
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
            # client_socket.send(json.dumps(response).encode('utf-8')) # OLD WAY
        except Exception as e:
             log_connection(f"Error fetching users in handle_get_users: {e}")
             traceback.print_exc()
             response = {
                 "type": "get_users_response",
                 "success": False,
                 "message": f"Server error fetching users: {e}"
             }
    
    # Send the response (either success or error) using the correct framed method
    try:
        send_framed_message(client_socket, response)
        log_connection(f"Sent '{response.get('type')}' response to client {client_id}")
    except Exception as e:
        log_connection(f"Failed to send get_users response to client {client_id}: {e}")
    
def handle_get_channels(client_socket, client_id):
    """Handle request to get all channels."""
    # Optional: Check if user is authenticated if needed, though admin check might be sufficient
    # with users_lock:
    #     is_authenticated = active_users.get(str(client_id), {}).get("authenticated", False)
    # if not is_authenticated:
    #     response = create_get_channels_response(False, [], "Authentication required")
    #     send_framed_message(client_socket, json.loads(response)) # Assuming create_... returns JSON string
    #     return

    response_dict = {} # Initialize response dict
    try:
        cursor.execute("SELECT id, is_public FROM channels")
        channels_data = [{"id": row[0], "is_public": bool(row[1])} for row in cursor.fetchall()]
        response_json = create_get_channels_response(channels_data)
        response_dict = json.loads(response_json) # Convert JSON string back to dict for send_framed_message

    except Exception as e:
        log_connection(f"Error fetching channels in handle_get_channels: {e}")
        traceback.print_exc()
        # Create an error dictionary directly
        response_dict = {
            "type": "get_channels_response",
            "success": False,
            "channels": [],
            "message": f"Server error fetching channels: {e}"
        }

    # Send the response (either success or error) using the correct framed method
    try:
        send_framed_message(client_socket, response_dict)
        log_connection(f"Sent '{response_dict.get('type')}' response to client {client_id}")
    except Exception as e:
        log_connection(f"Failed to send get_channels response to client {client_id}: {e}")


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
        # client_socket.send(json.dumps(response).encode('utf-8'))
        send_framed_message(client_socket, response) # NEW
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
    
    # client_socket.send(json.dumps(response).encode('utf-8'))
    send_framed_message(client_socket, response)

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
        # client_socket.send(json.dumps(response).encode('utf-8'))
        send_framed_message(client_socket, response)
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
    
    # client_socket.send(json.dumps(response).encode('utf-8'))
    send_framed_message(client_socket, response)

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
        # client_socket.send(json.dumps(response).encode('utf-8'))
        send_framed_message(client_socket, response)
        return
    
    # Send response before shutting down
    response = {
        "type": "admin_shutdown_server_response",
        "success": True,
        "message": "Server shutting down..."
    }
    # client_socket.send(json.dumps(response).encode('utf-8'))
    send_framed_message(client_socket, response)
    
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
        # client_socket.send(json.dumps(response).encode('utf-8'))
        send_framed_message(client_socket, response)
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
    
    # client_socket.send(json.dumps(response).encode('utf-8'))
    send_framed_message(client_socket, response)

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
        # client_socket.send(json.dumps(response).encode('utf-8'))
        send_framed_message(client_socket, response)
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
    
    # client_socket.send(json.dumps(response).encode('utf-8'))
    send_framed_message(client_socket, response)
    
def send_framed_message(sock, message_dict):
    """Encodes, frames, and sends a message dictionary over a socket."""
    try:
        message_json = json.dumps(message_dict)
        message_bytes = message_json.encode('utf-8')
        # Prepend message length as a 4-byte unsigned integer (big-endian)
        header = struct.pack('>I', len(message_bytes))
        sock.sendall(header + message_bytes)
        log_connection(f"Sent framed response '{message_dict.get('type', 'unknown')}' to client")
    except (BrokenPipeError, ConnectionResetError) as e:
        log_connection(f"Failed to send message (client disconnected): {e}")
        raise  # Re-raise to allow calling function to handle cleanup
    except Exception as e:
        log_connection(f"Error sending framed message: {e}")
        raise # Re-raise for handling

def receive_framed_message(client_socket):
    """Receives, unframes, and decodes a message dictionary."""
    buffer = b""
    header_size = 4
    try:
        # Receive Header
        # Consider adding a timeout specific to this read if needed
        while len(buffer) < header_size:
            chunk = client_socket.recv(header_size - len(buffer))
            if not chunk:
                log_connection(f"Client {client_socket.getpeername()} disconnected (no header).")
                return None # Indicate disconnection
            buffer += chunk

        msg_length = struct.unpack('>I', buffer[:header_size])[0]
        buffer = buffer[header_size:] # Keep any potential leftover data if recv got more than header

        # Receive Body
        body_buffer = buffer # Start with any leftover data
        while len(body_buffer) < msg_length:
            bytes_to_read = min(4096, msg_length - len(body_buffer))
            chunk = client_socket.recv(bytes_to_read)
            if not chunk:
                log_connection(f"Client {client_socket.getpeername()} disconnected (incomplete body).")
                return None # Indicate disconnection
            body_buffer += chunk

        message_json = body_buffer[:msg_length].decode('utf-8')
        # NOTE: Handle potential extra data if recv got more than needed
        # buffer = body_buffer[msg_length:] # This part is tricky and depends on protocol needs

        message_dict = json.loads(message_json)
        return message_dict

    except (ConnectionResetError, ConnectionAbortedError, socket.error) as e:
        log_connection(f"Connection error receiving from {client_socket.getpeername()}: {e}")
        return None # Indicate connection error/disconnection
    except socket.timeout:
        log_connection(f"Socket timeout receiving from {client_socket.getpeername()}")
        return None # Indicate timeout, maybe handle differently
    except (struct.error, json.JSONDecodeError) as e:
        log_connection(f"Error decoding/unpacking message from {client_socket.getpeername()}: {e}")
        # Send an error response back to the client
        try:
            error_response = {"type": "error", "message": "Invalid message format received"}
            send_framed_message(client_socket, error_response)
        except Exception as send_e:
            log_connection(f"Failed to send format error response: {send_e}")
        return None # Indicate bad message format
    except Exception as e:
        log_connection(f"Unexpected error receiving from {client_socket.getpeername()}: {e}")
        traceback.print_exc()
        return None # Indicate unexpected error

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
            data = receive_framed_message(client_socket) # NEW WAY
            if data is None:
                # Error occurred or client disconnected, logged in receive_framed_message
                break

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
                        # client_socket.send(json.dumps(response).encode('utf-8'))
                        handle_client
                        continue
            
            try:
                # Handle different message types
                if data['type'] == 'submit_info':
                    with peers_lock:
                        peers.append({'ip': data['ip'], 'port': data['port']})
                    response_json = create_submit_info_response(True, "Registration successful")
                    try:
                        response_dict = json.loads(response_json) # Convert JSON string to dict
                        send_framed_message(client_socket, response_dict)
                    except json.JSONDecodeError as e:
                        log_connection(f"Error decoding submit_info response JSON: {e}")
                    except Exception as e:
                        log_connection(f"Failed to send submit_info response: {e}")
                
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
                        response_json = create_get_list_response(peers)
                    response_dict = json.loads(response_json)
                    send_framed_message(client_socket, response_dict) 
                
                elif data['type'] == 'login':
                    username = data['username']
                    password = data['password']
                    # cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
                    response_dict = None # Initialize
                    with users_lock:
                        # Kiểm tra nếu username đã online
                        if username in online_users:
                            response_json = create_login_response(False, "This account is in use")
                        else:
                            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
                            if cursor.fetchone():
                                active_users[client_id] = {"authenticated": True, "username": username}
                                online_users[username] = client_id  # Đánh dấu user này đang online
                                response_json = create_login_response(True, "Login successful")
                            else:
                                response_json = create_login_response(False, "Invalid credentials")
                    
                    try:
                        response_dict = json.loads(response_json) # Convert JSON string to dict
                        send_framed_message(client_socket, response_dict)
                    except json.JSONDecodeError as e:
                        log_connection(f"Error decoding login response JSON: {e}")
                    except Exception as e:
                        log_connection(f"Failed to send login response: {e}")
                
                elif data['type'] == 'register':
                    username = data['username']
                    password = data['password']
                    response_json = None # Initialize
                    try:
                        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                        conn.commit()
                        response_json = create_register_response(True, "Registration successful")
                    except sqlite3.IntegrityError:
                        response_json = create_register_response(False, "Username already exists")
                    except Exception as e:
                        log_connection(f"Error during registration: {e}")
                        response_json = create_register_response(False, f"Server error during registration: {e}")

                    try:
                        response_dict = json.loads(response_json) # Convert JSON string to dict
                        send_framed_message(client_socket, response_dict)
                    except json.JSONDecodeError as e:
                        log_connection(f"Error decoding registration response JSON: {e}")
                    except Exception as e:
                        log_connection(f"Failed to send registration response: {e}")
                
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
                    
                    try:
                        response_dict = json.loads(response) # Convert JSON string to dict
                        send_framed_message(client_socket, response_dict)
                    except json.JSONDecodeError as e:
                        log_connection(f"Error decoding create_channel response JSON: {e}")
                    except Exception as e:
                        log_connection(f"Failed to send create_channel response: {e}")
                
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
                    response_dict = None # Initialize response dictionary
                    if result:
                        response_json = create_get_channel_host_response(True, result[0], result[1])
                    else:
                        response_json = create_get_channel_host_response(False, message="Channel not found")

                    try:
                        response_dict = json.loads(response_json)
                        send_framed_message(client_socket, response_dict)
                    except json.JSONDecodeError as e:
                        log_connection(f"Error decoding get_channel_host response JSON: {e}")
                        try:
                            error_resp = {"type": "error", "message": "Internal server error creating response"}
                            send_framed_message(client_socket, error_resp)
                        except Exception as send_e:
                             log_connection(f"Failed to send JSON decode error response: {send_e}")
                    except Exception as e:
                        log_connection(f"Failed to send get_channel_host response for {channel_id}: {e}")
                
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
                        # client_socket.send(response.encode('utf-8'))
                        try:
                            response_dict = json.loads(response_json)
                            send_framed_message(client_socket, response_dict)
                        except Exception as e:
                            log_connection(f"Failed to send sync_content auth error: {e}")
                        continue
                    
                    # Add sender information to the message
                    for msg in content:
                        if 'sender' not in msg:
                            msg['sender'] = username
                    
                    cursor.execute("UPDATE channels SET content=? WHERE id=?", (json.dumps(content), channel_id))
                    conn.commit()
                    response = create_sync_content_response(True, "Content synced")
                    # client_socket.send(response.encode('utf-8'))
                    try:
                        response_dict = json.loads(response_json) # NEW: Convert to dict
                        send_framed_message(client_socket, response_dict) # NEW: Use framed send
                    except Exception as e:
                        log_connection(f"Failed to send sync_content success response: {e}")
                    
                    # Broadcast message update to all clients in this channel
                    broadcast_message_update(channel_id, content)
                
                elif data['type'] == 'get_channels':
                    # cursor.execute("SELECT id, is_public FROM channels")
                    # channels = [{"id": row[0], "is_public": bool(row[1])} for row in cursor.fetchall()]
                    # response = create_get_channels_response(channels)
                    # client_socket.send(response.encode('utf-8'))
                    handle_get_channels(client_socket, client_id)
                
                elif data['type'] == 'get_messages':
                    channel_id = data['channel_id']
                    log_connection(f"Client {client_id} requested messages for channel {channel_id}")
                    handle_get_messages(client_socket, channel_id)
                
                elif data['type'] == 'logout':
                    with users_lock:
                        username = active_users.get(client_id, {}).get("username")
                        if username and username in online_users and online_users[username] == client_id:
                            del online_users[username]
                        active_users[client_id] = {"authenticated": False, "username": None}
                    response_dict = {"type": "logout", "success": True}
                    try:
                        send_framed_message(client_socket, response_dict)
                    except Exception as e:
                        log_connection(f"Failed to send logout response: {e}")
                
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
                    
                elif data['type'] == 'set_invisible':
                    with users_lock:
                        username = active_users.get(client_id, {}).get("username")
                        if not username:
                            response = {"type": "set_invisible_response", "success": False, "message": "Not authenticated"}
                        else:
                            is_invisible = data.get("invisible", False)
                            if isinstance(is_invisible, bool):  # Kiểm tra kiểu dữ liệu
                                if is_invisible:
                                    invisible_users.add(username)
                                else:
                                    invisible_users.discard(username)
                                response = {"type": "set_invisible_response", "success": True, "invisible": is_invisible}
                            else:
                                response = {"type": "set_invisible_response", "success": False, "message": "Invalid invisible value"}
                    send_framed_message(client_socket, response)
            
            except Exception as e:
                log_connection(f"Error processing request: {e}")
                try:
                    error_response = {"type": "error", "message": f"Server error: {str(e)}"}
                    # client_socket.send(json.dumps(error_response).encode('utf-8')) # OLD LINE
                    send_framed_message(client_socket, error_response) # NEW LINE
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
        username = active_users.get(client_id, {}).get("username")
        if username and username in online_users and online_users[username] == client_id:
            del online_users[username]
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