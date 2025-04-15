import json
import time

# Request Message Creators

def create_submit_info(ip, port):
    """Create a message for a peer to register its IP and port with the server."""
    return json.dumps({
        "type": "submit_info",
        "ip": ip,
        "port": port
    })

def create_get_list():
    """Create a message to request the list of active peers from the server."""
    return json.dumps({
        "type": "get_list"
    })

def create_login(username, password):
    """Create a message for user authentication with the server."""
    return json.dumps({
        "type": "login",
        "username": username,
        "password": password
    })

def create_create_channel(channel_id, host_ip, host_port):
    """Create a message to request the creation of a new channel."""
    return json.dumps({
        "type": "create_channel",
        "channel_id": channel_id,
        "host_ip": host_ip,
        "host_port": host_port
    })

def create_join_channel(channel_id, username, is_visitor):
    """Create a message for a user to join an existing channel."""
    return json.dumps({
        "type": "join_channel",
        "channel_id": channel_id,
        "username": username,
        "is_visitor": is_visitor
    })

def create_send_message(channel_id, username, message):
    """Create a message to send a chat message to a channel."""
    return json.dumps({
        "type": "send_message",
        "channel_id": channel_id,
        "username": username,
        "message": message
    })

def create_sync_content(channel_id, content):
    """Create a message to synchronize channel content with the server."""
    return json.dumps({
        "type": "sync_content",
        "channel_id": channel_id,
        "content": content
    })

def create_get_channel_content(channel_id):
    """Create a message to fetch content for a specific channel."""
    return json.dumps({
        "type": "get_channel_content",
        "channel_id": channel_id
    })

def create_notification(event, channel_id=None, data=None):
    """Create a generic notification message for events like new messages or user joins."""
    return json.dumps({
        "type": "notification",
        "event": event,
        "channel_id": channel_id,
        "data": data
    })

def create_register_response(success, message=None):
    """Create a response to a peer registration request."""
    return json.dumps({
        "type": "register_response",
        "success": success,
        "message": message
    })


# Response Message Creators

def create_submit_info_response(success, message):
    response = {
        "type": "submit_info_response",
        "success": success,
        "message": message
    }
    return json.dumps(response)

def create_get_list_response(peers):
    response = {
        "type": "get_list_response",
        "peers": peers
    }
    return json.dumps(response)

def create_login_response(success, message):
    response = {
        "type": "login_response",
        "success": success,
        "message": message
    }
    return json.dumps(response)

def create_register_response(success, message):
    response = {
        "type": "register_response",
        "success": success,
        "message": message
    }
    return json.dumps(response)

def create_create_channel_response(success, message):
    response = {
        "type": "create_channel_response",
        "success": success,
        "message": message
    }
    return json.dumps(response)

def create_join_channel_response(success, message):
    response = {
        "type": "join_channel_response",
        "success": success,
        "message": message
    }
    return json.dumps(response)

def create_get_channel_host_response(success, host_ip=None, host_port=None, message=None):
    response = {
        "type": "get_channel_host_response",
        "success": success
    }
    if success:
        response["host_ip"] = host_ip
        response["host_port"] = host_port
    else:
        response["message"] = message
    return json.dumps(response)

def create_sync_content_response(success, message):
    response = {
        "type": "sync_content_response",
        "success": success,
        "message": message
    }
    return json.dumps(response)

def create_get_channel_content_response(success, content=None, message=None):
    """Create a response to a content fetching request."""
    return json.dumps({
        "type": "get_channel_content_response",
        "success": success,
        "content": content,
        "message": message
    })

# New protocol functions
def create_get_channels_response(channels):
    response = {
        "type": "get_channels_response",
        "channels": channels
    }
    return json.dumps(response)

def create_get_messages_response(success, messages, message=None):
    response = {
        "type": "get_messages_response",
        "success": success,
        "messages": messages
    }
    if message:
        response["message"] = message
    return json.dumps(response)

# Host status protocol messages
def create_host_heartbeat(channel_id, host_ip, host_port):
    """Create a heartbeat message from channel host to server."""
    return json.dumps({
        "type": "host_heartbeat",
        "channel_id": channel_id,
        "host_ip": host_ip,
        "host_port": host_port,
        "timestamp": time.time()
    })

def create_host_status_update(channel_id, is_online):
    """Create message to notify peers about host status change."""
    return json.dumps({
        "type": "host_status_update",
        "channel_id": channel_id,
        "is_online": is_online,
        "timestamp": time.time()
    })

# Connection status protocol messages
def create_connection_status(status, client_id=None, username=None):
    """Create message about connection status change."""
    return json.dumps({
        "type": "connection_status",
        "status": status,  # "online" or "offline"
        "client_id": client_id,
        "username": username,
        "timestamp": time.time()
    })

# Offline sync protocol messages
def create_sync_offline_content(channel_id, content, client_timestamp):
    """Create message to sync content that was created offline."""
    return json.dumps({
        "type": "sync_offline_content",
        "channel_id": channel_id,
        "content": content,
        "client_timestamp": client_timestamp,
        "server_timestamp": time.time()
    })

def create_sync_conflict_resolution(channel_id, resolved_content):
    """Create message with conflict-resolved content."""
    return json.dumps({
        "type": "sync_conflict_resolution",
        "channel_id": channel_id,
        "resolved_content": resolved_content,
        "timestamp": time.time()
    })

# Add these new protocol functions for peer communication and host management

def create_peer_intro(channel_id, username):
    """Create a peer introduction message."""
    return json.dumps({
        "type": "peer_intro",
        "channel_id": channel_id,
        "username": username,
        "timestamp": time.time()
    })

def create_peer_intro_ack(username):
    """Create a peer introduction acknowledgment."""
    return json.dumps({
        "type": "peer_intro_ack",
        "username": username,
        "timestamp": time.time()
    })

def create_peer_content_update(channel_id, content):
    """Create a content update message for peer-to-peer communication."""
    return json.dumps({
        "type": "content_update",
        "channel_id": channel_id,
        "content": content,
        "timestamp": time.time()
    })

def create_peer_heartbeat(channel_id, username):
    """Create a heartbeat message for peer-to-peer connection."""
    return json.dumps({
        "type": "peer_heartbeat",
        "channel_id": channel_id,
        "username": username,
        "timestamp": time.time()
    })

def create_channel_host_info(channel_id, host_ip, host_port, peer_port, is_online):
    """Create a message with channel host information."""
    return json.dumps({
        "type": "channel_host_info",
        "channel_id": channel_id,
        "host_ip": host_ip,
        "host_port": host_port,
        "peer_port": peer_port,
        "is_online": is_online,
        "timestamp": time.time()
    })

def create_host_register(channel_id, host_ip, host_port, peer_port):
    """Create a message to register as a channel host."""
    return json.dumps({
        "type": "host_register",
        "channel_id": channel_id,
        "host_ip": host_ip,
        "host_port": host_port,
        "peer_port": peer_port,
        "timestamp": time.time()
    })

def create_host_register_response(success, message):
    """Create a response to a host registration request."""
    return json.dumps({
        "type": "host_register_response",
        "success": success,
        "message": message,
        "timestamp": time.time()
    })