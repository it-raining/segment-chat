# SegmentChat

SegmentChat is a hybrid network chat application demonstrating concepts from the Computer Networks course (CO3093, Semester 1, 2024-2025). It combines Client-Server and Peer-to-Peer (P2P) paradigms using Python, Tkinter, and standard networking libraries.

## Project Overview

This application implements a Discord-like chat system featuring:

*   **Hybrid Architecture:** Utilizes a central server for coordination (authentication, user/channel tracking, livestream registration, message fallback) and P2P connections primarily for efficient video livestreaming between clients within a channel.
*   **Authentication:** Supports registered user login (with password hashing on the server), visitor mode (temporary username, read-only access), and an invisible status for authenticated users.
*   **Channel-Based Communication:** Users interact within distinct channels. The server manages channel creation, membership, and provides lists of users and channels.
*   **P2P Livestreaming:** Authenticated users can host video streams within a channel. Other users in the channel can connect directly to the host peer to view the stream, reducing server load. The server acts as a tracker, registering active streams.
*   **Client-Server Fallback:** The server stores channel messages, acting as a fallback when P2P connections (e.g., to a host) are unavailable or for fetching message history.
*   **Offline Caching:** Clients maintain a local SQLite database to cache messages received while online, allowing viewing of past messages when offline. Messages sent while offline are also stored locally and synced upon reconnection.
*   **Admin Panel:** A separate Tkinter application allows administrators to manage users (create/delete), manage channels (create/delete), and control the server (shutdown).

## Documentation

A detailed report outlining the design, protocols, and implementation specifics can be found on Overleaf:
[SegmentChat Project Report (Overleaf)](https://www.overleaf.com/read/fkyfxnhqvrqf#b87b7b)

## Features

*   **User Authentication:**
    *   Registration & Login for authenticated users.
    *   Visitor mode for read-only access.
    *   Invisible mode for authenticated users.
*   **Channel Management:**
    *   Public and Private channels.
    *   Channel creation (authenticated users & admin).
    *   Joining/Leaving channels.
    *   Real-time user list updates within channels (respecting invisible status).
*   **Messaging:**
    *   Text messaging within channels.
    *   Image uploads/sharing within channels.
    *   Emoji picker.
*   **P2P Livestreaming:**
    *   Authenticated users can start video streams (using OpenCV).
    *   Direct P2P viewing of active streams within a channel.
    *   Server tracks active streams.
*   **Offline Capabilities:**
    *   Client-side caching of channel messages in SQLite DB.
    *   Storage of messages sent while offline.
    *   Synchronization of offline messages upon reconnection.
*   **Admin Interface:**
    *   User management (CRUD operations).
    *   Channel management (CRUD operations).
    *   Server shutdown control.
*   **Networking:**
    *   TCP sockets for Client-Server and P2P communication.
    *   JSON-based messaging protocol with length-prefix framing.
    *   Central server acts as tracker and fallback.

## Technology Stack

*   **Language:** Python 3.7+
*   **GUI:** Tkinter (via `ttk` for themed widgets)
*   **Networking:** `socket`, `threading`, `struct`
*   **Database:** `sqlite3` (for server state and client cache)
*   **Video:** `opencv-python` (for livestreaming)
*   **Image Handling:** `Pillow` (PIL)
*   **Serialization:** `json`
*   **Utilities:** `uuid`, `base64`, `hashlib` (implied for passwords)

## Architecture

The system employs a hybrid model:

1.  **Central Server (`src/server/server.py`):**
    *   Listens for client connections.
    *   Manages user authentication (against SQLite DB).
    *   Tracks online users, channel memberships, and invisible status in memory and DB.
    *   Stores channel metadata and message history (SQLite DB).
    *   Registers and tracks active livestreams.
    *   Handles administrative requests.
    *   Broadcasts events (user join/leave, new messages, stream updates) to relevant clients.
2.  **Chat Client (`chat_app.py`, `src/client/client.py`):**
    *   Connects to the central server.
    *   Handles user login/registration/visitor mode.
    *   Provides the Tkinter GUI.
    *   Manages local offline cache (`src/client/offline_storage.py`).
    *   Initiates and manages P2P connections via `PeerConnectionManager`.
    *   Handles sending/receiving messages via server or P2P host.
    *   Initiates/views livestreams (`src/p2p/livestream.py`).
3.  **Peer Manager (`src/p2p/peer_manager.py`):**
    *   Manages direct P2P connections between clients, primarily used for livestreaming.
    *   Listens for incoming peer connections.
    *   Connects to livestream hosts.
4.  **Admin Client (`admin_app.py`, `src/client/admin_client.py`):**
    *   A separate application connecting to the server with admin credentials.
    *   Provides UI for administrative tasks.

## Prerequisites

- Python 3.7 or higher
- Required Python packages:
  ```bash
  pip install opencv-python pillow numpy
  ```
  (Tkinter is usually included with Python installations)

## Installation

1.  Clone or download this repository.
2.  Install dependencies: `pip install opencv-python pillow numpy`

## Running for Development/Testing

1.  **Start the Server:**
    ```bash
    # Navigate to the project's root directory
    python src/server/server.py
    ```
    *(The server uses `segment_chat.db` in the root directory)*

2.  **Run the Chat Client:**
    ```bash
    # In a new terminal, navigate to the project's root directory
    python chat_app.py [--host <server_ip>]
    ```
    *(Run multiple instances to test P2P features)*

3.  **Run the Admin Client (Optional):**
    ```bash
    # In another terminal, navigate to the project's root directory
    python admin_app.py [--host <server_ip>]
    ```
    *(Default login: admin/admin)*

## Project Structure

-   `src/`: Contains core source code.
    -   `client/`: Client-side logic (`client.py`, `admin_client.py`, `offline_storage.py`).
    -   `server/`: Server-side logic (`server.py`).
    -   `p2p/`: Peer-to-peer logic (`peer_manager.py`, `livestream.py`).
    *   `common/`: Shared code (`protocols.py`, `utils.py`).
-   `chat_app.py`: Main chat application GUI entry point.
-   `admin_app.py`: Admin panel GUI entry point.
-   `segment_chat.db`: Server's SQLite database file (created on first run).
-   `logs/`: Contains log files (`connection_log.txt`).
-   `README.md`: This file.
-   `req.md`: Original assignment requirements document.
