# SegmentChat

SegmentChat is a feature-rich chat application with support for channels, peer-to-peer messaging, livestreaming, and offline capabilities.

## Prerequisites

Before running the application, make sure you have the following installed:

- Python 3.7 or higher
- Required Python packages (can be installed using pip):
  - tkinter (usually comes with Python)
  - opencv-python
  - pillow
  - numpy

## Installation

1. Clone or download this repository to your local machine.

2. Install the required dependencies:
   ```
   pip install opencv-python pillow numpy
   ```

## Setting Up and Running the Application

### Step 1: Start the Server

1. Open a command prompt or terminal window.
2. Navigate to the project directory:
   ```
   cd "path\to\segment_chat"
   ```
3. Start the server:
   ```
   python server.py
   ```
4. You should see a message indicating that the server is running on port 5000.

### Step 2: Run the Chat Application

1. Open a new command prompt or terminal window.
2. Navigate to the project directory.
3. Start the chat application:
   ```
   python chat_app.py
   ```
4. The application window should appear with a login screen.

### Step 3: Using the Application

#### Login or Register
- To register a new account, enter a username and password, then click "Register".
- To login with an existing account, enter your credentials and click "Login".
- To use the application without an account, click "Continue as Visitor".

#### Chat Functionality
1. **Join a Channel**: Click on a channel name in the left sidebar.
2. **Create a Channel**: Click the "Create Channel" button and enter a name.
3. **Send Messages**: Type in the message box at the bottom and click "Send" or press Enter.
4. **Upload Images**: Click the "Upload" button to share images in a channel.

#### Livestreaming
1. **Start a Stream**: Join a channel, then click "Start Stream" in the channel header.
2. **View a Stream**: Click "View Stream" to watch an active stream in the current channel.

### Step 4: Administrator Access (Optional)

1. Start the admin application:
   ```
   python admin_app.py
   ```
2. Login with the default admin credentials:
   - Username: admin
   - Password: admin
3. From the admin panel, you can:
   - Manage users
   - Create and delete channels
   - Control the server (restart/stop)

## Features

- **Channel-based Chat**: Public and private channels for organized discussions
- **User Authentication**: Secure user registration and login
- **Peer-to-Peer Communication**: Direct communication between clients when possible
- **Offline Support**: Store and sync messages when network connection is lost
- **File Sharing**: Share images in chat channels
- **Livestreaming**: Stream and view video in channels
- **Admin Controls**: Manage users, channels, and server via admin interface

## Troubleshooting

- **Connection Issues**: Ensure the server is running before starting the client
- **Webcam Access**: If livestreaming doesn't work, check your webcam permissions
- **Database Errors**: If you encounter database errors, delete the segment_chat.db file and restart the server
- **Port Already in Use**: If port 5000 is already in use, modify the PORT variable in server.py

## Project Structure

- `client.py`: Chat client implementation
- `server.py`: Server implementation
- `chat_app.py`: Main application UI
- `admin_app.py`: Administrator interface
- `peer_manager.py`: Peer-to-peer communication handling
- `livestream.py`: Video streaming functionality
- `offline_storage.py`: Local storage for offline operation
- `protocols.py`: Communication protocol definitions
- `utils.py`: Utility functions

## Advanced Usage

### Hosting Channels
When you create a channel and stay connected, you become the host. Other users will connect directly to you in a peer-to-peer fashion, reducing server load.

### Running Multiple Clients
You can run multiple instances of the chat application to test features like:
- Peer-to-peer messaging
- Livestreaming
- User online/offline status
