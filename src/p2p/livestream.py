import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import json
import time
import cv2
import numpy as np
import base64
import struct
from PIL import Image, ImageTk
from src.common.utils import log_connection
import collections
import traceback

class LivestreamClient:
    def __init__(self, root_window=None, username="anonymous"):
        self.username = username
        self.streaming = False
        self.viewing = False
        self.host_socket = None
        self.view_socket = None
        self.host_port = None
        self.stream_thread = None
        self.view_thread = None
        self.frame_callback = None
        self.status_callback = None
        self.video_capture = None
        self.server_client = None  # Reference to chat client for server registration
        self.root_window = root_window  # Store the root window
        
    def set_server_client(self, client):
        """Set the server client reference for stream registration."""
        self.server_client = client
    
    def start_hosting(self, channel_id):
        """Start hosting a livestream for the given channel."""
        if self.streaming:
            return False, "Already streaming"
        
        try:
            # Create a socket for broadcasting video
            self.host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.host_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.host_socket.bind(('0.0.0.0', 0))  # Bind to random available port
            self.host_port = self.host_socket.getsockname()[1]
            self.host_socket.listen(5)
            
            log_connection(f"Started livestream host on port {self.host_port} for channel {channel_id}")
            
            # Start video capture
            self.video_capture = cv2.VideoCapture(0)
            if not self.video_capture.isOpened():
                self.host_socket.close()
                return False, "Failed to open webcam"
            
            self.streaming = True
            
            # Register stream with server if server client is available
            if self.server_client and self.server_client.connected:
                log_connection(f"Attempting to register livestream for channel {channel_id} on port {self.host_port} with server.")
                self.server_client.register_livestream(channel_id, self.host_port)
                log_connection(f"Livestream registration initiated for channel {channel_id}.")
            else:
                log_connection(f"Server client not available or not connected. Skipping livestream registration for channel {channel_id}.")

            # Start thread to handle streaming
            self.stream_thread = threading.Thread(
                target=self._stream_video,
                args=(channel_id,)
            )
            self.stream_thread.daemon = True
            self.stream_thread.start()
            log_connection(f"Video streaming thread started for channel {channel_id}.")
            
            return True, self.host_port
        except Exception as e:
            self.stop_hosting()
            return False, str(e)

    def _stream_video(self, channel_id):
        """Thread function to stream video to connected viewers."""
        client_sockets = []
            
        # Thread to accept new connections
        def accept_connections():
            while self.streaming:
                try:
                    self.host_socket.settimeout(1.0)
                    client_socket, addr = self.host_socket.accept()
                    log_connection(f"New viewer connected from {addr}")
                    client_sockets.append(client_socket)
                except socket.timeout:
                    continue
                except Exception as e:
                    log_connection(f"Error accepting connection: {str(e)}")
                    break
        
        accept_thread = threading.Thread(target=accept_connections)
        accept_thread.daemon = True
        accept_thread.start()
        
        # Main streaming loop
        try:
            while self.streaming:
                ret, frame = self.video_capture.read()
                # if ret:
                #     log_connection(f"[{channel_id}] Host: Successfully read frame.")
                # else:
                #     log_connection(f"[{channel_id}] Host: Failed to read frame! ret={ret}")
                
                # Resize and compress frame
                frame = cv2.resize(frame, (640, 480))
                
                # Convert to JPEG and then base64
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                jpg_as_text = base64.b64encode(buffer)
                
                # Create frame packet
                frame_data = {
                    "username": self.username,
                    "channel_id": channel_id,
                    "timestamp": time.time(),
                    "frame_data": jpg_as_text.decode('utf-8')
                }
                frame_json = json.dumps(frame_data)
                
                # debugging purpose
                # num_clients = len(client_sockets)
                # if num_clients > 0:
                    # log_connection(f"Sending frame to {num_clients} viewers.")
                
                for client_socket in client_sockets[:]:
                    try:
                        # Send frame length followed by the frame data
                        msg_length = len(frame_json)
                        client_socket.sendall(struct.pack(">I", msg_length))
                        client_socket.sendall(frame_json.encode('utf-8'))
                    except Exception as send_err:
                        log_connection(f"Error sending frame to a client: {send_err}. Removing client.")
                        # Remove failed socket
                        try:
                            client_socket.close()
                        except:
                            pass
                        client_sockets.remove(client_socket)
                
                # Update our own UI if callback is set
                if self.frame_callback:
                    # log_connection("Updating local host UI with frame.") # Optional: Can be verbose
                    # Convert to format suitable for tkinter
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    if self.root_window:
                        self.root_window.after(0, lambda frame=rgb_frame: self.frame_callback(frame))
                    else:
                        log_connection("Error: Cannot schedule frame_callback without root_window context in _stream_video.")
                
                # Sleep to maintain desired framerate (aim for ~15-20 fps)
                time.sleep(0.05)
        except Exception as e:
            log_connection(f"Streaming error: {str(e)}")
        finally:
            # Clean up
            for client_socket in client_sockets:
                try:
                    client_socket.close()
                except:
                    pass

    def stop_hosting(self):
        """Stop hosting the livestream."""
        self.streaming = False
        if self.video_capture:
            self.video_capture.release()
            self.video_capture = None
        if self.host_socket:
            try:
                self.host_socket.close()
            except OSError:
                pass  # Ignore errors if socket is already closed
            self.host_socket = None
        if self.server_client and self.server_client.connected:
            self.server_client.unregister_livestream(self.host_port)
        log_connection("Stopped livestream hosting")
        if self.status_callback:
            try:
                if self.root_window:
                    self.root_window.after(0, lambda: self.status_callback("stopped"))
                else:
                    log_connection("Error: Cannot schedule status_callback without root_window context.")
            except Exception as e:
                log_connection(f"Error in status callback: {str(e)}")

    def start_viewing(self, host_ip, host_port):
        """Start viewing a livestream from the given host."""
        if self.viewing:
            return False, "Already viewing a stream"
        log_connection(f"Attempting to connect to {host_ip}:{host_port}")
        try:
            self.view_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.view_socket.settimeout(5.0)  # 5 seconds timeout
            self.view_socket.connect((host_ip, host_port))
            self.viewing = True
            
            # Start thread to receive video
            log_connection("Starting receive thread...")
            self.view_thread = threading.Thread(
                target=self._receive_video,
            )
            self.view_thread.daemon = True
            self.view_thread.start()
            
            log_connection(f"Connected to livestream at {host_ip}:{host_port}")
            if self.status_callback:
                self.status_callback("viewing")
            log_connection("Status callback 'viewing' called.")

            return True, "Connected to stream"
        except Exception as e:
            # Debugging proposals
            log_connection(f"Error during start_viewing: {e}")
            traceback.print_exc()
            self.stop_viewing()
            return False, str(e)

    def _receive_video(self):
        """Thread function to receive video from host."""
        try:
            while self.viewing:
                # Receive frame length
                length_data = self.view_socket.recv(4)
                if not length_data:
                    break
                msg_length = struct.unpack(">I", length_data)[0]
                
                # Receive frame data
                chunks = []
                bytes_received = 0
                while bytes_received < msg_length:
                    chunk = self.view_socket.recv(min(msg_length - bytes_received, 4096))
                    if not chunk:
                        raise RuntimeError("Socket connection closed")
                    chunks.append(chunk)
                    bytes_received += len(chunk)
                
                frame_json = b''.join(chunks).decode('utf-8')
                frame_data = json.loads(frame_json)
                
                # Extract and decode the frame
                jpg_as_text = frame_data['frame_data']
                jpg_bytes = base64.b64decode(jpg_as_text)
                
                # Convert to numpy array
                nparr = np.frombuffer(jpg_bytes, np.uint8)
                frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                
                # Convert to RGB for display
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
                # Update UI if callback is set
                if self.frame_callback:
                    if self.root_window:
                        self.root_window.after(0, lambda frame=rgb_frame: self.frame_callback(frame))
                    else:
                        log_connection("Error: Cannot schedule frame_callback without root_window context.")
        except Exception as e:
            log_connection(f"Viewing error: {str(e)}")
        finally:
            self.stop_viewing()

    def stop_viewing(self):
        """Stop viewing the livestream."""
        self.viewing = False
        if self.view_socket:
            try:
                self.view_socket.close()
            except OSError:
                pass  # Ignore errors if socket is already closed
            self.view_socket = None
        log_connection("Stopped livestream viewing")
        if self.status_callback:
            try:
                if self.root_window:
                    self.root_window.after(0, lambda: self.status_callback("stopped"))
                else:
                    log_connection("Error: Cannot schedule status_callback without root_window context.")
            except Exception as e:
                log_connection(f"Error in status callback: {str(e)}")

    def set_frame_callback(self, callback):
        """Set callback for receiving video frames: callback(frame)"""
        self.frame_callback = callback

    def set_status_callback(self, callback):
        """Set callback for status updates: callback(status)"""
        self.status_callback = callback

    def cleanup(self):
        """Clean up resources."""
        self.stop_hosting()
        self.stop_viewing()

class LivestreamWindow:
    def __init__(self, parent, client, channel_id, host_info=None):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Livestream - {channel_id}")
        self.window.geometry("800x600")
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.client = client
        self.channel_id = channel_id
        self.host_info = host_info
        self.status_var = tk.StringVar(value="Initializing...")
        self.setup_ui()
        self.frame_buffer = collections.deque(maxlen=5)  # Buffer ~5 frames
        self.display_update_ms = 50  # Target ~20fps display (1000ms / 20fps = 50ms)
        self.update_job = None

        # Ensure client has the root window reference
        if not self.client.root_window:
            if isinstance(parent, (tk.Tk, tk.Toplevel)):
                self.client.root_window = parent.winfo_toplevel()
            else:
                log_connection("CRITICAL ERROR: LivestreamClient needs root_window reference!")

        # Set callbacks *before* starting host/view
        self.client.set_frame_callback(self.handle_frame_update)  # Use handler
        self.client.set_status_callback(self.handle_status_update)  # Use handler

        if host_info:
            self.start_viewing()
        else:
            self.start_hosting()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True)
        self.canvas = tk.Canvas(main_frame, bg="black")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(status_frame, text="Stop", command=self.stop)
        self.stop_button.pack(side=tk.RIGHT)

    def start_hosting(self):
        self.status_var.set("Starting stream...")
        threading.Thread(
            target=self._start_hosting_thread,
            daemon=True
        ).start()

    def _start_hosting_thread(self):
        success, result = self.client.start_hosting(self.channel_id)
        if success:
            self.window.after(0, lambda: self.status_var.set(f"Streaming on port {result}"))
            self.window.after(0, self.schedule_display_update) # Start display loop
        else:
            self.window.after(0, lambda: self.status_var.set(f"Error: {result}"))
            self.window.after(0, lambda: messagebox.showerror("Streaming Error", result, parent=self.window))

    def start_viewing(self):
        self.status_var.set("Connecting to stream...")
        threading.Thread(
            target=self._start_viewing_thread,
            daemon=True
        ).start()
    def _start_viewing_thread(self):
        host_ip, host_port = self.host_info
        success, result = self.client.start_viewing(host_ip, host_port)
        if success:
            self.window.after(0, self.schedule_display_update) # Start display loop
        else:
            if self.window.winfo_exists():
                self.window.after(0, lambda: self.status_var.set(f"Error: {result}"))
                if self.window.winfo_exists():
                     self.window.after(0, lambda: messagebox.showerror("Viewing Error", result, parent=self.window))
                else:
                     log_connection("Viewing error occurred, but window was already destroyed.")
            else:
                 log_connection("Viewing error occurred, but window was already destroyed.")

    def handle_frame_update(self, frame):
        """Handles frame updates from client (called by background thread via root.after)."""
        self.frame_buffer.append(frame)

    def handle_status_update(self, status):
        """Handles status updates from client (called by background thread via root.after)."""
        self._update_ui_status(status)

    def _update_ui_status(self, status):
        """Update UI elements based on status (runs on main thread)."""
        log_connection(f"Livestream status update: {status}")
        self.status_var.set(f"Status: {status.replace('_', ' ').title()}")

        if status in ["stopped", "stopped_by_host", "disconnected", "error"]:
            if self.update_job:
                self.window.after_cancel(self.update_job)
                self.update_job = None

            if status == "stopped_by_host":
                messagebox.showinfo("Stream Ended", "The host has stopped the stream.", parent=self.window)
            elif status == "disconnected":
                messagebox.showwarning("Stream Disconnected", "Lost connection to the stream.", parent=self.window)
            elif status == "error":
                messagebox.showerror("Stream Error", "An error occurred during the stream.", parent=self.window)

            try:
                if self.window.winfo_exists():
                    self.window.destroy()
            except tk.TclError as e:
                log_connection(f"Error destroying livestream window (already destroyed?): {e}")

        elif status == "hosting":
            self.stop_button.config(text="Stop Hosting", command=self.client.stop_hosting)
        elif status == "viewing":
            self.stop_button.config(text="Stop Viewing", command=self.client.stop_viewing)
        else:
            self.stop_button.config(text="Stop", command=self.stop)

    def schedule_display_update(self):
        self.update_job = self.window.after(self.display_update_ms, self.schedule_display_update)
        self._display_next_frame()

    def _display_next_frame(self):
        """Display the next frame from the buffer."""
        try:
            if self.frame_buffer:
                frame = self.frame_buffer.popleft()
                image = Image.fromarray(frame)
                canvas_width = self.canvas.winfo_width()
                canvas_height = self.canvas.winfo_height()
                if canvas_width > 1 and canvas_height > 1:
                    image = image.resize((canvas_width, canvas_height), Image.Resampling.LANCZOS)
                self.photo = ImageTk.PhotoImage(image=image)
                self.canvas.create_image(0, 0, image=self.photo, anchor=tk.NW)
        except Exception as e:
            log_connection(f"Error displaying frame: {e}")

    def stop(self):
        if self.host_info:
            self.client.stop_viewing()
        else:
            self.client.stop_hosting()
        self.status_var.set("Stopped")

    def on_closing(self):
        try:
            self.stop()
            self.window.destroy()
        except Exception as e:
            log_connection(f"Error closing livestream window: {str(e)}")

    def add_stream_view(self, username, host_ip, host_port):
        """Add a stream view for multiple streams display."""
        self.host_info = (host_ip, host_port)
        self.start_viewing()
        self.status_var.set(f"Viewing stream from {username}")
