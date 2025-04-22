import os
import datetime
import inspect
import threading

# --- Files to disable logging for ---
DISABLED_LOG_FILES = {
    # 'chat_app.py',
      'client.py',
        'admin_client.py',
          'admin_app.py',
              'server.py'
          }

# --- Define Log Directory and File ---
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "connection_log.txt")

# --- Define Thread Lock for safe file access ---
log_lock = threading.Lock()

# --- Ensure log directory exists (run once at import time) ---
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except OSError as e:
        print(f"!!! Critical Error: Could not create log directory {LOG_DIR}: {e} !!!")

def log_connection(message):
    """Logs a message to the connection log file, respecting DISABLED_LOG_FILES."""
    # --- Check if logging is disabled for the calling file ---
    try:
        frame = inspect.currentframe().f_back
        filepath = frame.f_code.co_filename
        filename = os.path.basename(filepath)
        if filename in DISABLED_LOG_FILES:
            return # Skip logging for these files
    except Exception as e:
        print(f"!!! Log Inspection Error: {e} !!!")
    finally:
        if 'frame' in locals():
            del frame
    # --- End of check ---

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"

    # --- Thread-safe file writing ---
    with log_lock:
        try:
            with open(LOG_FILE, "a", encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"!!! Log File Write Error: {e} !!!")
            print(log_entry.strip()) # Use strip() to remove the extra newline for console output
