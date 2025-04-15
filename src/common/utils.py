import os
import datetime

def log_connection(message):
    # Make sure logs directory exists
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open('logs/connection_log.txt', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    
    try:
        if hash(message) % 10 == 0:  
            with open('logs/connection_log.txt', 'r') as f:
                lines = f.readlines()
    except:
        pass