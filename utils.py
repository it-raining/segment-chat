def log_connection(message):
    with open('logs/connection_log.txt', 'a') as f:
        f.write(f"{message}\n")
    # Check size and reset if needed
    with open('logs/connection_log.txt', 'r') as f:
        lines = f.readlines()
        if len(lines) > 10000:
            with open('logs/connection_log.txt', 'w') as f:
                f.write("")