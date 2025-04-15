#!/usr/bin/env python3
import sqlite3
import json
import os
from src.common.utils import log_connection

def fix_channel_content():
    log_connection("Starting database channel content fix")
    
    # Connect to the database
    conn = sqlite3.connect('segment_chat.db')
    cursor = conn.cursor()
    
    # Get all channels
    cursor.execute("SELECT id, content FROM channels")
    channels = cursor.fetchall()
    
    fixed_count = 0
    
    for channel_id, content in channels:
        # Check if content is NULL or invalid JSON
        if content is None:
            log_connection(f"Channel {channel_id} has NULL content, fixing")
            cursor.execute("UPDATE channels SET content=? WHERE id=?", (json.dumps([]), channel_id))
            fixed_count += 1
        else:
            try:
                # Try to parse the JSON to validate it
                json.loads(content)
            except (json.JSONDecodeError, TypeError):
                log_connection(f"Channel {channel_id} has invalid JSON content, fixing")
                cursor.execute("UPDATE channels SET content=? WHERE id=?", (json.dumps([]), channel_id))
                fixed_count += 1
    
    conn.commit()
    conn.close()
    
    log_connection(f"Fixed {fixed_count} channels with NULL or invalid content")
    return fixed_count

if __name__ == "__main__":
    fixed = fix_channel_content()
    print(f"Database repair complete. Fixed {fixed} channels.")
