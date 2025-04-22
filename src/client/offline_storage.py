import sqlite3
import json
import os
import time

class OfflineStorage:
    def __init__(self, username='anonymous'):
        # Create a unique database file for each user
        db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db')
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        self.db_path = os.path.join(db_dir, f'{username}_offline.db')
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_db()
        
    def _init_db(self):
        """Initialize database tables if they don't exist."""
        # Table for offline messages
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp REAL NOT NULL,
            synced INTEGER DEFAULT 0
        )
        ''')
        
        # Table for cached channel content
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS cached_channels (
            channel_id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            last_updated REAL NOT NULL
        )
        ''')
        
        self.conn.commit()
        
    def store_offline_message(self, channel_id, content, timestamp=None):
        """Store a message created while offline."""
        if timestamp is None:
            timestamp = time.time()
            
        # self.cursor.execute(
        #     "INSERT INTO offline_messages (channel_id, content, timestamp) VALUES (?, ?, ?)",
        #     (channel_id, json.dumps(content), timestamp)
        # )
        # self.conn.commit()
        # return True
        try:
            content_str = json.dumps(content)
            self.cursor.execute(
                "INSERT INTO offline_messages (channel_id, content, timestamp, synced) VALUES (?, ?, ?, 0)",
                (channel_id, content_str, timestamp)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Database error storing offline message: {e}") # Use proper logging
            return False
        except TypeError as e:
            print(f"Error serializing content for offline storage: {e}") # Use proper logging
            return False
        
    def get_offline_messages(self, channel_id=None):
        """Get all unsynced offline messages, optionally filtered by channel."""
        messages = []
        try:
            query = "SELECT id, channel_id, content, timestamp FROM offline_messages WHERE synced = 0"
            params = []
            if channel_id:
                query += " AND channel_id = ?"
                params.append(channel_id)

            self.cursor.execute(query, params)
            rows = self.cursor.fetchall()
            for row in rows:
                try:
                    content_dict = json.loads(row[2])
                    messages.append({
                        'db_id': row[0],    
                        'channel_id': row[1],
                        'content': content_dict,
                        'timestamp': row[3]
                    })
                except json.JSONDecodeError:
                    print(f"Warning: Could not decode offline message content for ID {row[0]}") # Use logging
        except sqlite3.Error as e:
            print(f"Database error getting offline messages: {e}") # Use logging
        return messages
        
    def mark_messages_synced(self, message_ids):
        """Mark messages as synced after successful server synchronization."""
        if not message_ids:
            return False
        try:
            placeholders = ','.join('?' * len(message_ids))
            self.cursor.execute(
                f"UPDATE offline_messages SET synced = 1 WHERE id IN ({placeholders})",
                message_ids
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Database error marking messages synced: {e}") # Use logging
            return False
        
    def cache_channel_content(self, channel_id, messages):
        """Cache channel content for offline access."""
        if not messages:
            return
        try:
            self.cursor.execute("SELECT content FROM cached_channels WHERE channel_id = ?", (channel_id,))
            row = self.cursor.fetchone()
            cached_messages = []
            if row:
                try:
                    cached_messages = json.loads(row[0])
                    if not isinstance(cached_messages, list): cached_messages = []
                except json.JSONDecodeError:
                    cached_messages = [] # Reset if invalid JSON

            existing_timestamps = {msg.get('timestamp') for msg in cached_messages if msg.get('timestamp')}
            added_new = False
            for msg in messages:
                if msg.get('timestamp') not in existing_timestamps:
                    cached_messages.append(msg)
                    existing_timestamps.add(msg.get('timestamp'))
                    added_new = True

            if added_new:
                # Sort by timestamp before saving
                cached_messages.sort(key=lambda x: x.get('timestamp', 0))
                content_str = json.dumps(cached_messages)
                last_updated = time.time()
                self.cursor.execute(
                    "INSERT OR REPLACE INTO cached_channels (channel_id, content, last_updated) VALUES (?, ?, ?)",
                    (channel_id, content_str, last_updated)
                )
                self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error caching channel content: {e}") # Use logging
        except TypeError as e:
             print(f"Error serializing content for caching: {e}") # Use logging

        
    # def get_cached_content(self, channel_id):
    #     """Get cached content for a channel."""
    #     self.cursor.execute(
    #         "SELECT content, last_updated FROM cached_channels WHERE channel_id = ?",
    #         (channel_id,)
    #     )
    #     result = self.cursor.fetchone()
        
    #     if result:
    #         return {
    #             'content': json.loads(result[0]),
    #             'last_updated': result[1]
    #         }
    #     return None
        
    def get_cached_content(self, channel_id):
        """Get cached messages for a channel. Returns a list of dicts."""
        try:
            self.cursor.execute("SELECT content FROM cached_channels WHERE channel_id = ?", (channel_id,))
            row = self.cursor.fetchone()
            if row:
                try:
                    messages = json.loads(row[0])
                    return messages if isinstance(messages, list) else []
                except json.JSONDecodeError:
                    return []
            else:
                return []
        except sqlite3.Error as e:
            print(f"Database error getting cached content: {e}") # Use logging
            return []

    def get_latest_cached_timestamp(self, channel_id):
        """Get the timestamp of the most recent message cached for a channel."""
        cached_content = self.get_cached_content(channel_id)
        if not cached_content:
            return 0 # Return 0 if no cache or empty cache
        timestamps = [msg.get('timestamp') for msg in cached_content if msg.get('timestamp')]
        return max(timestamps) if timestamps else 0

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
