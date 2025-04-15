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
            
        self.cursor.execute(
            "INSERT INTO offline_messages (channel_id, content, timestamp) VALUES (?, ?, ?)",
            (channel_id, json.dumps(content), timestamp)
        )
        self.conn.commit()
        return True
        
    def get_offline_messages(self, channel_id=None):
        """Get all unsynced offline messages, optionally filtered by channel."""
        if channel_id:
            self.cursor.execute(
                "SELECT id, channel_id, content, timestamp FROM offline_messages WHERE channel_id = ? AND synced = 0",
                (channel_id,)
            )
        else:
            self.cursor.execute(
                "SELECT id, channel_id, content, timestamp FROM offline_messages WHERE synced = 0"
            )
            
        messages = []
        for row in self.cursor.fetchall():
            messages.append({
                'id': row[0],
                'channel_id': row[1],
                'content': json.loads(row[2]),
                'timestamp': row[3]
            })
            
        return messages
        
    def mark_messages_synced(self, message_ids):
        """Mark messages as synced after successful server synchronization."""
        if not message_ids:
            return
            
        placeholders = ', '.join(['?'] * len(message_ids))
        self.cursor.execute(
            f"UPDATE offline_messages SET synced = 1 WHERE id IN ({placeholders})",
            message_ids
        )
        self.conn.commit()
        
    def cache_channel_content(self, channel_id, content):
        """Cache channel content for offline access."""
        self.cursor.execute(
            "INSERT OR REPLACE INTO cached_channels (channel_id, content, last_updated) VALUES (?, ?, ?)",
            (channel_id, json.dumps(content), time.time())
        )
        self.conn.commit()
        
    def get_cached_content(self, channel_id):
        """Get cached content for a channel."""
        self.cursor.execute(
            "SELECT content, last_updated FROM cached_channels WHERE channel_id = ?",
            (channel_id,)
        )
        result = self.cursor.fetchone()
        
        if result:
            return {
                'content': json.loads(result[0]),
                'last_updated': result[1]
            }
        return None
        
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
