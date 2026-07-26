import sqlite3

# Setting up sqlite3, save data to data.db
def init_db():
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_agent TEXT,
            language TEXT,
            platform TEXT,
            screen_resolution TEXT,
            timezone TEXT,
            referrer TEXT,
            canvas_fingerprint TEXT
        )
    """)
    conn.commit()
    conn.close()