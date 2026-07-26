import datetime
import sqlite3

def save_fingerprint(data):
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute("""
                    INSERT INTO results (timestamp, user_agent, language, platform, screen_resolution, timezone, referrer, canvas_fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        datetime.datetime.now().isoformat(),
                        data.get("userAgent"),
                        data.get("language"),
                        data.get("platform"),
                        data.get("screenResolution"),
                        data.get("timezone"),
                        data.get("referrer"),
                        data.get("canvas"),
                    ))
    conn.commit()
    conn.close()

def get_latest_fingerprint():
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute("""
                    SELECT user_agent, platform, screen_resolution, timezone, referrer, canvas_fingerprint
                    FROM results
                    ORDER BY id DESC
                    LIMIT 1
                   """)
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "userAgent" : row[0],
            "platform" : row[1],
            "screenResolution" : row[2],
            "timezone" : row[3],
            "referrer" : row[4],
            "canvas" : row[5],
        }
    return {}
