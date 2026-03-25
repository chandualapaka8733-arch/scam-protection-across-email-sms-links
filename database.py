import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any

db_path = os.path.join(os.path.dirname(__file__), "..", "phish_hunter.db")

def init_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Scan Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            input_summary TEXT,
            risk_level TEXT,
            score INTEGER,
            flags TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Domain Cache / Blocklist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def save_scan(scan_type: str, input_summary: str, risk_level: str, score: int, flags: List[str]):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_logs (scan_type, input_summary, risk_level, score, flags)
        VALUES (?, ?, ?, ?, ?)
    ''', (scan_type, input_summary, risk_level, score, "\n".join(flags)))
    conn.commit()
    conn.close()

def get_stats() -> Dict[str, Any]:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scan_logs")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'High'")
    high_threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT scan_type, COUNT(*) FROM scan_logs GROUP BY scan_type")
    type_distribution = dict(cursor.fetchall())
    
    # Get recent scans
    cursor.execute("SELECT id, scan_type, input_summary, risk_level, score, timestamp FROM scan_logs ORDER BY timestamp DESC LIMIT 10")
    recent_scans = []
    for row in cursor.fetchall():
        recent_scans.append({
            "id": row[0],
            "type": row[1],
            "input": row[2],
            "risk": row[3],
            "score": row[4],
            "time": row[5]
        })
        
    conn.close()
    return {
        "total_scans": total_scans,
        "high_threats": high_threats,
        "type_distribution": type_distribution,
        "recent_scans": recent_scans
    }

def get_top_domains() -> List[Dict[str, Any]]:
    # This is a bit complex as we have to extract domains from scan_logs flags or input
    # For simplicity, let's just count occurrences of flagged domains in input_summary for URL scans
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT input_summary, COUNT(*) FROM scan_logs WHERE scan_type = 'URL' AND risk_level = 'High' GROUP BY input_summary ORDER BY COUNT(*) DESC LIMIT 5")
    results = [{"domain": row[0], "count": row[1]} for row in cursor.fetchall()]
    conn.close()
    return results

def add_to_blocklist(domain: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO blocklist (domain) VALUES (?)", (domain,))
        conn.commit()
    finally:
        conn.close()

def is_blocked(domain: str) -> bool:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM blocklist WHERE domain = ?", (domain,))
    res = cursor.fetchone()
    conn.close()
    return res is not None
