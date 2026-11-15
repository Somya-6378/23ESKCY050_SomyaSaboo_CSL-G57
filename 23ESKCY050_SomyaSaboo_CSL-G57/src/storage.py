import sqlite3,hashlib
from config import DB_PATH
from security import audit_mac
def init_db():
 DB_PATH.parent.mkdir(exist_ok=True)
 with sqlite3.connect(DB_PATH) as c: c.execute('CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,url_sha256 TEXT NOT NULL,verdict TEXT NOT NULL,rule_score INTEGER NOT NULL,ml_probability REAL NOT NULL,created_at TEXT NOT NULL,audit_hmac TEXT NOT NULL)')
def save_scan(url,verdict,score,prob,created):
 digest=hashlib.sha256(url.encode()).hexdigest(); mac=audit_mac(digest,verdict,created)
 with sqlite3.connect(DB_PATH) as c: c.execute('INSERT INTO scans(url_sha256,verdict,rule_score,ml_probability,created_at,audit_hmac) VALUES(?,?,?,?,?,?)',(digest,verdict,score,prob,created,mac))
 return digest,mac
def recent_scans(limit=8):
 with sqlite3.connect(DB_PATH) as c: return c.execute('SELECT id,url_sha256,verdict,rule_score,ml_probability,created_at FROM scans ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
