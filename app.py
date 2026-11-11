from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime
import random
import threading
import time

app = Flask(__name__)
DB = "smartshield.db"

PROFILES = [
    ("192.168.1.45", "10.0.0.10", "TCP", "Port Scan", "Critical", "BLOCK"),
    ("172.16.2.15", "10.0.0.20", "TCP", "Brute Force", "High", "BLOCK"),
    ("10.0.0.8", "10.0.0.30", "HTTP", "Suspicious Traffic", "Medium", "ALERT"),
    ("10.0.0.12", "10.0.0.40", "HTTPS", "Normal Traffic", "Low", "ALLOW"),
    ("192.168.1.77", "10.0.0.15", "UDP", "DoS Attempt", "Critical", "BLOCK"),
    ("172.16.1.90", "10.0.0.25", "HTTP", "SQL Injection", "Critical", "BLOCK"),
    ("10.0.0.21", "10.0.0.50", "HTTPS", "Normal Traffic", "Low", "ALLOW"),
    ("192.168.1.60", "10.0.0.60", "TCP", "Suspicious Connection", "Medium", "ALERT"),
]

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            attack_category TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL
        )
    """)
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if count == 0:
        for _ in range(18):
            add_random_event(conn)
    conn.commit()
    conn.close()

def add_random_event(conn=None):
    own = False
    if conn is None:
        conn = db()
        own = True
    src, dst, protocol, category, severity, action = random.choice(PROFILES)
    # Slightly vary private IPs for a more realistic demo stream.
    if random.random() < 0.65:
        src = f"192.168.1.{random.randint(2, 250)}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO events
        (source_ip,destination_ip,protocol,attack_category,severity,timestamp,action)
        VALUES (?,?,?,?,?,?,?)""",
        (src, dst, protocol, category, severity, now, action)
    )
    if own:
        conn.commit()
        conn.close()

def demo_loop():
    while True:
        time.sleep(4)
        try:
            conn = db()
            add_random_event(conn)
            conn.commit()
            conn.close()
        except Exception:
            pass

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/events")
def events():
    limit = min(int(request.args.get("limit", 100)), 500)
    conn = db()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/stats")
def stats():
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    critical = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity='Critical'"
    ).fetchone()[0]
    suspicious = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity IN ('High','Medium')"
    ).fetchone()[0]
    normal = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity='Low'"
    ).fetchone()[0]
    blocked = conn.execute(
        "SELECT COUNT(*) FROM events WHERE action='BLOCK'"
    ).fetchone()[0]

    categories = conn.execute("""
        SELECT attack_category AS name, COUNT(*) AS value
        FROM events GROUP BY attack_category ORDER BY value DESC
    """).fetchall()

    protocols = conn.execute("""
        SELECT protocol AS name, COUNT(*) AS value
        FROM events GROUP BY protocol ORDER BY value DESC
    """).fetchall()

    actions = conn.execute("""
        SELECT action AS name, COUNT(*) AS value
        FROM events GROUP BY action
    """).fetchall()
    conn.close()

    return jsonify({
        "total": total,
        "critical": critical,
        "suspicious": suspicious,
        "normal": normal,
        "blocked": blocked,
        "categories": [dict(x) for x in categories],
        "protocols": [dict(x) for x in protocols],
        "actions": [dict(x) for x in actions]
    })

@app.post("/api/event")
def create_event():
    data = request.get_json(force=True)
    required = ["source_ip", "destination_ip", "protocol", "attack_category", "severity"]
    if not all(data.get(k) for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    severity = data["severity"].title()
    action = "ALLOW" if severity == "Low" else "ALERT"
    if severity in ("High", "Critical"):
        action = "BLOCK"

    conn = db()
    conn.execute(
        """INSERT INTO events
        (source_ip,destination_ip,protocol,attack_category,severity,timestamp,action)
        VALUES (?,?,?,?,?,?,?)""",
        (
            data["source_ip"],
            data["destination_ip"],
            data["protocol"].upper(),
            data["attack_category"],
            severity,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            action
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Event detected", "action": action})

@app.post("/api/clear")
def clear_events():
    conn = db()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    return jsonify({"message": "Events cleared"})

if __name__ == "__main__":
    init_db()
    threading.Thread(target=demo_loop, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
