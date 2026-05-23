"""SQLite database for Incident Response Engine."""
import sqlite3
import os
from datetime import datetime
from .config import DB_PATH


def get_db():
    """Get database connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            dest_ip TEXT,
            port INTEGER,
            user TEXT,
            process TEXT,
            path TEXT,
            data TEXT,
            raw_log TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_dt ON events(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT,
            status TEXT DEFAULT 'open',
            description TEXT,
            source_ips TEXT,
            event_count INTEGER DEFAULT 0,
            false_positive INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_dt ON incidents(created_at DESC)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            pattern TEXT NOT NULL,
            evidence TEXT,
            confidence REAL DEFAULT 0.0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_inc ON correlations(incident_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS forensics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            timeline TEXT,
            iocs TEXT,
            attack_vector TEXT,
            affected_systems TEXT,
            analysis TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_fore_inc ON forensics(incident_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS containment_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            result TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cont_inc ON containment_actions(incident_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS remediation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            action_type TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            verified INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remed_inc ON remediation_actions(incident_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            report_type TEXT DEFAULT 'nist',
            content TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rep_inc ON reports(incident_id)")

    conn.commit()
    conn.close()
    return True


def insert_event(event_type, source_ip=None, dest_ip=None, port=None, user=None,
                 process=None, path=None, data=None, raw_log=None):
    """Insert a telemetry event."""
    conn = get_db()
    conn.execute(
        "INSERT INTO events (event_type, source_ip, dest_ip, port, user, process, path, data, raw_log, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (event_type, source_ip, dest_ip, port, user, process, path, data, raw_log, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def insert_incident(rule_id, name, severity, category, description, source_ips, event_count):
    """Insert a new incident."""
    now = datetime.utcnow().isoformat()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO incidents (rule_id, name, severity, category, status, description, source_ips, event_count, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rule_id, name, severity, category, "open", description, source_ips, event_count, now, now),
    )
    incident_id = cur.lastrowid
    conn.commit()
    conn.close()
    return incident_id


def update_incident_status(incident_id, status):
    """Update incident status."""
    conn = get_db()
    conn.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (status, datetime.utcnow().isoformat(), incident_id))
    conn.commit()
    conn.close()


def insert_correlation(incident_id, pattern, evidence, confidence):
    """Insert correlation data."""
    conn = get_db()
    conn.execute(
        "INSERT INTO correlations (incident_id, pattern, evidence, confidence, created_at) VALUES (?,?,?,?,?)",
        (incident_id, pattern, evidence, confidence, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def insert_forensic(incident_id, timeline, iocs, attack_vector, affected_systems, analysis):
    """Insert forensic analysis."""
    conn = get_db()
    conn.execute(
        "INSERT INTO forensics (incident_id, timeline, iocs, attack_vector, affected_systems, analysis, created_at) VALUES (?,?,?,?,?,?,?)",
        (incident_id, timeline, iocs, attack_vector, affected_systems, analysis, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def insert_containment_action(incident_id, action_type, target, status="pending"):
    """Insert containment action."""
    conn = get_db()
    conn.execute(
        "INSERT INTO containment_actions (incident_id, action_type, target, status, created_at) VALUES (?,?,?,?,?)",
        (incident_id, action_type, target, status, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def update_containment_action(action_id, status, result=None):
    """Update containment action."""
    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE containment_actions SET status=?, result=?, completed_at=? WHERE id=?", (status, result, now, action_id))
    conn.commit()
    conn.close()


def insert_remediation_action(incident_id, action_type, description, status="pending"):
    """Insert remediation action."""
    conn = get_db()
    conn.execute(
        "INSERT INTO remediation_actions (incident_id, action_type, description, status, created_at) VALUES (?,?,?,?,?)",
        (incident_id, action_type, description, status, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def insert_report(incident_id, content, report_type="nist"):
    """Insert generated report."""
    conn = get_db()
    conn.execute(
        "INSERT INTO reports (incident_id, report_type, content, created_at) VALUES (?,?,?,?)",
        (incident_id, report_type, content, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_open_incidents():
    """Get all open incidents."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM incidents WHERE status='open' ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_events(limit=100):
    """Get recent events."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM events ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incident_events(incident_id):
    """Get events for a specific incident."""
    conn = get_db()
    inc = conn.execute("SELECT source_ips FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        conn.close()
        return []
    ips = inc["source_ips"].split(",") if inc["source_ips"] else []
    placeholders = ",".join("?" * len(ips))
    rows = conn.execute(f"SELECT * FROM events WHERE source_ip IN ({placeholders}) ORDER BY created_at DESC LIMIT 200", ips).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    """Get dashboard statistics."""
    conn = get_db()
    stats = {}
    stats["total_events"] = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    stats["total_incidents"] = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    stats["open_incidents"] = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
    stats["contained_incidents"] = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='contained'").fetchone()[0]
    stats["resolved_incidents"] = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='resolved'").fetchone()[0]
    stats["false_positives"] = conn.execute("SELECT COUNT(*) FROM incidents WHERE false_positive=1").fetchone()[0]
    stats["total_containments"] = conn.execute("SELECT COUNT(*) FROM containment_actions").fetchone()[0]
    stats["total_reports"] = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    severity_dist = {}
    for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity").fetchall():
        severity_dist[row["severity"]] = row["cnt"]
    stats["severity_distribution"] = severity_dist

    category_dist = {}
    for row in conn.execute("SELECT category, COUNT(*) as cnt FROM incidents GROUP BY category").fetchall():
        category_dist[row["category"]] = row["cnt"]
    stats["category_distribution"] = category_dist

    conn.close()
    return stats
