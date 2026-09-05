import sqlite3


def create_database():
    connection = sqlite3.connect("cybersecurity.db")

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding TEXT,
            created_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ids_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert TEXT,
            created_at TEXT
        )
    """)

    connection.commit()

    connection.close

def save_finding(finding):
    connection = sqlite3.connect("cybersecurity.db")

    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO security_findings (finding, created_at) VALUES (?, datetime('now'))",
        (finding,)
    )

    connection.commit()
    connection.close()

def save_alert(alert):
    connection = sqlite3.connect("cybersecurity.db")

    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO ids_alerts (alert, created_at) VALUES (?, datetime('now'))",
        (alert,)
    )

    connection.commit()
    connection.close()

def get_findings():
    connection = sqlite3.connect("cybersecurity.db")

    cursor = connection.cursor()

    cursor.execute(
        "SELECT id, finding, created_at FROM security_findings"
    )

    findings = cursor.fetchall()

    connection.close()

    return findings

def get_alerts():
    connection = sqlite3.connect("cybersecurity.db")

    cursor = connection.cursor()

    cursor.execute(
        "SELECT id, alert, created_at FROM ids_alerts"
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts

if __name__ == "__main__":
    create_database()
    print("Database ready.")