import sqlite3
import os

def init_db():
    # Delete existing database if it exists (clean start)
    if os.path.exists('securemanuf.db'):
        os.remove('securemanuf.db')
        print("🗑️ Old database removed")
    
    conn = sqlite3.connect('securemanuf.db')
    cursor = conn.cursor()
    
    # Users table with status column
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            encrypted TEXT NOT NULL,
            priority TEXT DEFAULT 'normal',
            is_read BOOLEAN DEFAULT 0,
            sent_by TEXT NOT NULL
        )
    ''')
    
    # Audit log table
    cursor.execute('''
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            username TEXT NOT NULL
        )
    ''')
    
    # Login tracking table
    cursor.execute('''
        CREATE TABLE login_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            is_after_hours BOOLEAN DEFAULT 0
        )
    ''')
    
    # Insert ALL users (admin, operator, qc, maintenance) - ALL APPROVED
    users = [
        ('admin', 'admin123', 'admin', 'System Administrator', 'active'),
        ('operator', 'op123', 'operator', 'Floor Operator', 'active'),
        ('qc', 'qc123', 'qc', 'QC Inspector', 'active'),
        ('maintenance', 'maint123', 'maintenance', 'Maintenance Engineer', 'active')
    ]
    
    for username, password, role, full_name, status in users:
        try:
            cursor.execute('''
                INSERT INTO users (username, password, role, full_name, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password, role, full_name, status))
            print(f"✅ Added user: {username} / {password}")
        except Exception as e:
            print(f"Error adding {username}: {e}")
    
    conn.commit()
    conn.close()
    
    print("\n" + "="*50)
    print("✅ DATABASE CREATED SUCCESSFULLY!")
    print("📁 File: securemanuf.db")
    print("\n👥 ALL USERS (Auto-Approved):")
    print("   admin      / admin123     (Administrator)")
    print("   operator   / op123        (Floor Operator)")
    print("   qc         / qc123        (QC Inspector)")
    print("   maintenance / maint123    (Maintenance Engineer)")
    print("\n📝 New users can register at /register")
    print("   Admin must approve them in dashboard")
    print("="*50 + "\n")

if __name__ == "__main__":
    init_db()