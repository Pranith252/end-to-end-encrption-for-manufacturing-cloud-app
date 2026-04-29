from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from cryptography.fernet import Fernet
from datetime import datetime
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "securemanuf_secret_2026"

# ============================================
# DATABASE
# ============================================

def get_db():
    conn = sqlite3.connect('securemanuf.db')
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# ENCRYPTION
# ============================================

KEY_FILE = "master.key"

def get_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
        print("🔑 New encryption key created")
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_msg(text):
    f = Fernet(get_key())
    return f.encrypt(text.encode()).hex()

def decrypt_msg(hex_data):
    try:
        f = Fernet(get_key())
        return f.decrypt(bytes.fromhex(hex_data)).decode()
    except Exception as e:
        print(f"Decrypt error: {e}")
        return None

# ============================================
# ROLE PERMISSIONS
# ============================================

# ============================================
# ROLE PERMISSIONS
# ============================================

SENDERS_BY_ROLE = {
    'admin': ['Control-Room', 'Machine-A', 'Machine-B', 'Machine-C', 'QC-Station-1', 'QC-Station-2', 'Assembly-Line-1', 'Maintenance-Unit'],
    'operator': ['Machine-A', 'Machine-B', 'Machine-C', 'Assembly-Line-1'],
    'qc': ['QC-Station-1', 'QC-Station-2'],
    'maintenance': ['Maintenance-Unit']
}

RECEIVER_FOR_USER = {
    'admin': 'Control-Room',
    'operator': 'Machine-A',
    'qc': 'QC-Station-1',
    'maintenance': 'Maintenance'
}

def can_decrypt(msg, username, role):
    """Check if user can decrypt this message"""
    if role == 'admin':
        return True
    # Allow sender to decrypt their own messages
    if msg.get('sent_by') == username:
        return True
    # Allow receiver to decrypt messages sent to them
    return msg['receiver'] == RECEIVER_FOR_USER.get(username, '')

def can_decrypt(msg, username, role):
    if role == 'admin':
        return True
    # Allow sender to decrypt their own messages
    if msg.get('sent_by') == username:
        return True
    # Allow receiver to decrypt messages sent to them
    return msg['receiver'] == RECEIVER_FOR_USER.get(username, '')

def add_audit(action, detail, username):
    try:
        conn = get_db()
        conn.execute('INSERT INTO audit_log (action, detail, username) VALUES (?, ?, ?)', (action, detail, username))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Audit error: {e}")

def is_after_hours():
    hour = datetime.now().hour
    return hour < 8 or hour >= 18

# ============================================
# ROUTES
# ============================================

@app.route('/')
def index():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    session.clear()
    return render_template('login.html')

@app.route('/register')
def register_page():
    session.clear()
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        fullname = data.get('fullname', '').strip()
        username = data.get('username', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'operator')
        
        # Validation
        if not fullname or not username or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 4:
            return jsonify({'error': 'Password must be at least 4 characters'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        # Check if username exists
        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing:
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400
        
        # Insert new user (pending approval)
        conn.execute('''
            INSERT INTO users (username, password, role, full_name, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, role, fullname, 'pending'))
        conn.commit()
        conn.close()
        
        # Log registration
        add_audit('REGISTER', f'New user {username} (role: {role}) registered', 'system')
        
        return jsonify({'success': True, 'message': 'Registration successful. Awaiting admin approval.'})
    
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        u = data.get('username', '').strip().lower()
        p = data.get('password', '')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (u, p)).fetchone()
        conn.close()
        
        if not user:
            add_audit('LOGIN_FAIL', f'Failed login attempt for {u}', 'system')
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Check if user is approved
        if user['status'] != 'active':
            return jsonify({'success': False, 'error': 'Account pending admin approval'}), 401
        
        session['username'] = u
        session['role'] = user['role']
        session['name'] = user['full_name']
        session['user_id'] = user['id']
        
        # Log login
        conn = get_db()
        conn.execute('INSERT INTO login_tracking (username, ip_address, is_after_hours) VALUES (?, ?, ?)',
                     (u, request.remote_addr, is_after_hours()))
        conn.commit()
        conn.close()
        
        add_audit('LOGIN', f'{u} logged in from {request.remote_addr}', u)
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    if 'username' in session:
        add_audit('LOGOUT', f'{session["username"]} logged out', session['username'])
        session.clear()
    return jsonify({'success': True})

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html',
        username=session['username'],
        role=session['role'],
        name=session['name'],
        senders=SENDERS_BY_ROLE.get(session['role'], ['Control-Room'])
    )

@app.route('/api/pending-users', methods=['GET'])
def get_pending_users():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    conn = get_db()
    users = conn.execute('SELECT * FROM users WHERE status = "pending" ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])

@app.route('/api/approve-user', methods=['POST'])
def approve_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    data = request.get_json()
    user_id = data.get('user_id')
    action = data.get('action')
    
    conn = get_db()
    if action == 'approve':
        conn.execute('UPDATE users SET status = "active" WHERE id = ?', (user_id,))
        user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        add_audit('APPROVE_USER', f'Admin approved user {user["username"]}', session['username'])
    else:
        user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        add_audit('REJECT_USER', f'Admin rejected user {user["username"]}', session['username'])
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/send', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        sender = data.get('sender')
        receiver = data.get('receiver')
        msg_text = data.get('message', '').strip()
        priority = data.get('priority', 'normal')
        
        if not msg_text:
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        if sender not in SENDERS_BY_ROLE.get(session['role'], []):
            return jsonify({'error': f'Cannot send from {sender}'}), 403
        
        msg_id = datetime.now().strftime('%Y%m%d%H%M%S%f')
        encrypted = encrypt_msg(msg_text)
        
        conn = get_db()
        conn.execute('''
            INSERT INTO messages (id, sender, receiver, encrypted, priority, sent_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (msg_id, sender, receiver, encrypted, priority, session['username']))
        conn.commit()
        conn.close()
        
        add_audit('SEND', f'[{priority}] {sender}→{receiver}: {msg_text[:50]}', session['username'])
        return jsonify({'success': True, 'id': msg_id, 'full_encrypted': encrypted})
    except Exception as e:
        print(f"Send error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages')
def get_messages():
    if 'username' not in session:
        return jsonify([]), 401
    
    try:
        conn = get_db()
        msgs = conn.execute('SELECT * FROM messages ORDER BY ts DESC').fetchall()
        conn.close()
        
        result = []
        for m in msgs:
            m_dict = dict(m)
            m_dict['can_decrypt'] = can_decrypt(m_dict, session['username'], session['role'])
            
            if m_dict['can_decrypt']:
                plain = decrypt_msg(m_dict['encrypted'])
                m_dict['content'] = plain if plain else '[Decryption Error]'
            else:
                m_dict['content'] = m_dict['encrypted'][:80] + '...'
            
            result.append(m_dict)
        
        return jsonify(result)
    except Exception as e:
        print(f"Messages error: {e}")
        return jsonify([]), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        msg_id = data.get('id')
        
        conn = get_db()
        msg = conn.execute('SELECT * FROM messages WHERE id = ?', (msg_id,)).fetchone()
        
        if not msg:
            conn.close()
            return jsonify({'error': 'Message not found'}), 404
        
        if not can_decrypt(dict(msg), session['username'], session['role']):
            conn.close()
            add_audit('DECRYPT_DENIED', f'{session["username"]} tried to read {msg["sender"]}', session['username'])
            return jsonify({'error': 'Not authorized - message not for you'}), 403
        
        plain = decrypt_msg(msg['encrypted'])
        if not plain:
            return jsonify({'error': 'Decryption failed'}), 500
        
        conn.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (msg_id,))
        conn.commit()
        conn.close()
        
        add_audit('READ', f'{msg["sender"]}→{msg["receiver"]}: {plain[:50]}', session['username'])
        return jsonify({'success': True, 'plaintext': plain})
    except Exception as e:
        print(f"Decrypt error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    if 'username' not in session:
        return jsonify({}), 401
    
    try:
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) as c FROM messages').fetchone()['c']
        critical = conn.execute('SELECT COUNT(*) as c FROM messages WHERE priority = "critical"').fetchone()['c']
        high = conn.execute('SELECT COUNT(*) as c FROM messages WHERE priority = "high"').fetchone()['c']
        normal = conn.execute('SELECT COUNT(*) as c FROM messages WHERE priority = "normal"').fetchone()['c']
        low = conn.execute('SELECT COUNT(*) as c FROM messages WHERE priority = "low"').fetchone()['c']
        
        if session['role'] == 'admin':
            unread = conn.execute('SELECT COUNT(*) as c FROM messages WHERE is_read = 0').fetchone()['c']
        else:
            rec = RECEIVER_FOR_USER.get(session['username'], '')
            unread = conn.execute('SELECT COUNT(*) as c FROM messages WHERE receiver = ? AND is_read = 0', (rec,)).fetchone()['c']
        
        conn.close()
        return jsonify({'total': total, 'unread': unread, 'critical': critical, 'high': high, 'normal': normal, 'low': low})
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({'total': 0, 'unread': 0, 'critical': 0, 'high': 0, 'normal': 0, 'low': 0})

@app.route('/api/audit')
def get_audit():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    try:
        conn = get_db()
        logs = conn.execute('SELECT * FROM audit_log ORDER BY ts DESC LIMIT 100').fetchall()
        conn.close()
        return jsonify([dict(l) for l in logs])
    except Exception as e:
        print(f"Audit error: {e}")
        return jsonify([])

@app.route('/api/login-tracking')
def get_login_tracking():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    try:
        conn = get_db()
        logs = conn.execute('SELECT * FROM login_tracking ORDER BY login_time DESC LIMIT 100').fetchall()
        conn.close()
        return jsonify([dict(l) for l in logs])
    except Exception as e:
        print(f"Login tracking error: {e}")
        return jsonify([])

@app.route('/api/clear-messages', methods=['POST'])
def clear_messages():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    try:
        conn = get_db()
        conn.execute('DELETE FROM messages')
        conn.commit()
        conn.close()
        add_audit('CLEAR_ALL', 'All messages deleted by admin', session['username'])
        return jsonify({'success': True})
    except Exception as e:
        print(f"Clear error: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/seed')
def seed_messages():
    demos = [
        ('Machine-A', 'Control-Room', '⚠️ ALERT: Power consumption 38% above threshold on Unit A-1. Investigating.', 'high'),
        ('QC-Station-1', 'Quality-Manager', 'CRITICAL: Viscosity out of spec on Batch #208. Defect rate 12%. Halt production immediately!', 'critical'),
        ('Machine-B', 'Maintenance', 'Hydraulic seal degrading on Unit B-3. Maintenance required within 4 hours.', 'high'),
        ('Assembly-Line-1', 'Control-Room', 'Line 1 running at 95% efficiency. All production targets on track for this shift.', 'low'),
        ('Machine-C', 'Control-Room', 'Temperature spike detected on Unit C-2 — auto-reducing speed to 80%. Monitor closely.', 'high'),
        ('Maintenance-Unit', 'Maintenance', 'Scheduled PM complete on Robot Arm #2. Unit cleared for full operation.', 'normal'),
        ('QC-Station-2', 'Quality-Manager', 'QC PASSED — Batch #207 cleared. 498/500 units within specification limits.', 'normal'),
        ('Control-Room', 'Floor-Supervisor', 'Shift change at 14:00. Ensure all production logs are signed off before leaving.', 'normal'),
        ('Machine-A', 'Machine-B', 'Batch #208 completed — 500 units produced. Ready for quality inspection.', 'normal'),
        ('QC-Station-1', 'Control-Room', 'QUALITY ALERT: Batch #208 rejected. Defect rate exceeded threshold. Quarantine initiated.', 'critical')
    ]
    
    count = 0
    for s, r, m, p in demos:
        try:
            msg_id = datetime.now().strftime('%Y%m%d%H%M%S%f')
            encrypted = encrypt_msg(m)
            conn = get_db()
            conn.execute('INSERT INTO messages (id, sender, receiver, encrypted, priority, sent_by) VALUES (?, ?, ?, ?, ?, ?)',
                (msg_id, s, r, encrypted, p, 'seed'))
            conn.commit()
            conn.close()
            count += 1
        except Exception as e:
            print(f"Seed error: {e}")
    
    add_audit('SEED', f'Added {count} demo messages', 'system')
    return jsonify({'success': True, 'count': count})

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  🔒 SECUREMANUF PRO - E2EE Manufacturing System")
    print("="*55)
    print("  🌐 Server: http://127.0.0.1:5000")
    print("\n  📋 Login Credentials:")
    print("     admin / admin123 (Administrator)")
    print("\n  📝 New Users:")
    print("     Go to /register to create new account")
    print("     Admin must approve in dashboard")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)