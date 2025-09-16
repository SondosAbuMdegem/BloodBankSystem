import sqlite3
from datetime import date, datetime, timezone
import json
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import xml.etree.ElementTree as ET
from tkinter import filedialog
import csv
from pathlib import Path
import os, hashlib, hmac

PBKDF2_ITERATIONS = 200_000  # חוזק גיבוב סיסמא

DB_PATH = "becs.db"

# -------------------- Data / Rules --------------------
BLOOD_TYPES = ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"]
# שכיחויות באוכלוסיית ישראל (מקור הטבלה ששלחת)
ABO_RH_PREVALENCE = {
    "O+": 0.32, "A+": 0.34, "B+": 0.17, "AB+": 0.07,
    "O-": 0.03, "A-": 0.04, "B-": 0.02, "AB-": 0.01,
}

def policy_sort_key(bt: str):
    """
    ככל שהסוג שכיח יותר — העדיפות גבוהה יותר.
    נמיין לפי שכיחות יורדת (reverse=True).
    """
    return ABO_RH_PREVALENCE.get(bt, 0.0)

# ---- RBAC helpers ----
ROLES = ("admin", "user", "research")
def is_valid_national_id(nid: str) -> bool:
    return (nid or "").isdigit() and len(nid) == 9

def is_admin(user):    return bool(user) and user.get("role") == "admin"
def is_worker(user):   return bool(user) and user.get("role") in ("admin", "user")
def is_research(user): return bool(user) and user.get("role") == "research"

# TODO: Replace with the EXACT compatibility from your assignment doc.
# donors_that_can_supply[recipient] -> list of donor types that can donate to 'recipient'
donors_that_can_supply = {
    "O-":  ["O-"],
    "O+":  ["O-", "O+"],
    "A-":  ["O-", "A-"],
    "A+":  ["O-", "O+", "A-", "A+"],
    "B-":  ["O-", "B-"],
    "B+":  ["O-", "O+", "B-", "B+"],
    "AB-": ["O-", "A-", "B-", "AB-"],
    "AB+": ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"],
}

# -------------------- DB --------------------
def db_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS Inventory(
        blood_type TEXT PRIMARY KEY,
        units INTEGER NOT NULL DEFAULT 0
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS Donations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        donor_id TEXT NOT NULL,
        donor_name TEXT NOT NULL,
        blood_type TEXT NOT NULL,
        donation_date TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS Issues(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_type TEXT NOT NULL,  -- 'routine' | 'mci'
        blood_type TEXT NOT NULL,
        units INTEGER NOT NULL,
        issue_date TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS Rarity(
        blood_type TEXT PRIMARY KEY,
        rarity_weight REAL NOT NULL
    )""")
    # seed inventory rows
    for bt in BLOOD_TYPES:
        cur.execute("INSERT OR IGNORE INTO Inventory(blood_type, units) VALUES(?, 0)", (bt,))
    # placeholder rarity weights
    default_weights = {
        "O-": 1.0, "O+": 0.8, "A-": 0.9, "A+": 0.7,
        "B-": 0.95, "B+": 0.75, "AB-": 1.1, "AB+": 0.6
    }
    for bt, w in default_weights.items():
        cur.execute("INSERT OR IGNORE INTO Rarity(blood_type, rarity_weight) VALUES(?, ?)", (bt, w))

    # ✅ תוסיפי את זה לפני הסגירה
    ensure_audit_schema(con)
    # ✅ HIPAA step 1: users/roles
    ensure_user_schema(con)
    seed_admin_if_needed(con)

    con.commit()
    con.close()


def get_stock(bt):
    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT units FROM Inventory WHERE blood_type = ?", (bt,))
    row = cur.fetchone()
    con.close()
    return row[0] if row else 0

def add_stock(bt, n):
    con = db_conn()
    cur = con.cursor()
    cur.execute("UPDATE Inventory SET units = units + ? WHERE blood_type = ?", (n, bt))
    con.commit()
    con.close()

def take_stock(bt, n):
    if get_stock(bt) < n:
        return False
    con = db_conn()
    cur = con.cursor()
    cur.execute("UPDATE Inventory SET units = units - ? WHERE blood_type = ?", (n, bt))
    con.commit()
    con.close()
    return True

def rarity_weight(bt):
    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT rarity_weight FROM Rarity WHERE blood_type = ?", (bt,))
    row = cur.fetchone()
    con.close()
    return float(row[0]) if row else 1.0

def log_event(*, actor, action, entity,
              record_id=None, old_values=None, new_values=None,
              source='GUI', success=True, note=None):
    """
    רושם שורה בטבלת audit_log (פותח/סוגר חיבור בעצמו).
    old_values/new_values אפשר dict/list או מחרוזת.
    """
    con = db_conn()
    cur = con.cursor()

    def _to_json(v):
        if isinstance(v, (dict, list)):
            return json.dumps(v, ensure_ascii=False)
        return v

    cur.execute("""
      INSERT INTO audit_log(event_time_utc, actor, action, entity, record_id,
                            old_values, new_values, source, success, note)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        (actor or "UNKNOWN"),
        action,
        entity,
        str(record_id) if record_id is not None else None,
        _to_json(old_values),
        _to_json(new_values),
        source,
        1 if success else 0,
        note
    ))
    con.commit()
    con.close()
def require_operator(actor: str) -> bool:
    """
    מחייב Operator ID לפני ביצוע פעולה.
    מציג הודעת שגיאה, ורושם אירוע כושל ביומן אם חסר.
    """
    if not actor or actor == "UNKNOWN":
        messagebox.showerror("Error", "Please enter Operator ID before performing actions.")
        # לוג אופציונלי – ניסיון פעולה בלי מזהה מפעיל
        log_event(actor="UNKNOWN", action="OPERATOR_ID_MISSING", entity="system",
                  success=False, note="Operator ID required")
        return False
    return True

def ensure_audit_schema(con):
    cur = con.cursor()
    # טבלת יומן פעולות (append-only)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time_utc TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        entity TEXT NOT NULL,
        record_id TEXT,
        old_values TEXT,
        new_values TEXT,
        source TEXT DEFAULT 'GUI',
        success INTEGER NOT NULL DEFAULT 1,
        note TEXT
    )
    """)
    # מניעת עדכון/מחיקה ביומן
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'Audit log is append-only (no UPDATE)');
    END;
    """)
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
    BEFORE DELETE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'Audit log is append-only (no DELETE)');
    END;
    """)
    con.commit()


def ensure_user_schema(con):
    cur = con.cursor()
    # טבלת Users מלאה כולל national_id ייחודי
    cur.execute("""
    CREATE TABLE IF NOT EXISTS Users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK(role IN ('admin','user','research')),
        password_salt BLOB NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        must_reset INTEGER NOT NULL DEFAULT 0,
        national_id TEXT NOT NULL DEFAULT '000000001'
    )
    """)

    # מיגרציה: להוסיף עמודות חסרות
    cur.execute("PRAGMA table_info(Users)")
    cols = {r[1] for r in cur.fetchall()}
    if "is_active" not in cols:
        cur.execute("ALTER TABLE Users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    if "must_reset" not in cols:
        cur.execute("ALTER TABLE Users ADD COLUMN must_reset INTEGER NOT NULL DEFAULT 0")
    if "national_id" not in cols:
        # מוסיפים בלי UNIQUE כי ALTER לא תומך ב־constraint; ניצור אינדקס ייחודי בנפרד
        cur.execute("ALTER TABLE Users ADD COLUMN national_id TEXT")
        # מילוי ערך ברירת מחדל למשתמש admin (אם קיים)
        cur.execute("UPDATE Users SET national_id='000000001' WHERE username='admin' AND (national_id IS NULL OR national_id='')")
    # אינדקס ייחודי על תעודת הזהות
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_national_id ON Users(national_id)")
    con.commit()


def _hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    return salt, pw_hash

def _verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    return pw_hash == expected_hash

def seed_admin_if_needed(con):
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM Users")
    count = cur.fetchone()[0]
    if count == 0:
        salt, pw_hash = _hash_password("admin")
        cur.execute("""
            INSERT INTO Users(username, role, password_salt, password_hash, created_at, is_active, must_reset, national_id)
            VALUES(?,?,?,?,?,?,0,?)
        """, ("admin", "admin", salt, pw_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1, "000000001"))


def get_user_by_username(username: str):
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT id, username, role, password_salt, password_hash, is_active, must_reset
        FROM Users WHERE username = ?
    """, (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "role": row[2],
        "password_salt": row[3],
        "password_hash": row[4],
        "is_active": row[5],
        "must_reset": row[6],
    }

def verify_user_password(username: str, password: str):
    u = get_user_by_username(username)
    if not u or u.get("is_active") == 0:
        return False, None
    ok = _verify_password(password, u["password_salt"], u["password_hash"])
    return (ok, u if ok else None)
def list_users():
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT
            username,
            role,
            is_active,
            created_at,
            lower(hex(password_hash)) AS pw_hash_hex,
            lower(hex(password_salt)) AS salt_hex,
            national_id
        FROM Users
        ORDER BY username
    """)
    rows = cur.fetchall()
    con.close()
    return rows  # [(username, role, is_active, created_at, pw_hash_hex, salt_hex, national_id), ...]

def create_user(*, username: str, role: str, password: str, national_id: str, actor: str):
    if role not in ROLES:
        raise ValueError("Invalid role")
    username = (username or "").strip()
    if not username:
        raise ValueError("Username required")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 chars")
    national_id = (national_id or "").strip()
    if not is_valid_national_id(national_id):
        raise ValueError("National ID must be exactly 9 digits")

    con = db_conn()
    cur = con.cursor()
    # ייחודיות
    cur.execute("SELECT 1 FROM Users WHERE username=?", (username,))
    if cur.fetchone():
        con.close()
        raise ValueError("Username already exists")

    cur.execute("SELECT 1 FROM Users WHERE national_id=?", (national_id,))
    if cur.fetchone():
        con.close()
        raise ValueError("National ID already exists")

    salt, pw_hash = _hash_password(password)
    cur.execute("""
        INSERT INTO Users(username, role, password_salt, password_hash, created_at, is_active, must_reset, national_id)
        VALUES(?,?,?,?,?,?,0,?)
    """, (username, role, salt, pw_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1, national_id))
    con.commit()
    con.close()

    log_event(actor=actor, action="USER_CREATE", entity="Users",
              success=True, new_values={"username": username, "role": role, "national_id": "***"})
def reset_password_with_national_id(username: str, national_id: str, new_password: str) -> bool:
    username = (username or "").strip()
    national_id = (national_id or "").strip()
    if not username or not is_valid_national_id(national_id):
        raise ValueError("Invalid username or national ID")
    if not new_password or len(new_password) < 8:
        raise ValueError("Password must be at least 8 chars")

    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT id, national_id FROM Users WHERE username=? AND is_active=1", (username,))
    row = cur.fetchone()
    if not row:
        con.close()
        raise ValueError("User not found or inactive")
    user_id, nid_db = row
    if nid_db != national_id:
        con.close()
        raise ValueError("National ID does not match")

    salt, pw_hash = _hash_password(new_password)
    cur.execute("UPDATE Users SET password_salt=?, password_hash=?, must_reset=0 WHERE id=?",
                (salt, pw_hash, user_id))
    con.commit()
    con.close()

    # רישום ביומן עם actor = שם המשתמש (Self-service)
    log_event(actor=username, action="PASSWORD_RESET_SELF", entity="Users",
              success=True, note="Reset via national_id", new_values={"username": username})
    return True

def get_user_admin_view(username: str):
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT id, username, role, is_active, created_at, national_id
        FROM Users WHERE username=?
    """, (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "role": row[2],
        "is_active": int(row[3]),
        "created_at": row[4],
        "national_id": row[5],
    }

def _count_active_admins(con) -> int:
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM Users WHERE role='admin' AND is_active=1")
    return int(cur.fetchone()[0])

def update_user_fields(old_username: str, *, new_username: str, role: str, is_active: int, national_id: str, actor: str):
    new_username = (new_username or "").strip()
    national_id = (national_id or "").strip()
    if not new_username:
        raise ValueError("Username required")
    if role not in ROLES:
        raise ValueError("Invalid role")
    if is_active not in (0, 1):
        raise ValueError("is_active must be 0/1")
    if not is_valid_national_id(national_id):
        raise ValueError("National ID must be exactly 9 digits")

    con = db_conn()
    cur = con.cursor()

    # מצב נוכחי
    cur.execute("SELECT id, username, role, is_active, created_at, national_id FROM Users WHERE username=?", (old_username,))
    row = cur.fetchone()
    if not row:
        con.close()
        raise ValueError("User not found")
    user_id, _cur_username, cur_role, cur_active, cur_created_at, cur_nid = row

    # ייחודיות username / national_id (מלבד המשתמש עצמו)
    cur.execute("SELECT 1 FROM Users WHERE username=? AND id<>?", (new_username, user_id))
    if cur.fetchone():
        con.close()
        raise ValueError("Username already exists")
    cur.execute("SELECT 1 FROM Users WHERE national_id=? AND id<>?", (national_id, user_id))
    if cur.fetchone():
        con.close()
        raise ValueError("National ID already exists")

    # הגנה: לא משביתים/מדרגים את admin הפעיל האחרון
    if cur_role == "admin" and (role != "admin" or is_active == 0):
        admins = _count_active_admins(con)
        if admins <= 1:
            con.close()
            raise ValueError("Cannot demote/deactivate the last active admin")

    old_values = {
        "username": _cur_username, "role": cur_role, "is_active": int(cur_active),
        "created_at": cur_created_at, "national_id": cur_nid
    }
    new_values = {
        "username": new_username, "role": role, "is_active": is_active,
        "created_at": cur_created_at, "national_id": national_id
    }

    # עדכון
    cur.execute("""
        UPDATE Users
        SET username=?, role=?, is_active=?, national_id=?
        WHERE id=?
    """, (new_username, role, is_active, national_id, user_id))
    con.commit()
    con.close()

    log_event(actor=actor, action="USER_UPDATE", entity="Users",
              record_id=user_id, old_values=old_values,
              new_values={**new_values, "national_id": "***"}, success=True)

def delete_user(username: str, actor: str):
    username = (username or "").strip()
    if not username:
        raise ValueError("Username required")

    # לא מוחקים את עצמך
    if username == actor:
        raise ValueError("You cannot delete your own account")

    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT id, role, is_active, created_at, national_id FROM Users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        con.close()
        raise ValueError("User not found")

    user_id, role, is_active, created_at, national_id = row

    # לא מוחקים את ה־admin הפעיל האחרון
    if role == "admin" and int(is_active) == 1:
        admins = _count_active_admins(con)
        if admins <= 1:
            con.close()
            raise ValueError("Cannot delete the last active admin")

    # מחיקה
    cur.execute("DELETE FROM Users WHERE id=?", (user_id,))
    con.commit()
    con.close()

    log_event(actor=actor, action="USER_DELETE", entity="Users", record_id=user_id,
              old_values={"username": username, "role": role, "is_active": int(is_active),
                          "created_at": created_at, "national_id": "***"},
              success=True)

def export_all_to_csv_dir(actor: str, role: str):
    """CSV לאקסל, עם הסתרת PHI אם role == 'research'."""
    if not require_operator(actor):
        return
    from tkinter import filedialog
    d = filedialog.askdirectory(title="Choose export folder")
    if not d:
        return
    base = Path(d)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = base / f"becs_export_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    con = db_conn()
    cur = con.cursor()

    # בניית שאילתות לפי תפקיד
    if role == "research":
        donations_sql = "SELECT id, '[REDACTED]' AS donor_id, '[REDACTED]' AS donor_name, blood_type, donation_date FROM Donations"
        audit_sql     = "SELECT id, event_time_utc, actor, action, entity, record_id, '[REDACTED]' AS old_values, '[REDACTED]' AS new_values, source, success, note FROM audit_log"
    else:
        donations_sql = "SELECT id, donor_id, donor_name, blood_type, donation_date FROM Donations"
        audit_sql     = "SELECT id, event_time_utc, actor, action, entity, record_id, old_values, new_values, source, success, note FROM audit_log"

    tables = [
        ("Donations", donations_sql),
        ("Issues",    "SELECT id, request_type, blood_type, units, issue_date FROM Issues"),
        ("Inventory", "SELECT blood_type, units FROM Inventory"),
        ("Rarity",    "SELECT blood_type, rarity_weight FROM Rarity"),
        ("audit_log", audit_sql),
    ]

    for name, sql in tables:
        cur.execute(sql)
        rows = cur.fetchall()
        headers = [d[0] for d in cur.description]
        with open(outdir / f"{name}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(headers)
            w.writerows(rows)

    con.close()
    log_event(actor=actor, action="EXPORT_CSV", entity="system",
              success=True, new_values={"dir": str(outdir), "role": role})
    messagebox.showinfo("Export", f"CSV files saved to:\n{outdir}")


def export_all_to_html(actor: str, role: str):
    """דוח HTML ידידותי (RTl) — עם הסתרת PHI ל־research. אפשר להדפיס ל־PDF."""
    if not require_operator(actor):
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = filedialog.asksaveasfilename(
        title="Save HTML report",
        defaultextension=".html",
        initialfile=f"becs_export_{ts}.html",
        filetypes=[("HTML", "*.html")]
    )
    if not path:
        return

    con = db_conn()
    cur = con.cursor()

    if role == "research":
        donations_sql = "SELECT id, '[REDACTED]' AS donor_id, '[REDACTED]' AS donor_name, blood_type, donation_date FROM Donations"
        audit_sql     = "SELECT id, event_time_utc, actor, action, entity, record_id, success, note, '[REDACTED]' AS old_values, '[REDACTED]' AS new_values FROM audit_log ORDER BY id DESC"
    else:
        donations_sql = "SELECT id, donor_id, donor_name, blood_type, donation_date FROM Donations"
        audit_sql     = "SELECT id, event_time_utc, actor, action, entity, record_id, success, note, old_values, new_values FROM audit_log ORDER BY id DESC"

    sections = [
        ("Donations", donations_sql),
        ("Issues",    "SELECT id, request_type, blood_type, units, issue_date FROM Issues"),
        ("Inventory", "SELECT blood_type, units FROM Inventory"),
        ("Rarity",    "SELECT blood_type, rarity_weight FROM Rarity"),
        ("Audit Log", audit_sql),
    ]

    def html_table(title, headers, rows):
        head_html = "".join(f"<th>{h}</th>" for h in headers)
        rows_html = []
        for r in rows:
            cells = "".join(f"<td>{'' if (c is None) else str(c)}</td>" for c in r)
            rows_html.append(f"<tr>{cells}</tr>")
        return f"""
        <h2>{title}</h2>
        <table>
          <thead><tr>{head_html}</tr></thead>
          <tbody>
            {''.join(rows_html)}
          </tbody>
        </table>
        """

    parts = []
    for title, sql in sections:
        cur.execute(sql)
        rows = cur.fetchall()
        headers = [d[0] for d in cur.description]
        parts.append(html_table(title, headers, rows))

    con.close()

    html = f"""<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<title>BECS Export</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #555; margin-bottom: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; table-layout: fixed; }}
  th, td {{ border: 1px solid #ccc; padding: 6px; vertical-align: top; word-wrap: break-word; }}
  th {{ background: #f2f2f2; }}
  @media print {{ a#print-hint {{ display: none; }} }}
</style>
</head>
<body>
  <h1>BECS – Export Report</h1>
  <div class="meta">
    Generated (Local): {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
    Operator: {actor} | Role: {role}
  </div>
  <p id="print-hint">להפקת PDF: הדפסה → שמירה כ־PDF.</p>
  {''.join(parts)}
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    log_event(actor=actor, action="EXPORT_HTML", entity="system",
              success=True, new_values={"file": path, "role": role})
    messagebox.showinfo("Export", f"HTML report saved.\nOpen & Print→Save as PDF:\n{path}")


def export_all_to_xml(file_path: str, actor: str, role: str):
    """
    XML אחד לכל הטבלאות; אם role == 'research' – מסתיר donor_id/donor_name ועוטף old/new בערך REDACTED.
    """
    con = db_conn()
    cur = con.cursor()

    root = ET.Element("becs_export", {
        "generated_local": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "actor": actor,
        "role": role,
        "db_path": DB_PATH,
        "version": "1.1"
    })

    def add_table(name: str, query: str):
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        t = ET.SubElement(root, name)
        t.set("rowcount", str(len(rows)))
        for r in rows:
            row_el = ET.SubElement(t, "row")
            for col, val in zip(cols, r):
                cell = ET.SubElement(row_el, col)
                cell.text = "" if val is None else str(val)
        return len(rows)

    # שאילתות עם/בלי מסוך
    if role == "research":
        donations_sql = "SELECT id, '[REDACTED]' AS donor_id, '[REDACTED]' AS donor_name, blood_type, donation_date FROM Donations ORDER BY id"
        audit_sql     = "SELECT id, event_time_utc, actor, action, entity, record_id, '[REDACTED]' AS old_values, '[REDACTED]' AS new_values, source, success, note FROM audit_log ORDER BY id"
    else:
        donations_sql = "SELECT id, donor_id, donor_name, blood_type, donation_date FROM Donations ORDER BY id"
        audit_sql     = "SELECT id, event_time_utc, actor, action, entity, record_id, old_values, new_values, source, success, note FROM audit_log ORDER BY id"

    counts = {}
    counts["Donations"] = add_table("Donations", donations_sql)
    counts["Issues"]    = add_table("Issues",    "SELECT id, request_type, blood_type, units, issue_date FROM Issues ORDER BY id")
    counts["Inventory"] = add_table("Inventory", "SELECT blood_type, units FROM Inventory ORDER BY blood_type")
    counts["Rarity"]    = add_table("Rarity",    "SELECT blood_type, rarity_weight FROM Rarity ORDER BY blood_type")
    counts["audit_log"] = add_table("audit_log", audit_sql)

    con.close()

    tree = ET.ElementTree(root)
    tree.write(file_path, encoding="utf-8", xml_declaration=True)
    return counts

# -------------------- Suggestion Logic --------------------
def suggest_alternative(recipient_bt, units_needed):
    """
    מחזיר את סוג הדם בעל העדיפות הגבוהה ביותר (לפי שכיחות באוכלוסייה)
    מבין התורמים התואמים לרסיפיינט, כאשר יש ממנו לפחות יחידה אחת.
    הערה: לא מציע את אותו סוג שבוקש (כדי לשמר את ההיגיון 'אין' -> חלופות).
    """
    cands = [bt for bt in donors_that_can_supply.get(recipient_bt, []) if bt != recipient_bt]
    cands = [bt for bt in cands if get_stock(bt) > 0]
    cands.sort(key=policy_sort_key, reverse=True)  # שכיח יותר קודם
    return cands[0] if cands else None

class LoginDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Login")
        self.resizable(False, False)
        self.result = None

        self.username = tk.StringVar()
        self.password = tk.StringVar()

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0)

        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(frm, textvariable=self.username).grid(row=0, column=1, sticky="ew", pady=4)

        ttk.Label(frm, text="Password").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(frm, textvariable=self.password, show="*").grid(row=1, column=1, sticky="ew", pady=4)

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, columnspan=2, pady=(8,0), sticky="e")
        ttk.Button(btns, text="Login", command=self.try_login).pack(side="left", padx=6)
        ttk.Button(btns, text="Quit", command=self.on_cancel).pack(side="left")
        ttk.Button(btns, text="Forgot password?", command=self.open_reset).pack(side="left", padx=(0, 6))

        frm.columnconfigure(1, weight=1)

        self.bind("<Return>", lambda _e: self.try_login())
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.transient(master)
        self.grab_set()
        self.focus_set()

    def open_reset(self):
        ResetPasswordDialog(self)

    def try_login(self):
        u = (self.username.get() or "").strip()
        p = self.password.get() or ""
        ok, user = verify_user_password(u, p)
        if ok:
            log_event(actor=u, action="LOGIN_SUCCESS", entity="Users", success=True)
            self.result = user   # dict: id, username, role, salts...
            self.destroy()
        else:
            log_event(actor=u or "UNKNOWN", action="LOGIN_FAILED", entity="Users",
                      success=False, note="Bad credentials")
            messagebox.showerror("Login failed", "Wrong username or password.")

    def on_cancel(self):
        self.result = None
        self.destroy()

class ResetPasswordDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Reset Password")
        self.resizable(False, False)

        self.username = tk.StringVar()
        self.nid = tk.StringVar()
        self.new_pw = tk.StringVar()
        self.new_pw2 = tk.StringVar()

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0)

        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.username, width=24).grid(row=0, column=1, sticky="w")

        ttk.Label(frm, text="National ID (9 digits)").grid(row=1, column=0, sticky="w", pady=2)
        vcmd = (self.register(lambda s: (s == "" or (s.isdigit() and len(s) <= 9))), "%P")
        ttk.Entry(frm, textvariable=self.nid, validate="key", validatecommand=vcmd, width=24).grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="New password").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.new_pw, show="*", width=24).grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Confirm password").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.new_pw2, show="*", width=24).grid(row=3, column=1, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=2, pady=(8,0), sticky="e")
        ttk.Button(btns, text="Reset", command=self.on_reset).pack(side="left", padx=6)
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="left")

        self.bind("<Return>", lambda _e: self.on_reset())
        self.transient(master)
        self.grab_set()
        self.focus_set()

    def on_reset(self):
        try:
            if self.new_pw.get() != self.new_pw2.get():
                raise ValueError("Passwords do not match")
            reset_password_with_national_id(self.username.get(), self.nid.get(), self.new_pw.get())
            messagebox.showinfo("Done", "Password has been reset.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Reset failed", str(e))

class EditUserDialog(tk.Toplevel):
    def __init__(self, master, username: str, actor: str, on_saved_callback):
        super().__init__(master)
        self.title(f"Edit User: {username}")
        self.resizable(False, False)
        self.actor = actor
        self.on_saved = on_saved_callback
        self.old_username = username

        # טען נתונים עדכניים
        u = get_user_admin_view(username)
        if not u:
            messagebox.showerror("Error", "User not found")
            self.destroy()
            return

        self.username = tk.StringVar(value=u["username"])
        self.role = tk.StringVar(value=u["role"])
        self.active = tk.IntVar(value=int(u["is_active"]))
        self.nid = tk.StringVar(value=u["national_id"])
        created_at = u["created_at"]

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0)

        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.username, width=24).grid(row=0, column=1, sticky="w")

        ttk.Label(frm, text="Role").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Combobox(frm, textvariable=self.role, values=list(ROLES), state="readonly", width=21)\
            .grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="Active").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Checkbutton(frm, variable=self.active).grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="National ID (9 digits)").grid(row=3, column=0, sticky="w", pady=2)
        vcmd = (self.register(lambda s: (s == "" or (s.isdigit() and len(s) <= 9))), "%P")
        ttk.Entry(frm, textvariable=self.nid, validate="key", validatecommand=vcmd, width=24)\
            .grid(row=3, column=1, sticky="w")

        ttk.Label(frm, text="Created At").grid(row=4, column=0, sticky="w", pady=2)
        ttk.Label(frm, text=created_at).grid(row=4, column=1, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=2, pady=(10,0), sticky="e")
        ttk.Button(btns, text="Save", command=self.on_save).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")

        self.bind("<Return>", lambda _e: self.on_save())
        self.transient(master)
        self.grab_set()
        self.focus_set()

    def on_save(self):
        try:
            update_user_fields(
                self.old_username,
                new_username=self.username.get(),
                role=self.role.get(),
                is_active=int(self.active.get()),
                national_id=self.nid.get(),
                actor=self.actor
            )
            messagebox.showinfo("Saved", "User updated successfully.")
            if callable(self.on_saved):
                self.on_saved()
            self.destroy()
        except Exception as e:
            messagebox.showerror("Update failed", str(e))

class ManageUsersDialog(tk.Toplevel):
    def __init__(self, master, actor: str):
        super().__init__(master)
        self.title("Manage Users")
        self.resizable(False, False)
        self.actor = actor

        wrapper = ttk.Frame(self, padding=12)
        wrapper.grid(row=0, column=0, sticky="nsew")

        # --- רשימת משתמשים ---
        ttk.Label(wrapper, text="Existing users").grid(row=0, column=0, sticky="w")
        self.tree = ttk.Treeview(
            wrapper,
            columns=("username", "role", "active", "created", "hash", "salt", "nid"),
            show="headings",
            height=8,
            selectmode="browse"
        )
        self.tree.heading("username", text="Username")
        self.tree.heading("role", text="Role")
        self.tree.heading("active", text="Active")
        self.tree.heading("created", text="Created At")
        self.tree.heading("hash", text="Password Hash (PBKDF2)")
        self.tree.heading("salt", text="Salt")
        self.tree.heading("nid", text="National ID")

        self.tree.column("username", width=140, anchor="w")
        self.tree.column("role", width=90, anchor="w")
        self.tree.column("active", width=70, anchor="center")
        self.tree.column("created", width=150, anchor="w")
        self.tree.column("hash", width=360, anchor="w")
        self.tree.column("salt", width=200, anchor="w")
        self.tree.column("nid", width=120, anchor="w")

        self.tree.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(4, 6))

        # סרגל פעולות לעריכה/מחיקה/רענון
        actions = ttk.Frame(wrapper)
        actions.grid(row=2, column=0, columnspan=3, sticky="e", pady=(0, 8))
        ttk.Button(actions, text="Edit Selected…", command=self.on_edit).pack(side="left", padx=6)
        ttk.Button(actions, text="Delete Selected", command=self.on_delete).pack(side="left", padx=6)
        ttk.Button(actions, text="Refresh", command=self.reload).pack(side="left", padx=6)

        self.tree.bind("<Double-1>", lambda _e: self.on_edit())

        # --- טופס הוספה ---
        sep = ttk.Separator(wrapper, orient="horizontal")
        sep.grid(row=3, column=0, columnspan=3, sticky="ew", pady=6)

        ttk.Label(wrapper, text="Add new user").grid(row=4, column=0, sticky="w", pady=(4,0))

        ttk.Label(wrapper, text="Username").grid(row=5, column=0, sticky="w", pady=2)
        self.new_username = tk.StringVar()
        ttk.Entry(wrapper, textvariable=self.new_username, width=22).grid(row=5, column=1, sticky="w")

        ttk.Label(wrapper, text="Role").grid(row=6, column=0, sticky="w", pady=2)
        self.new_role = tk.StringVar(value="user")
        ttk.Combobox(wrapper, textvariable=self.new_role, values=list(ROLES), state="readonly", width=19)\
            .grid(row=6, column=1, sticky="w")

        ttk.Label(wrapper, text="Password").grid(row=7, column=0, sticky="w", pady=2)
        self.new_password = tk.StringVar()
        ttk.Entry(wrapper, textvariable=self.new_password, show="*", width=22).grid(row=7, column=1, sticky="w")

        ttk.Label(wrapper, text="National ID (9 digits)").grid(row=8, column=0, sticky="w", pady=2)
        self.new_nid = tk.StringVar()
        vcmd_nid = (self.register(lambda s: (s == "" or (s.isdigit() and len(s) <= 9))), "%P")
        ttk.Entry(wrapper, textvariable=self.new_nid, validate="key", validatecommand=vcmd_nid, width=22)\
            .grid(row=8, column=1, sticky="w")

        ttk.Button(wrapper, text="Add User", command=self.on_add).grid(row=9, column=1, sticky="e", pady=(8, 0))

        wrapper.columnconfigure(2, weight=1)
        self.reload()

        self.bind("<Return>", lambda _e: self.on_add())
        self.transient(master)
        self.grab_set()
        self.focus_set()

    def reload(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for username, role, is_active, created_at, pw_hash_hex, salt_hex, national_id in list_users():
            self.tree.insert(
                "",
                "end",
                values=(username, role, "Yes" if is_active else "No", created_at, pw_hash_hex, salt_hex, national_id)
            )

    def _selected_username(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Please select a user first.")
            return None
        vals = self.tree.item(sel[0], "values")
        return vals[0]  # username

    def on_edit(self):
        uname = self._selected_username()
        if not uname:
            return
        # פותחים דיאלוג עריכה
        EditUserDialog(self, uname, self.actor, on_saved_callback=self.reload)

    def on_delete(self):
        uname = self._selected_username()
        if not uname:
            return
        if messagebox.askyesno("Confirm delete", f"Delete user '{uname}'? This cannot be undone."):
            try:
                delete_user(uname, self.actor)
                messagebox.showinfo("Deleted", f"User '{uname}' deleted.")
                self.reload()
            except Exception as e:
                messagebox.showerror("Delete failed", str(e))

    def on_add(self):
        try:
            create_user(
                username=self.new_username.get(),
                role=self.new_role.get(),
                password=self.new_password.get(),
                national_id=self.new_nid.get(),
                actor=self.actor
            )
            messagebox.showinfo("User created", "User added successfully.")
            self.new_username.set("")
            self.new_password.set("")
            self.new_role.set("user")
            self.new_nid.set("")
            self.reload()
        except Exception as e:
            messagebox.showerror("Error", str(e))

class InventoryViewTab(ttk.Frame):
    """תצוגת מלאי קריאה בלבד לחוקר/סטודנט."""
    def __init__(self, parent):
        super().__init__(parent)

        ttk.Label(self, text="Inventory (read-only)", font=("TkDefaultFont", 10, "bold"))\
            .pack(anchor="w", padx=8, pady=(10, 4))

        self.tree = ttk.Treeview(self, columns=("bt", "units"), show="headings", height=10)
        self.tree.heading("bt", text="Blood Type")
        self.tree.heading("units", text="Units")
        self.tree.column("bt", width=100, anchor="center")
        self.tree.column("units", width=120, anchor="e")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="Refresh", command=self.refresh).pack(side="left")

        self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for bt in BLOOD_TYPES:
            self.tree.insert("", "end", values=(bt, get_stock(bt)))
class DonorReportTab(ttk.Frame):
    """דוח תורמים: שם, ת״ז, סוג דם, תאריך, וכמה מנות נתרמו (קיבוץ לפי תאריך+תורם)."""
    def __init__(self, parent, status_var):
        super().__init__(parent)
        self.status_var = status_var

        ttk.Label(self, text="Donations by Donor & Date",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=8, pady=(10, 4))

        cols = ("donor_name", "donor_id", "blood_type", "donation_date", "units")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        self.tree.heading("donor_name", text="Donor Name")
        self.tree.heading("donor_id", text="National ID")
        self.tree.heading("blood_type", text="Blood Type")
        self.tree.heading("donation_date", text="Date")
        self.tree.heading("units", text="Units")

        self.tree.column("donor_name", width=200, anchor="w")
        self.tree.column("donor_id", width=120, anchor="center")
        self.tree.column("blood_type", width=90, anchor="center")
        self.tree.column("donation_date", width=120, anchor="center")
        self.tree.column("units", width=80, anchor="e")

        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="Refresh", command=self.reload).pack(side="left")

        self.reload()

    def reload(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        con = db_conn()
        cur = con.cursor()
        cur.execute("""
            SELECT donor_name, donor_id, blood_type, donation_date, COUNT(*) AS units
            FROM Donations
            GROUP BY donor_name, donor_id, blood_type, donation_date
            ORDER BY date(donation_date) DESC, donor_name
        """)
        rows = cur.fetchall()
        con.close()

        for r in rows:
            self.tree.insert("", "end", values=r)

        self.status_var.set(f"Loaded {len(rows)} donation group(s).")
class IssuedByUserReportTab(ttk.Frame):
    """
    דו״ח הנפקות לפי משתמש (USER): שם משתמש, ת״ז, סוג דם, כמות, תאריך.
    נשען על audit_log (ISSUE_ROUTINE / ISSUE_MCI) וממפה actor -> Users.username כדי להביא national_id.
    """
    def __init__(self, parent, status_var):
        super().__init__(parent)
        self.status_var = status_var

        ttk.Label(self, text="Issued Units by Users",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=8, pady=(10, 4))

        cols = ("username", "national_id", "request_type", "blood_type", "units", "issue_date")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)

        self.tree.heading("username", text="User")
        self.tree.heading("national_id", text="National ID")
        self.tree.heading("request_type", text="Type")
        self.tree.heading("blood_type", text="Blood Type")
        self.tree.heading("units", text="Units")
        self.tree.heading("issue_date", text="Date")

        self.tree.column("username", width=160, anchor="w")
        self.tree.column("national_id", width=120, anchor="center")
        self.tree.column("request_type", width=90, anchor="center")
        self.tree.column("blood_type", width=90, anchor="center")
        self.tree.column("units", width=70, anchor="e")
        self.tree.column("issue_date", width=120, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="Refresh", command=self.reload).pack(side="left")

        self.reload()

    def reload(self):
        # נקה טבלה
        for i in self.tree.get_children():
            self.tree.delete(i)

        con = db_conn()
        cur = con.cursor()
        # לוקחים רק הנפקות מוצלחות ומצמידים ת״ז מה־Users
        cur.execute("""
            SELECT al.event_time_utc, al.actor, IFNULL(u.national_id,'') AS nid, al.action, al.new_values
            FROM audit_log AS al
            LEFT JOIN Users AS u ON u.username = al.actor
            WHERE al.entity = 'Issues'
              AND al.success = 1
              AND al.action IN ('ISSUE_ROUTINE','ISSUE_MCI')
            ORDER BY al.id DESC
        """)
        rows = cur.fetchall()
        con.close()

        total = 0
        for event_time_utc, actor, nid, action, new_vals in rows:
            # פריסה בטוחה של ה־JSON
            try:
                nv = json.loads(new_vals) if new_vals else {}
            except Exception:
                nv = {}

            bt    = nv.get("blood_type", "")
            units = nv.get("units", "")
            date_str = nv.get("issue_date", (event_time_utc.split(" ")[0] if event_time_utc else ""))

            req_type = "mci" if action == "ISSUE_MCI" else "routine"

            self.tree.insert("", "end", values=(actor, nid, req_type, bt, units, date_str))
            try:
                total += int(units)
            except Exception:
                pass

        self.status_var.set(f"Loaded {len(rows)} issue record(s). Total units: {total}")

# -------------------- GUI --------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.RELOGIN = False  # ברירת מחדל: לא להתאתחל מחדש
        self.title("BECS - Blood Establishment Computer Software")
        self.geometry("720x460")

        # ---- Login (חובה לפני הכל) ----
        self.current_user = None
        dlg = LoginDialog(self)
        self.wait_window(dlg)
        if not dlg.result:
            # המשתמש סגר/ביטל
            self.destroy()
            return
        self.current_user = dlg.result  # dict: {username, role, ...}

        # ---- Status bar ----
        self.status = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status, anchor="w")
        status_bar.pack(fill="x", side="bottom")

        # ---- פס עליון: מי מחובר ----
        topbar = ttk.Frame(self)
        topbar.pack(fill="x", side="top", padx=8, pady=6)
        ttk.Label(
            topbar,
            text=f"Logged in: {self.current_user['username']} ({self.current_user['role']})"
        ).pack(side="left")
        ttk.Button(topbar, text="Logout", command=self.logout).pack(side="right")

        # ---- הטאבים ----
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        role = self.current_user["role"]

        if role == "research":
            # חוקר/סטודנט: דף אחד בלבד – תצוגת מלאי (קריאה בלבד)
            self.inv_view = InventoryViewTab(nb)
            nb.add(self.inv_view, text="Inventory View")
        else:
            # עובד/אדמין
            if is_worker(self.current_user):
                self.donations_tab = DonationsTab(nb, self.status, self.get_actor)
                nb.add(self.donations_tab, text="Donations")

            self.routine_tab = RoutineIssueTab(nb, self.status, self.get_actor)
            nb.add(self.routine_tab, text="Routine Issue")

            self.mci_tab = MCITab(nb, self.status, self.get_actor)
            nb.add(self.mci_tab, text="Emergency (MCI)")

            # רק אדמין רואה Audit + Export + תפריט ניהול
            if is_admin(self.current_user):
                self.audit_tab = AuditLogTab(nb, self.status)
                nb.add(self.audit_tab, text="Audit Log")

                self.export_tab = ExportTab(
                    nb, self.status, self.get_actor,
                    role_getter=lambda: self.current_user["role"]
                )
                nb.add(self.export_tab, text="Export")
                # דו״ח הנפקות לפי משתמש (רק אדמין)
                self.issued_by_user_tab = IssuedByUserReportTab(nb, self.status)
                nb.add(self.issued_by_user_tab, text="Issued by Users")

                self.donor_report_tab = DonorReportTab(nb, self.status)
                nb.add(self.donor_report_tab, text="Donor Report")
                menubar = tk.Menu(self)
                adminmenu = tk.Menu(menubar, tearoff=0)
                adminmenu.add_command(
                    label="Manage Users…",
                    command=lambda: ManageUsersDialog(self, self.get_actor())
                )
                menubar.add_cascade(label="Admin", menu=adminmenu)
                self.config(menu=menubar)


    def get_actor(self):
        # עכשיו ה־actor הוא שם המשתמש המחובר (ולא תיבת טקסט למעלה)
        return self.current_user["username"] if self.current_user else "UNKNOWN"

    def logout(self):
        user = self.current_user["username"] if self.current_user else "UNKNOWN"
        if messagebox.askyesno("Logout", f"Log out {user}?"):
            log_event(actor=user, action="LOGOUT", entity="Users", success=True)
            # סימון שנרצה להפעיל מחדש את מסך ההתחברות
            self.RELOGIN = True
            self.destroy()


class DonationsTab(ttk.Frame):
    def __init__(self, parent, status_var, actor_getter):
        super().__init__(parent)
        self.status_var = status_var
        self.actor_getter = actor_getter


        self.bt = tk.StringVar(value=BLOOD_TYPES[0])
        self.dt = tk.StringVar(value=str(date.today()))
        self.donor_id = tk.StringVar()
        self.donor_name = tk.StringVar()

        row = 0
        ttk.Label(self, text="Blood Type").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.OptionMenu(self, self.bt, self.bt.get(), *BLOOD_TYPES).grid(row=row, column=1, sticky="ew", padx=8)

        row += 1
        ttk.Label(self, text="Donation Date (YYYY-MM-DD)").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(self, textvariable=self.dt).grid(row=row, column=1, sticky="ew", padx=8)

        vcmd_did = (self.register(self._validate_donor_id), '%P')
        row += 1
        ttk.Label(self, text="* Donor ID must be exactly 9 digits").grid(row=row, column=1, sticky="w", padx=8)
        ttk.Label(self, text="Donor ID").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(self, textvariable=self.donor_id, validate='key', validatecommand=vcmd_did).grid(row=row, column=1,
                                                                                                   sticky="ew", padx=8)

        row += 1
        ttk.Label(self, text="Donor Full Name").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(self, textvariable=self.donor_name).grid(row=row, column=1, sticky="ew", padx=8)

        row += 1
        ttk.Button(self, text="Add Unit", command=self.add_unit).grid(row=row, column=0, columnspan=2, pady=10)

        row += 1
        self.stock_tree = ttk.Treeview(self, columns=("units",), show="headings", height=8)
        self.stock_tree.heading("units", text="Units")
        self.stock_tree.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=8, pady=8)
        self.grid_rowconfigure(row, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.refresh_stock()

    def _validate_donor_id(self, proposed: str) -> bool:
        # לאפשר ריק בזמן הקלדה/מחיקה
        if proposed == "":
            return True
        # רק ספרות, ושלא יעבור 9 תווים
        return proposed.isdigit() and len(proposed) <= 9

    def refresh_stock(self):
        for i in self.stock_tree.get_children():
            self.stock_tree.delete(i)
        for bt in BLOOD_TYPES:
            self.stock_tree.insert("", "end", values=(f"{bt}: {get_stock(bt)}"))

    def add_unit(self):
        bt = self.bt.get().strip()
        dt = self.dt.get().strip()
        did = self.donor_id.get().strip()
        dname = self.donor_name.get().strip()

        actor = self.actor_getter()  # מזהה מפעיל ליומן
        if not require_operator(actor):
            return

        # דרישה: בדיוק 9 ספרות
        if not (did.isdigit() and len(did) == 9):
            messagebox.showerror("Error", "Donor ID must be exactly 9 digits.")
            log_event(actor=actor, action="DONATION_CREATE", entity="Donations",
                      success=False, note="Invalid donor_id (must be 9 digits)")
            return

        if not (bt and dt and did and dname):
            messagebox.showerror("Error", "All fields are required.")
            # רישום כישלון קלט ביומן
            log_event(actor=actor, action="DONATION_CREATE", entity="Donations",
                      success=False, note="Missing required fields")
            return

        # מלאי לפני
        before_units = get_stock(bt)

        # שמירת התרומה ולקיחת ה-ID
        con = db_conn()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO Donations(donor_id, donor_name, blood_type, donation_date) VALUES(?,?,?,?)",
            (did, dname, bt, dt)
        )
        donation_id = cur.lastrowid
        con.commit()
        con.close()

        # עדכון מלאי
        add_stock(bt, 1)
        after_units = get_stock(bt)

        # --- Audit: תרומה חדשה ---
        log_event(
            actor=actor,
            action="DONATION_CREATE",
            entity="Donations",
            record_id=donation_id,
            new_values={"donor_id": did, "donor_name": dname, "blood_type": bt, "donation_date": dt},
            success=True
        )

        # --- Audit: עדכון מלאי ---
        log_event(
            actor=actor,
            action="INVENTORY_UPDATE",
            entity="Inventory",
            record_id=bt,
            old_values={"blood_type": bt, "units": before_units},
            new_values={"blood_type": bt, "units": after_units},
            success=True
        )

        self.refresh_stock()
        self.status_var.set(f"Added 1 unit of {bt}. Stock now {after_units}.")

class RoutineIssueTab(ttk.Frame):
    def __init__(self, parent, status_var, actor_getter):
        super().__init__(parent)
        self.status_var = status_var
        self.actor_getter = actor_getter

        self.req_bt = tk.StringVar(value=BLOOD_TYPES[0])
        self.units_needed = tk.IntVar(value=1)
        self.last_checked = None  # (bt, n) מהעברתה האחרונה

        row = 0
        ttk.Label(self, text="Requested Blood Type").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.OptionMenu(self, self.req_bt, self.req_bt.get(), *BLOOD_TYPES).grid(row=row, column=1, sticky="ew", padx=8)

        row += 1
        ttk.Label(self, text="Units Needed").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.Spinbox(self, from_=1, to=999, textvariable=self.units_needed, width=8)\
            .grid(row=row, column=1, sticky="w", padx=8)

        row += 1
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=8)

        # כפתור קבוע: Check
        ttk.Button(btn_frame, text="Check", command=self.check_availability).pack(side="left", padx=6)

        # כפתורים דינמיים: אחד מהם יוצג רק אחרי בדיקה
        self.issue_btn   = ttk.Button(btn_frame, text="Issue", command=self.issue_now)
        self.suggest_btn = ttk.Button(btn_frame, text="Suggest Alternative", command=self.do_suggest_modal)
        # לא עושים pack כאן – נציג לפי תוצאת הבדיקה

        row += 1
        self.result = tk.StringVar()
        ttk.Label(self, textvariable=self.result, foreground="blue").grid(row=row, column=0, columnspan=2, sticky="w", padx=8)
        # <<< ADD: אזור לפאנלי חלופה אופציונליים (inline / quick buttons)
        row += 1
        self.alt_panel = ttk.Frame(self)
        self.alt_panel.grid(row=row, column=0, columnspan=2, sticky="ew", padx=8, pady=(4, 0))
        self.alt_panel.grid_remove()

        row += 1
        self.quick_panel = ttk.Frame(self)
        self.quick_panel.grid(row=row, column=0, columnspan=2, sticky="ew", padx=8, pady=(4, 0))
        self.quick_panel.grid_remove()

        self.grid_columnconfigure(1, weight=1)

        # שינוי קלט מאפס את המצב – מסתיר כפתורים
        self.req_bt.trace_add("write", lambda *_: self._reset_after_change())
        self.units_needed.trace_add("write", lambda *_: self._reset_after_change())
    # <<< ADD: מחשב רשימת חלופות ממוספרת וממוינת
    def _compute_candidates(self, req_bt, units_needed):
        # חלופות תואמות, ללא הסוג המבוקש עצמו
        raw = [bt for bt in donors_that_can_supply.get(req_bt, []) if bt != req_bt]

        # רק כאלה שיש מהם מלאי
        raw = [bt for bt in raw if get_stock(bt) > 0]

        # סדר עדיפות לפי שכיחות באוכלוסייה (גבוה->נמוך)
        raw.sort(key=policy_sort_key, reverse=True)

        # בונים טבלה להצגה: (סוג, מלאי, דירוג, האם מכסה את כל הכמות)
        out = []
        for rank, bt in enumerate(raw, start=1):
            stock = get_stock(bt)
            is_full = stock >= units_needed
            out.append((bt, stock, rank, is_full))
        return out

    # <<< ADD: ווריאנט מודאלי
    def do_suggest_modal(self):
        self._clear_alt_ui()
        bt = self.req_bt.get()
        n = int(self.units_needed.get() or 0)
        actor = self.actor_getter()
        if not require_operator(actor):
            return
        cands = self._compute_candidates(bt, n)
        if not cands:
            messagebox.showwarning("Suggestion", "No compatible alternative available.")
            log_event(actor=actor, action="ISSUE_SUGGEST", entity="Issues",
                      new_values={"requested_bt": bt, "requested_units": n},
                      success=False, note="No alternative")
            return
        dlg = AlternativeDialog(self, cands, n)
        self.wait_window(dlg)
        if dlg.result:
            alt_bt, alt_n = dlg.result
            self._issue_specific(alt_bt, alt_n, requested_from=bt)
        else:
            # ביטול
            pass

    # <<< ADD: איפוס רכיבי UI חלופיים (אם קיימים)
    def _clear_alt_ui(self):
        # פאנל inline
        if hasattr(self, "alt_panel") and self.alt_panel.winfo_exists():
            for w in self.alt_panel.winfo_children():
                w.destroy()
            self.alt_panel.grid_remove()
        # קומבו+כפתור
        if hasattr(self, "alt_combo") and self.alt_combo.winfo_exists():
            self.alt_combo.pack_forget()
        if hasattr(self, "alt_issue_btn") and self.alt_issue_btn.winfo_exists():
            self.alt_issue_btn.pack_forget()
        # פאנל כפתורי-בזק
        if hasattr(self, "quick_panel") and self.quick_panel.winfo_exists():
            for w in self.quick_panel.winfo_children():
                w.destroy()
            self.quick_panel.grid_remove()

    # <<< ADD: הנפקת סוג דם וכמות ספציפיים (גם לחלופין)
    def _issue_specific(self, bt, n, requested_from=None):
        actor = self.actor_getter()
        if not require_operator(actor):
            return
        try:
            n = int(n)
        except Exception:
            messagebox.showerror("Error", "Units must be a positive integer.")
            return
        if n <= 0:
            messagebox.showerror("Error", "Units must be positive.")
            return

        before_units = get_stock(bt)
        if before_units < n:
            messagebox.showerror("Insufficient", f"Only {before_units} unit(s) of {bt} in stock.")
            log_event(actor=actor, action="ISSUE_ROUTINE", entity="Issues",
                      success=False,
                      old_values={"blood_type": bt, "requested": n, "stock": before_units},
                      note=f"ALT issue failed (requested_from={requested_from or self.req_bt.get()})")
            return

        # ניפוק + רישום
        take_stock(bt, n)
        after_units = get_stock(bt)
        con = db_conn()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO Issues(request_type, blood_type, units, issue_date) VALUES('routine', ?, ?, ?)",
            (bt, n, str(date.today()))
        )
        issue_id = cur.lastrowid
        con.commit()
        con.close()

        log_event(actor=actor, action="ISSUE_ROUTINE", entity="Issues",
                  record_id=issue_id,
                  new_values={"blood_type": bt, "units": n, "issue_date": str(date.today()),
                              "requested_from": requested_from or self.req_bt.get()},
                  success=True, note="ALT or direct issue")
        log_event(actor=actor, action="INVENTORY_UPDATE", entity="Inventory",
                  record_id=bt,
                  old_values={"blood_type": bt, "units": before_units},
                  new_values={"blood_type": bt, "units": after_units},
                  success=True)

        self.result.set(f"Issued {n} unit(s) of {bt}. Remaining: {after_units}")
        self.status_var.set(self.result.get())
        self._reset_after_change()
        self._clear_alt_ui()

    # עוזרים להצגה/הסתרה
    def _show_issue(self):
        try: self.suggest_btn.pack_forget()
        except Exception: pass
        if not self.issue_btn.winfo_ismapped():
            self.issue_btn.pack(side="left", padx=6)

    def _show_suggest(self):
        try: self.issue_btn.pack_forget()
        except Exception: pass
        if not self.suggest_btn.winfo_ismapped():
            self.suggest_btn.pack(side="left", padx=6)

    def _reset_after_change(self):
        for b in (self.issue_btn, self.suggest_btn):
            try: b.pack_forget()
            except Exception: pass
        self.last_checked = None

    # שלב 1: בדיקה בלבד
    def check_availability(self):
        bt = self.req_bt.get()
        n = int(self.units_needed.get() or 0)
        actor = self.actor_getter()
        if not require_operator(actor):
            return
        if n <= 0:
            messagebox.showerror("Error", "Units must be positive.")
            log_event(actor=actor, action="ISSUE_CHECK", entity="Issues",
                      success=False, note="Units must be positive")
            return

        stock = get_stock(bt)
        if stock >= n:
            self.result.set(f"✅ Available: {n} unit(s) of {bt} (stock {stock}). Click 'Issue' to proceed.")
            self.status_var.set(self.result.get())
            self._show_issue()
            self.last_checked = (bt, n)
            log_event(actor=actor, action="ISSUE_CHECK", entity="Issues",
                      success=True, new_values={"blood_type": bt, "units": n, "stock": stock})
        else:
            self.result.set(
                f"❌ Insufficient {bt}. Requested {n}, stock {stock}. Click 'Suggest Alternative' to use the top-priority compatible type.")
            self.status_var.set(self.result.get())
            self._show_suggest()
            self.last_checked = None
            log_event(actor=actor, action="ISSUE_CHECK", entity="Issues",
                      success=False, old_values={"blood_type": bt, "requested": n, "stock": stock},
                      note="Insufficient stock")

    # שלב 2: ניפוק בפועל (רק אם הבדיקה הצליחה ולא השתנו קלטים)
    def issue_now(self):
        bt = self.req_bt.get()
        n = int(self.units_needed.get() or 0)
        actor = self.actor_getter()
        if not require_operator(actor):
            return
        if self.last_checked != (bt, n):
            messagebox.showwarning("Check first", "Inputs changed. Please run 'Check' again.")
            self._reset_after_change()
            return

        before_units = get_stock(bt)
        if before_units < n:
            messagebox.showerror("Insufficient", "Stock changed. Please check again.")
            log_event(actor=actor, action="ISSUE_ROUTINE", entity="Issues",
                      success=False, note="Stock changed before issue",
                      old_values={"blood_type": bt, "requested": n, "stock": before_units})
            self._reset_after_change()
            return

        take_stock(bt, n)
        after_units = get_stock(bt)
        con = db_conn()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO Issues(request_type, blood_type, units, issue_date) VALUES('routine', ?, ?, ?)",
            (bt, n, str(date.today()))
        )
        issue_id = cur.lastrowid
        con.commit()
        con.close()

        log_event(actor=actor, action="ISSUE_ROUTINE", entity="Issues",
                  record_id=issue_id,
                  new_values={"blood_type": bt, "units": n, "issue_date": str(date.today())},
                  success=True)
        log_event(actor=actor, action="INVENTORY_UPDATE", entity="Inventory",
                  record_id=bt,
                  old_values={"blood_type": bt, "units": before_units},
                  new_values={"blood_type": bt, "units": after_units},
                  success=True)

        self.result.set(f"Issued {n} unit(s) of {bt}. Remaining: {after_units}")
        self.status_var.set(self.result.get())
        self._reset_after_change()

    # מציג הצעה כשאין מלאי מתאים
    def do_suggest(self):
        bt = self.req_bt.get()
        n = int(self.units_needed.get() or 0)
        actor = self.actor_getter()
        if not require_operator(actor):
            return
        alt = suggest_alternative(bt, n)
        if alt:
            messagebox.showinfo("Suggestion", f"Alternative: {alt} (stock {get_stock(alt)})")
            log_event(actor=actor, action="ISSUE_SUGGEST", entity="Issues",
                      new_values={"requested_bt": bt, "requested_units": n,
                                  "suggested_bt": alt, "suggested_stock": get_stock(alt)},
                      success=True, note="Manual suggest")
        else:
            messagebox.showwarning("Suggestion", "No compatible alternative available.")
            log_event(actor=actor, action="ISSUE_SUGGEST", entity="Issues",
                      new_values={"requested_bt": bt, "requested_units": n},
                      success=False, note="Manual suggest: no alternative")

class AlternativeDialog(tk.Toplevel):
    def __init__(self, master, candidates, units_requested):
        super().__init__(master)
        self.title("Choose Alternative (Policy)")
        self.resizable(False, False)
        self.result = None  # (bt, units)

        # first/only permitted type:
        if not candidates:
            ttk.Label(self, text="No compatible alternatives in stock.").pack(padx=10, pady=10)
            ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0,10))
            self.transient(self.master); self.grab_set(); self.focus_set()
            return

        self.top_bt   = candidates[0][0]
        self.top_stock= candidates[0][1]

        ttk.Label(
            self,
            text=f"ניתן להנפיק רק מסוג העדיפות הראשונה: {self.top_bt} (מלאי {self.top_stock})"
        ).pack(anchor="w", padx=10, pady=(10, 4))

        self.tree = ttk.Treeview(self, columns=("bt","stock","rank","full"), show="headings", height=7)
        for c, w, a in (("bt",120,"center"), ("stock",70,"e"), ("rank",70,"e"), ("full",70,"center")):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor=a)
        for bt, stock, rank, is_full in candidates:
            self.tree.insert("", "end", values=(bt, stock, rank, "Full" if is_full else "Partial"))
        self.tree.pack(fill="both", expand=True, padx=10)

        # בוחרים את הראשונה כברירת מחדל
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[0])

        frm = ttk.Frame(self); frm.pack(fill="x", padx=10, pady=10)
        ttk.Label(frm, text="Units to issue").pack(side="left")
        self.n_var = tk.IntVar(value=min(units_requested, self.top_stock if self.top_stock>0 else units_requested))
        self.spin  = ttk.Spinbox(frm, from_=1, to=max(1, self.top_stock), textvariable=self.n_var, width=6)
        self.spin.pack(side="left", padx=8)

        btns = ttk.Frame(self); btns.pack(fill="x", padx=10, pady=(0,10))
        ttk.Button(btns, text="Issue",  command=self.on_issue).pack(side="right", padx=6)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")

        self.transient(self.master)
        self.grab_set()
        self.focus_set()

    def on_issue(self):
        # אוכפים הנפקה רק מהסוג הראשון
        sel = self.tree.selection()
        if not sel:
            return
        chosen_bt = self.tree.item(sel[0], "values")[0]
        if chosen_bt != self.top_bt:
            messagebox.showwarning("Policy",
                                   f"You may issue only from the top-priority type: {self.top_bt}.")
            return
        try:
            n = int(self.n_var.get())
        except Exception:
            messagebox.showerror("Error", "Units must be a positive integer.")
            return
        if n <= 0:
            messagebox.showerror("Error", "Units must be positive.")
            return
        if n > self.top_stock:
            messagebox.showerror("Error", f"Max available for {self.top_bt} is {self.top_stock}.")
            return

        self.result = (self.top_bt, n)
        self.destroy()


class MCITab(ttk.Frame):
    def __init__(self, parent, status_var, actor_getter):
        super().__init__(parent)
        self.status_var = status_var
        self.actor_getter = actor_getter


        self.label = ttk.Label(self, text=f"O- stock: {get_stock('O-')}")
        self.label.pack(pady=10)

        ttk.Button(self, text="Dispense Max O−", command=self.dispense_max).pack(pady=10)

        self.result = tk.StringVar()
        ttk.Label(self, textvariable=self.result, foreground="blue").pack(pady=6)

        self.refresh()

    def refresh(self):
        self.label.config(text=f"O- stock: {get_stock('O-')}")

    def dispense_max(self):
        actor = self.actor_getter()
        if not require_operator(actor):
            return
        current = get_stock("O-")
        if current <= 0:
            self.result.set("Error: No O− stock available.")
            self.status_var.set(self.result.get())
            log_event(
                actor=actor,
                action="ISSUE_MCI",
                entity="Issues",
                success=False,
                note="No O- stock"
            )
            return

        before_units = current
        take_stock("O-", current)
        after_units = get_stock("O-")

        con = db_conn()
        cur = con.cursor()
        cur.execute("INSERT INTO Issues(request_type, blood_type, units, issue_date) VALUES('mci', 'O-', ?, ?)",
                    (current, str(date.today())))
        issue_id = cur.lastrowid
        con.commit()
        con.close()

        # Audit: ניפוק אר"ן
        log_event(
            actor=actor,
            action="ISSUE_MCI",
            entity="Issues",
            record_id=issue_id,
            new_values={"blood_type": "O-", "units": current, "issue_date": str(date.today())},
            success=True
        )
        # Audit: עדכון מלאי
        log_event(
            actor=actor,
            action="INVENTORY_UPDATE",
            entity="Inventory",
            record_id="O-",
            old_values={"blood_type": "O-", "units": before_units},
            new_values={"blood_type": "O-", "units": after_units},
            success=True
        )

        self.refresh()
        self.result.set(f"Issued {current} unit(s) of O− for MCI.")
        self.status_var.set(self.result.get())

class AuditLogTab(ttk.Frame):
    """
    מציג את טבלת היומן (audit_log) עם פרטים.
    למעלה כפתור Refresh; באמצע טבלת רשומות; למטה חלון פרטים (old/new JSON).
    """
    def __init__(self, parent, status_var):
        super().__init__(parent)
        self.status_var = status_var

        # כפתור רענון
        btn_bar = ttk.Frame(self)
        btn_bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(btn_bar, text="Refresh", command=self.reload_data).pack(side="left")

        # טבלה
        cols = ("id", "time", "actor", "action", "entity", "record_id", "success", "note")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        for c, w in zip(cols, (60, 130, 120, 120, 120, 100, 70, 250)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=6)

        # פרטים (old/new)
        details_frame = ttk.LabelFrame(self, text="Details (old/new)")
        details_frame.pack(fill="both", expand=True, padx=8, pady=6)
        self.details_txt = ScrolledText(details_frame, height=8)
        self.details_txt.pack(fill="both", expand=True)

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        self.reload_data()

    def reload_data(self):
        # טען את 500 האחרונות (שינוי קל אם תרצי)
        for i in self.tree.get_children():
            self.tree.delete(i)
        con = db_conn()
        cur = con.cursor()
        cur.execute("""
            SELECT id, event_time_utc, actor, action, entity, IFNULL(record_id,''), success, IFNULL(note,'')
            FROM audit_log
            ORDER BY id DESC
            LIMIT 500
        """)
        rows = cur.fetchall()
        con.close()
        for r in rows:
            # מציג בכל שורה; נשמור את id בתור iid כדי שיהיה קל לאחזר פרטים
            self.tree.insert("", "end", iid=str(r[0]), values=r)

        self.status_var.set(f"Loaded {len(rows)} audit event(s).")

        # נקה חלון פרטים
        self.details_txt.delete("1.0", "end")

    def on_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        row_id = int(sel[0])
        con = db_conn()
        cur = con.cursor()
        cur.execute("""
            SELECT old_values, new_values
            FROM audit_log
            WHERE id = ?
        """, (row_id,))
        row = cur.fetchone()
        con.close()

        def pretty(x):
            if x is None:
                return ""
            try:
                return json.dumps(json.loads(x), ensure_ascii=False, indent=2)
            except Exception:
                return str(x)

        old_v = pretty(row[0]) if row else ""
        new_v = pretty(row[1]) if row else ""

        self.details_txt.delete("1.0", "end")
        self.details_txt.insert("end", "OLD VALUES:\n")
        self.details_txt.insert("end", old_v + "\n\n")
        self.details_txt.insert("end", "NEW VALUES:\n")
        self.details_txt.insert("end", new_v)
class ExportTab(ttk.Frame):
    """טאב ייצוא של כל הרשומות: XML + CSV + HTML (להדפסה ל-PDF) עם מסוך PHI ל-research."""
    def __init__(self, parent, status_var, actor_getter, role_getter):
        super().__init__(parent)
        self.status_var = status_var
        self.actor_getter = actor_getter
        self.role_getter  = role_getter  # <<< חדש

        title = ttk.Label(self, text="Export all records", font=("TkDefaultFont", 10, "bold"))
        title.pack(anchor="w", padx=8, pady=(10, 4))
        info = ttk.Label(self, text="Create portable copies of all tables (Donations, Issues, Inventory, Rarity, audit_log).")
        info.pack(anchor="w", padx=8)

        ttk.Label(self, text="XML").pack(anchor="w", padx=8, pady=(10, 0))
        ttk.Button(self, text="Export (XML)", command=self.do_export_xml).pack(anchor="w", padx=8, pady=6)

        ttk.Label(self, text="CSV (Excel)").pack(anchor="w", padx=8)
        ttk.Button(self, text="Export CSV (Excel)…",
                   command=lambda: export_all_to_csv_dir(self.actor_getter(), self.role_getter())
        ).pack(anchor="w", padx=8, pady=6)

        ttk.Label(self, text="HTML / Print to PDF").pack(anchor="w", padx=8)
        ttk.Button(self, text="Export HTML (for PDF)…",
                   command=lambda: export_all_to_html(self.actor_getter(), self.role_getter())
        ).pack(anchor="w", padx=8, pady=6)

    def do_export_xml(self):
        actor = self.actor_getter()
        role  = self.role_getter()
        if not require_operator(actor):
            return

        default_name = f"becs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        path = filedialog.asksaveasfilename(
            title="Save BECS export",
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml")],
            initialfile=default_name
        )
        if not path:
            return
        try:
            counts = export_all_to_xml(path, actor, role)
            log_event(actor=actor, action="EXPORT_XML", entity="export",
                      success=True, note=path, new_values={"counts": counts, "role": role})
            self.status_var.set(f"Exported XML to {path}")
            messagebox.showinfo(
                "Export complete",
                "Exported to:\n{}\n\nRows:\n- Donations: {}\n- Issues: {}\n- Inventory: {}\n- Rarity: {}\n- Audit: {}".format(
                    path, counts["Donations"], counts["Issues"], counts["Inventory"], counts["Rarity"], counts["audit_log"]
                )
            )
        except Exception as e:
            log_event(actor=actor, action="EXPORT_XML", entity="export",
                      success=False, note=str(e))
            messagebox.showerror("Export failed", f"Error: {e}")
            self.status_var.set("Export failed.")

# -------------------- Main --------------------
if __name__ == "__main__":
    init_db()
    while True:
        app = App()
        app.mainloop()
        # אם המשתמש לחץ Logout – נפתח שוב את App (שיאתחל דיאלוג התחברות חדש)
        if getattr(app, "RELOGIN", False):
            continue
        # אחרת – יציאה רגילה
        break


