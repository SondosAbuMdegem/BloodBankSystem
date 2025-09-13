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

DB_PATH = "becs.db"

# -------------------- Data / Rules --------------------
BLOOD_TYPES = ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"]

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
def export_all_to_csv_dir(actor: str):
    """מייצא את כל הטבלאות לספריית CSVs ידידותית ל-Excel (קובץ לכל טבלה)."""
    if not require_operator(actor):
        return
    d = filedialog.askdirectory(title="Choose export folder")
    if not d:
        return
    base = Path(d)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = base / f"becs_export_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    con = db_conn()
    cur = con.cursor()

    tables = [
        ("Donations", "SELECT id, donor_id, donor_name, blood_type, donation_date FROM Donations"),
        ("Issues",    "SELECT id, request_type, blood_type, units, issue_date FROM Issues"),
        ("Inventory", "SELECT blood_type, units FROM Inventory"),
        ("Rarity",    "SELECT blood_type, rarity_weight FROM Rarity"),
        ("audit_log", "SELECT id, event_time_utc, actor, action, entity, record_id, old_values, new_values, source, success, note FROM audit_log"),
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
              success=True, new_values={"dir": str(outdir)})
    messagebox.showinfo("Export", f"CSV files saved to:\n{outdir}")


def export_all_to_html(actor: str):
    """מייצא דוח HTML (RTL) נוח לקריאה ואפשר להדפיסו ל-PDF מהדפדפן."""
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

    sections = [
        ("Donations", "SELECT id, donor_id, donor_name, blood_type, donation_date FROM Donations"),
        ("Issues",    "SELECT id, request_type, blood_type, units, issue_date FROM Issues"),
        ("Inventory", "SELECT blood_type, units FROM Inventory"),
        ("Rarity",    "SELECT blood_type, rarity_weight FROM Rarity"),
        ("Audit Log", "SELECT id, event_time_utc, actor, action, entity, record_id, success, note, old_values, new_values FROM audit_log ORDER BY id DESC"),
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
  @media print {{
    a#print-hint {{ display: none; }}
  }}
</style>
</head>
<body>
  <h1>BECS – Export Report</h1>
  <div class="meta">
    Generated (Local): {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
    Operator: {actor}
  </div>
  <p id="print-hint">להפקת PDF: בקשי מהדפדפן <b>Print</b> → <b>Save as PDF</b>.</p>
  {''.join(parts)}
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    log_event(actor=actor, action="EXPORT_HTML", entity="system",
              success=True, new_values={"file": path})
    messagebox.showinfo("Export", f"HTML report saved.\nOpen it in a browser and Print→Save as PDF:\n{path}")

def export_all_to_xml(file_path: str, actor: str):
    """
    מייצא את כל הטבלאות (Donations, Issues, Inventory, Rarity, audit_log) לקובץ XML אחד.
    מחזיר dict עם ספירת שורות לכל טבלה.
    """
    con = db_conn()
    cur = con.cursor()

    root = ET.Element("becs_export", {
        "generated_utc": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "actor": actor,
        "db_path": DB_PATH,
        "version": "1.0"
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

    counts = {}
    counts["Donations"] = add_table("Donations", "SELECT * FROM Donations ORDER BY id")
    counts["Issues"]    = add_table("Issues",    "SELECT * FROM Issues ORDER BY id")
    counts["Inventory"] = add_table("Inventory", "SELECT * FROM Inventory ORDER BY blood_type")
    counts["Rarity"]    = add_table("Rarity",    "SELECT * FROM Rarity ORDER BY blood_type")
    counts["audit_log"] = add_table("audit_log", "SELECT * FROM audit_log ORDER BY id")

    con.close()

    tree = ET.ElementTree(root)
    tree.write(file_path, encoding="utf-8", xml_declaration=True)

    return counts

# -------------------- Suggestion Logic --------------------
def suggest_alternative(recipient_bt, units_needed):
    candidates = donors_that_can_supply.get(recipient_bt, [])
    viable_full = [(t, get_stock(t)) for t in candidates if get_stock(t) >= units_needed]
    if viable_full:
        return min(viable_full, key=lambda x: (rarity_weight(x[0]), -x[1]))[0]
    partials = [(t, get_stock(t)) for t in candidates if get_stock(t) > 0]
    if partials:
        return min(partials, key=lambda x: (rarity_weight(x[0]), -x[1]))[0]
    return None

# -------------------- GUI --------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BECS - Blood Establishment Computer Software")
        self.geometry("720x460")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.status = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status, anchor="w")
        status_bar.pack(fill="x", side="bottom")

        # ---- Operator ID (מזהה מפעיל) למעלה ----
        self.operator_id_var = tk.StringVar(value="")
        topbar = ttk.Frame(self)
        topbar.pack(fill="x", side="top", padx=8, pady=6)
        ttk.Label(topbar, text="Operator ID:").pack(side="left")
        ttk.Entry(topbar, textvariable=self.operator_id_var, width=22).pack(side="left", padx=6)
        # -----------------------------------------

        self.donations_tab = DonationsTab(nb, self.status, self.get_actor)
        self.routine_tab = RoutineIssueTab(nb, self.status, self.get_actor)
        self.mci_tab = MCITab(nb, self.status, self.get_actor)

        nb.add(self.donations_tab, text="Donations")
        nb.add(self.routine_tab, text="Routine Issue")
        nb.add(self.mci_tab, text="Emergency (MCI)")
        self.audit_tab = AuditLogTab(nb, self.status)
        nb.add(self.audit_tab, text="Audit Log")
        self.export_tab = ExportTab(nb, self.status, self.get_actor)
        nb.add(self.export_tab, text="Export")

        # --- Menu: File → Export ---
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Export CSV (Excel)…",
                             command=lambda: export_all_to_csv_dir(self.get_actor()))
        filemenu.add_command(label="Export HTML (for PDF)…",
                             command=lambda: export_all_to_html(self.get_actor()))
        menubar.add_cascade(label="File", menu=filemenu)
        self.config(menu=menubar)
        # ---------------------------

    def get_actor(self):
        v = (self.operator_id_var.get() or "").strip()
        return v if v else "UNKNOWN"


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
        # דרישה: בדיוק 9 ספרות
        if not (did.isdigit() and len(did) == 9):
            messagebox.showerror("Error", "Donor ID must be exactly 9 digits.")
            log_event(actor=actor, action="DONATION_CREATE", entity="Donations",
                      success=False, note="Invalid donor_id (must be 9 digits)")
            return

        dname = self.donor_name.get().strip()
        actor = self.actor_getter()  # מזהה מפעיל ליומן
        if not require_operator(actor):
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

        row = 0
        ttk.Label(self, text="Requested Blood Type").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.OptionMenu(self, self.req_bt, self.req_bt.get(), *BLOOD_TYPES).grid(row=row, column=1, sticky="ew", padx=8)

        row += 1
        ttk.Label(self, text="Units Needed").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.Spinbox(self, from_=1, to=999, textvariable=self.units_needed, width=8).grid(row=row, column=1, sticky="w", padx=8)

        row += 1
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=8)
        ttk.Button(btn_frame, text="Check & Issue", command=self.check_and_issue).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Suggest Alternative", command=self.do_suggest).pack(side="left", padx=6)

        row += 1
        self.result = tk.StringVar()
        ttk.Label(self, textvariable=self.result, foreground="blue").grid(row=row, column=0, columnspan=2, sticky="w", padx=8)

        self.grid_columnconfigure(1, weight=1)

    def check_and_issue(self):
        bt = self.req_bt.get()
        n = self.units_needed.get()
        actor = self.actor_getter()
        if not require_operator(actor):
            return

        if n <= 0:
            messagebox.showerror("Error", "Units must be positive.")
            log_event(actor=actor, action="ISSUE_ROUTINE", entity="Issues",
                      success=False, note="Units must be positive")
            return

        before_units = get_stock(bt)

        if before_units >= n:
            # עודכן מלאי
            take_stock(bt, n)
            after_units = get_stock(bt)

            # יצירת רשומת Issue
            con = db_conn()
            cur = con.cursor()
            cur.execute(
                "INSERT INTO Issues(request_type, blood_type, units, issue_date) VALUES('routine', ?, ?, ?)",
                (bt, n, str(date.today()))
            )
            issue_id = cur.lastrowid
            con.commit()
            con.close()

            # Audit: ניפוק מוצלח
            log_event(
                actor=actor,
                action="ISSUE_ROUTINE",
                entity="Issues",
                record_id=issue_id,
                new_values={"blood_type": bt, "units": n, "issue_date": str(date.today())},
                success=True
            )
            # Audit: עדכון מלאי
            log_event(
                actor=actor,
                action="INVENTORY_UPDATE",
                entity="Inventory",
                record_id=bt,
                old_values={"blood_type": bt, "units": before_units},
                new_values={"blood_type": bt, "units": after_units},
                success=True
            )

            self.result.set(f"Issued {n} unit(s) of {bt}. Remaining: {after_units}")
            self.status_var.set(self.result.get())
        else:
            # אין מספיק מלאי
            log_event(
                actor=actor,
                action="ISSUE_ATTEMPT",
                entity="Issues",
                old_values={"blood_type": bt, "requested": n, "stock": before_units},
                success=False,
                note="Insufficient stock"
            )

            alt = suggest_alternative(bt, n)
            if alt:
                self.result.set(f"Insufficient {bt}. Suggested alternative: {alt} (stock {get_stock(alt)}).")
                self.status_var.set(self.result.get())
                log_event(
                    actor=actor,
                    action="ISSUE_SUGGEST",
                    entity="Issues",
                    new_values={"requested_bt": bt, "requested_units": n,
                                "suggested_bt": alt, "suggested_stock": get_stock(alt)},
                    success=True
                )
            else:
                self.result.set(f"Insufficient {bt}. No compatible alternative available.")
                self.status_var.set(self.result.get())
                log_event(
                    actor=actor,
                    action="ISSUE_SUGGEST",
                    entity="Issues",
                    new_values={"requested_bt": bt, "requested_units": n},
                    success=False,
                    note="No compatible alternative"
                )

    def do_suggest(self):
        bt = self.req_bt.get()
        n = self.units_needed.get()
        actor = self.actor_getter()
        if not require_operator(actor):
            return

        alt = suggest_alternative(bt, n)
        if alt:
            messagebox.showinfo("Suggestion", f"Alternative: {alt} (stock {get_stock(alt)})")
            log_event(
                actor=actor,
                action="ISSUE_SUGGEST",
                entity="Issues",
                new_values={"requested_bt": bt, "requested_units": n,
                            "suggested_bt": alt, "suggested_stock": get_stock(alt)},
                success=True,
                note="Manual suggest"
            )
        else:
            messagebox.showwarning("Suggestion", "No compatible alternative available.")
            log_event(
                actor=actor,
                action="ISSUE_SUGGEST",
                entity="Issues",
                new_values={"requested_bt": bt, "requested_units": n},
                success=False,
                note="Manual suggest: no alternative"
            )


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
    """טאב ייצוא של כל הרשומות: XML + CSV + HTML (להדפסה ל-PDF)."""
    def __init__(self, parent, status_var, actor_getter):
        super().__init__(parent)
        self.status_var = status_var
        self.actor_getter = actor_getter

        # כותרת והסבר
        title = ttk.Label(self, text="Export all records", font=("TkDefaultFont", 10, "bold"))
        title.pack(anchor="w", padx=8, pady=(10, 4))
        info = ttk.Label(self, text="Create portable copies of all tables (Donations, Issues, Inventory, Rarity, audit_log).")
        info.pack(anchor="w", padx=8)

        # --- XML ---
        ttk.Label(self, text="XML").pack(anchor="w", padx=8, pady=(10, 0))
        ttk.Button(self, text="Export (XML)", command=self.do_export_xml).pack(anchor="w", padx=8, pady=6)

        # --- CSV (Excel) ---
        ttk.Label(self, text="CSV (Excel)").pack(anchor="w", padx=8)
        ttk.Button(
            self,
            text="Export CSV (Excel)…",
            command=lambda: export_all_to_csv_dir(self.actor_getter())
        ).pack(anchor="w", padx=8, pady=6)

        # --- HTML (להמרה קלה ל-PDF דרך הדפדפן) ---
        ttk.Label(self, text="HTML / Print to PDF").pack(anchor="w", padx=8)
        ttk.Button(
            self,
            text="Export HTML (for PDF)…",
            command=lambda: export_all_to_html(self.actor_getter())
        ).pack(anchor="w", padx=8, pady=6)

    # השארתי את הלוגיקה של XML כפי שהייתה אצלך, רק שיניתי שם פונקציה לקריאות
    def do_export_xml(self):
        actor = self.actor_getter()
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
            counts = export_all_to_xml(path, actor)
            log_event(actor=actor, action="EXPORT_XML", entity="export",
                      success=True, note=path, new_values={"counts": counts})
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
    app = App()
    app.mainloop()

