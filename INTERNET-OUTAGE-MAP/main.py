import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import sqlite3
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib

DB_FILE = "outage_reports.db"

# Encryption helpers
def generate_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_data(data: bytes, password: str) -> bytes:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_data(token: bytes, password: str) -> bytes:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(token)

# Database helpers
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter TEXT,
            status TEXT,
            location TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_report(reporter, status, location):
    timestamp = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO reports (reporter, status, location, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (reporter, status, location, timestamp))
    conn.commit()
    conn.close()

def get_all_reports():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT reporter, status, location, timestamp FROM reports ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def export_reports_encrypted(filename, password):
    rows = get_all_reports()
    data = [dict(reporter=r[0], status=r[1], location=r[2], timestamp=r[3]) for r in rows]
    json_data = json.dumps(data, indent=2).encode('utf-8')
    encrypted = encrypt_data(json_data, password)
    with open(filename, 'wb') as f:
        f.write(encrypted)

def import_reports_encrypted(filename, password):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"{filename} does not exist.")
    with open(filename, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_data(encrypted_data, password)
    data = json.loads(decrypted_data.decode('utf-8'))

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    added_count = 0
    for report in data:
        c.execute('SELECT COUNT(*) FROM reports WHERE reporter=? AND timestamp=?',
                  (report['reporter'], report['timestamp']))
        if c.fetchone()[0] == 0:
            c.execute('INSERT INTO reports (reporter, status, location, timestamp) VALUES (?, ?, ?, ?)',
                      (report['reporter'], report['status'], report['location'], report['timestamp']))
            added_count += 1
    conn.commit()
    conn.close()
    return added_count

# GUI app
class OutageReporterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Offline Internet Outage Reporter")
        self.geometry("700x500")

        # Input fields
        frame = tk.Frame(self)
        frame.pack(pady=10)

        tk.Label(frame, text="Reporter Name/ID:").grid(row=0, column=0, sticky="e")
        self.reporter_entry = tk.Entry(frame, width=25)
        self.reporter_entry.grid(row=0, column=1, padx=5)

        tk.Label(frame, text="Internet Status (up/down):").grid(row=1, column=0, sticky="e")
        self.status_entry = tk.Entry(frame, width=25)
        self.status_entry.grid(row=1, column=1, padx=5)

        tk.Label(frame, text="Location (city/region):").grid(row=2, column=0, sticky="e")
        self.location_entry = tk.Entry(frame, width=25)
        self.location_entry.grid(row=2, column=1, padx=5)

        add_btn = tk.Button(frame, text="Add Report", command=self.add_report)
        add_btn.grid(row=3, column=0, columnspan=2, pady=5)

        # Buttons for import/export
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        export_btn = tk.Button(btn_frame, text="Export Reports (Encrypted)", command=self.export_reports)
        export_btn.grid(row=0, column=0, padx=5)

        import_btn = tk.Button(btn_frame, text="Import Reports (Encrypted)", command=self.import_reports)
        import_btn.grid(row=0, column=1, padx=5)

        show_btn = tk.Button(btn_frame, text="Show All Reports", command=self.show_reports)
        show_btn.grid(row=0, column=2, padx=5)

        # Text box to show reports
        self.report_box = scrolledtext.ScrolledText(self, width=80, height=20)
        self.report_box.pack(padx=10, pady=10)

        init_db()

    def add_report(self):
        reporter = self.reporter_entry.get().strip()
        status = self.status_entry.get().strip().lower()
        location = self.location_entry.get().strip()

        if not reporter or not status or not location:
            messagebox.showwarning("Input error", "Please fill all fields.")
            return
        if status not in ['up', 'down']:
            messagebox.showwarning("Input error", "Status must be 'up' or 'down'.")
            return

        add_report(reporter, status, location)
        messagebox.showinfo("Success", "Report added.")
        self.reporter_entry.delete(0, tk.END)
        self.status_entry.delete(0, tk.END)
        self.location_entry.delete(0, tk.END)

    def export_reports(self):
        filename = filedialog.asksaveasfilename(defaultextension=".bin",
                                                filetypes=[("Encrypted files", "*.bin"), ("All files", "*.*")])
        if not filename:
            return
        password = simpledialog.askstring("Password", "Enter password to encrypt export:", show='*')
        if not password:
            messagebox.showwarning("Cancelled", "Export cancelled (no password).")
            return

        try:
            export_reports_encrypted(filename, password)
            messagebox.showinfo("Exported", f"Reports exported and encrypted to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def import_reports(self):
        filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.bin"), ("All files", "*.*")])
        if not filename:
            return
        password = simpledialog.askstring("Password", "Enter password to decrypt import:", show='*')
        if not password:
            messagebox.showwarning("Cancelled", "Import cancelled (no password).")
            return

        try:
            count = import_reports_encrypted(filename, password)
            messagebox.showinfo("Imported", f"Imported {count} new reports from file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import: {e}")

    def show_reports(self):
        rows = get_all_reports()
        self.report_box.delete('1.0', tk.END)
        if not rows:
            self.report_box.insert(tk.END, "No reports found.\n")
            return

        header = f"{'Reporter':<15} | {'Status':<6} | {'Location':<15} | {'Timestamp (UTC)'}\n"
        self.report_box.insert(tk.END, header)
        self.report_box.insert(tk.END, "-"*70 + "\n")
        for r in rows:
            line = f"{r[0]:<15} | {r[1]:<6} | {r[2]:<15} | {r[3]}\n"
            self.report_box.insert(tk.END, line)

if __name__ == "__main__":
    app = OutageReporterApp()
    app.mainloop()
