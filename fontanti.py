import os
import json
import time
import hashlib
import tkinter as tk
from tkinter import ttk
import shutil
import threading

# ================= PATHS =================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SIEM_FILE = os.path.join(BASE_DIR, "siem_events.json")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocked_hashes.txt")

SCAN_PATHS = [
    os.path.expandvars(r"%USERPROFILE%"),
    os.path.expandvars(r"%TEMP%"),
]

SUSPICIOUS_EXT = (".exe", ".dll", ".ps1", ".bat", ".vbs")

# ================= UTILS =================

def load_blocked_hashes():
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def load_siem_events(limit=50):
    events = []
    if os.path.exists(SIEM_FILE):
        with open(SIEM_FILE, "r", encoding="utf-8") as f:
            for line in f.readlines()[-limit:]:
                try:
                    events.append(json.loads(line))
                except:
                    pass
    return events

def list_quarantine():
    if not os.path.exists(QUARANTINE_DIR):
        return []
    return os.listdir(QUARANTINE_DIR)

# ================= GUI APP =================

class EndpointGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Endpoint Guard – Security Dashboard")
        self.geometry("900x550")
        self.resizable(False, False)

        self.blocked_hashes = load_blocked_hashes()

        self.create_widgets()
        self.refresh_all()

    # ---------- UI ----------

    def create_widgets(self):
        header = tk.Label(
            self,
            text="Endpoint Guard – EDR Dashboard",
            font=("Segoe UI", 16, "bold")
        )
        header.pack(pady=10)

        self.status_label = tk.Label(
            self,
            text="Status: 🟢 Backend Running",
            font=("Segoe UI", 11),
            fg="green"
        )
        self.status_label.pack(pady=5)

        tabs = ttk.Notebook(self)
        tabs.pack(expand=True, fill="both", padx=10, pady=10)

        # ---- Events ----
        self.events_frame = ttk.Frame(tabs)
        tabs.add(self.events_frame, text="Security Events")

        self.events_box = tk.Text(
            self.events_frame,
            height=15,
            state="disabled",
            font=("Consolas", 10)
        )
        self.events_box.pack(expand=True, fill="both", padx=5, pady=5)

        # ---- Quarantine ----
        self.quarantine_frame = ttk.Frame(tabs)
        tabs.add(self.quarantine_frame, text="Quarantine")

        self.quarantine_list = tk.Listbox(
            self.quarantine_frame,
            font=("Consolas", 10)
        )
        self.quarantine_list.pack(expand=True, fill="both", padx=5, pady=5)

        # ---- Manual Scan ----
        self.scan_frame = ttk.Frame(tabs)
        tabs.add(self.scan_frame, text="Manual Scan")

        self.scan_output = tk.Text(
            self.scan_frame,
            height=15,
            state="disabled",
            font=("Consolas", 10)
        )
        self.scan_output.pack(expand=True, fill="both", padx=5, pady=5)

        # ---- Buttons ----
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame, text="🔍 Manual Scan",
            width=18, command=self.start_manual_scan
        ).pack(side="left", padx=10)

        tk.Button(
            btn_frame, text="🔄 Refresh",
            width=15, command=self.refresh_all
        ).pack(side="left", padx=10)

        tk.Button(
            btn_frame, text="❌ Exit",
            width=15, command=self.destroy
        ).pack(side="left", padx=10)

    # ---------- Thread-safe UI log ----------

    def ui_log(self, text):
        self.scan_output.after(
            0, lambda: self.scan_output.insert(tk.END, text)
        )

    # ---------- Refresh ----------

    def refresh_all(self):
        self.refresh_events()
        self.refresh_quarantine()

    def refresh_events(self):
        events = load_siem_events()
        self.events_box.config(state="normal")
        self.events_box.delete("1.0", tk.END)

        if not events:
            self.events_box.insert(tk.END, "No security events recorded.\n")
        else:
            for e in events:
                ts = e.get("timestamp") or time.time()
                etype = e.get("event_type") or "unknown"
                self.events_box.insert(
                    tk.END,
                    f"[{time.ctime(ts)}] {etype} → {e.get('details')}\n"
                )

        self.events_box.config(state="disabled")

    def refresh_quarantine(self):
        self.quarantine_list.delete(0, tk.END)
        files = list_quarantine()
        if not files:
            self.quarantine_list.insert(tk.END, "No quarantined files.")
        else:
            for f in files:
                self.quarantine_list.insert(tk.END, f)

    # ---------- Manual Scan Thread ----------

    def start_manual_scan(self):
        t = threading.Thread(target=self.manual_scan, daemon=True)
        t.start()

    def manual_scan(self):
        self.scan_output.after(0, lambda: self.scan_output.config(state="normal"))
        self.scan_output.after(0, lambda: self.scan_output.delete("1.0", tk.END))
        self.ui_log("🔍 Manual scan started...\n\n")

        scanned = 0
        removed = 0

        for base in SCAN_PATHS:
            if not os.path.exists(base):
                continue

            for root, _, files in os.walk(base):
                for name in files:
                    if not name.lower().endswith(SUSPICIOUS_EXT):
                        continue

                    path = os.path.join(root, name)
                    scanned += 1

                    try:
                        h = file_hash(path)
                        if h and h in self.blocked_hashes:
                            os.makedirs(QUARANTINE_DIR, exist_ok=True)
                            shutil.move(path, os.path.join(QUARANTINE_DIR, name))
                            self.ui_log(f"❌ Removed: {path}\n")
                            removed += 1
                    except:
                        continue

        if removed == 0:
            self.ui_log(
                f"\n✅ Scan complete\nFiles scanned: {scanned}\nNo threats found.\n"
            )
        else:
            self.ui_log(
                f"\n🧪 Scan complete\nFiles scanned: {scanned}\nThreats removed: {removed}\n"
            )

        self.scan_output.after(0, lambda: self.scan_output.config(state="disabled"))
        self.refresh_quarantine()

# ================= RUN =================

if __name__ == "__main__":
    app = EndpointGuardApp()
    app.mainloop()
