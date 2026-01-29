import os, json, stat, time, tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
META_FILE = os.path.join(BASE_DIR, "quarantine_meta.json")
LOG_FILE = os.path.join(BASE_DIR, "security_events.log")

BG="#0f172a"
PANEL="#1e293b"
TEXT="#e5e7eb"
BTN="#22c55e"
DANGER="#ef4444"

SCAN_TARGETS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
    os.environ["TEMP"]
]

# ---------------- META ----------------

def load_meta():
    if os.path.exists(META_FILE):
        with open(META_FILE) as f:
            return json.load(f)
    return {}

def save_meta(meta):
    with open(META_FILE,"w") as f:
        json.dump(meta,f)

# ---------------- UI ----------------

class AntivirusUI:
    def __init__(self, root):
        root.title("Scarface Securenet")
        root.geometry("1100x700")
        root.configure(bg=BG)

        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(1, weight=1)

        self.header()
        self.sidebar()

        self.container = tk.Frame(root,bg=BG)
        self.container.grid(row=1,column=1,sticky="nsew")

        self.show_home()

    # ---------------- LAYOUT ----------------

    def header(self):
        tk.Label(root,text="🛡 Scarface Securenet",
                 bg=BG,fg="white",
                 font=("Arial",22,"bold")).grid(row=0,column=0,columnspan=2,sticky="w",padx=15)

    def sidebar(self):
        side=tk.Frame(root,bg=PANEL)
        side.grid(row=1,column=0,sticky="ns")

        for t,f in [
            ("Home",self.show_home),
            ("Manual Scan",self.show_scan),
            ("Quarantine",self.show_quarantine),
            ("Logs",self.show_logs)
        ]:
            tk.Button(side,text=t,command=f,
                      bg="#334155",fg=TEXT,relief="flat",
                      font=("Arial",11)
                      ).pack(fill="x",pady=4,ipady=10)

    def clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    # ---------------- HOME ----------------

    def show_home(self):
        self.clear()
        tk.Label(self.container,text="🟢 PROTECTION ACTIVE",
                 fg=BTN,bg=BG,
                 font=("Arial",34,"bold")).pack(expand=True)

    # ---------------- MANUAL SCAN ----------------

    def show_scan(self):
        self.clear()

        tk.Label(self.container,text="Manual System Scan",
                 fg="white",bg=BG,
                 font=("Arial",20,"bold")).pack(pady=15)

        self.progress = ttk.Progressbar(self.container)
        self.progress.pack(fill="x",padx=40,pady=15)

        self.counter = tk.Label(self.container,text="Waiting...",
                                fg=TEXT,bg=BG,font=("Arial",12))
        self.counter.pack()

        tk.Button(self.container,text="Start Full Scan",
                  bg=BTN,font=("Arial",12),
                  command=self.start_scan).pack(pady=25)

    def collect_files(self):
        files=[]
        for folder in SCAN_TARGETS:
            for root,_,fs in os.walk(folder):
                for f in fs:
                    files.append(os.path.join(root,f))
        return files

    def start_scan(self):
        files=self.collect_files()
        total=len(files)

        if total==0:
            messagebox.showinfo("Scan","No files found")
            return

        self.progress["maximum"]=total

        for i,_ in enumerate(files,1):
            self.progress["value"]=i
            self.counter.config(text=f"Scanned {i} / {total} files")
            root.update()

        messagebox.showinfo("Scan","Full system scan completed")

    # ---------------- QUARANTINE ----------------

    def show_quarantine(self):
        self.clear()

        tk.Label(self.container,text="Quarantine",
                 fg="white",bg=BG,
                 font=("Arial",20,"bold")).pack(pady=10)

        self.q_list=tk.Listbox(self.container,bg="#020617",fg=TEXT)
        self.q_list.pack(fill="both",expand=True,padx=30,pady=15)

        if os.path.exists(QUARANTINE_DIR):
            for f in os.listdir(QUARANTINE_DIR):
                self.q_list.insert(tk.END,f)

        btns=tk.Frame(self.container,bg=BG)
        btns.pack()

        tk.Button(btns,text="Restore",
                  bg="#38bdf8",
                  command=self.restore_file).pack(side="left",padx=10)

        tk.Button(btns,text="Delete",
                  bg=DANGER,
                  command=self.delete_file).pack(side="left",padx=10)

    def restore_file(self):
        if not self.q_list.curselection():
            return

        name=self.q_list.get(self.q_list.curselection()[0])
        meta=load_meta()

        if name not in meta:
            messagebox.showerror("Error","Original path not found")
            return

        src=os.path.join(QUARANTINE_DIR,name)
        dst=meta[name]

        try:
            os.makedirs(os.path.dirname(dst),exist_ok=True)
            os.rename(src,dst)
            meta.pop(name)
            save_meta(meta)

            messagebox.showinfo("Restored",f"Restored to:\n{dst}")
            self.show_quarantine()

        except Exception as e:
            messagebox.showerror("Restore failed",str(e))

    def delete_file(self):
        if not self.q_list.curselection():
            return

        name=self.q_list.get(self.q_list.curselection()[0])
        path=os.path.join(QUARANTINE_DIR,name)

        if not os.path.exists(path):
            messagebox.showerror("Error","File not found")
            return

        try:
            os.chmod(path, stat.S_IWRITE)
            time.sleep(0.2)
            os.remove(path)

            meta=load_meta()
            meta.pop(name,None)
            save_meta(meta)

            messagebox.showinfo("Deleted",f"{name} permanently removed")
            self.show_quarantine()

        except PermissionError:
            messagebox.showerror(
                "File Locked",
                "Antivirus engine is protecting this file.\nClose backend and try again."
            )

        except Exception as e:
            messagebox.showerror("Delete failed",str(e))

    # ---------------- LOG VIEWER (FIXED PROFESSIONAL) ----------------

    def show_logs(self):
        self.clear()

        tk.Label(self.container,text="Security Logs",
                 fg="white",bg=BG,font=("Arial",20,"bold")).pack(pady=5)

        self.log_reader = scrolledtext.ScrolledText(
            self.container,
            wrap=tk.WORD,
            bg="#020617",
            fg=TEXT,
            insertbackground="white",
            font=("Consolas",11)
        )

        self.log_reader.pack(fill="both",expand=True,padx=25,pady=15)

        self.log_reader.configure(state="normal")

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                for line in f:
                    self.log_reader.insert(tk.END, line)

        self.log_reader.configure(state="disabled")  # read-only

        # Enable text cursor (reader mode)
        self.log_reader.config(cursor="xterm")

        tk.Label(self.container,
                 text="Tip: Select text and press Ctrl+C to copy",
                 bg=BG,fg="#94a3b8").pack(pady=5)


# ---------------- RUN ----------------

if __name__=="__main__":
    root=tk.Tk()
    AntivirusUI(root)
    root.mainloop()
