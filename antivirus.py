import os, sys, time, psutil, hashlib, shutil, json, ctypes, random

# ================= AUTO ADMIN =================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None,"runas",sys.executable," ".join(sys.argv),None,1
    )
    sys.exit()

# ================= CONFIG =================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCAN_INTERVAL = 5

QUARANTINE_DIR = os.path.join(BASE_DIR,"quarantine")
META_FILE = os.path.join(BASE_DIR,"quarantine_meta.json")
BLOCKLIST_FILE = os.path.join(BASE_DIR,"blocked_hashes.txt")
SIEM_FILE = os.path.join(BASE_DIR,"siem_events.json")
LOG_FILE = os.path.join(BASE_DIR,"security_events.log")

SYSTEM_IGNORE={"registry","memcompression","system","idle"}
SECURITY_SOFTWARE={"msmpeng.exe","mpdefendercoreservice.exe"}
TRUSTED={"python.exe","pythonw.exe","py.exe"}

DANGEROUS_ZONES=[
    os.environ["TEMP"].lower(),
    os.environ["USERPROFILE"].lower(),
    "c:\\users"
]

# ================= META =================

def load_meta():
    if os.path.exists(META_FILE):
        with open(META_FILE) as f:
            return json.load(f)
    return {}

META = load_meta()

def save_meta():
    with open(META_FILE,"w") as f:
        json.dump(META,f)

# ================= UTILS =================

def log(m):
    print(m)
    with open(LOG_FILE,"a",encoding="utf-8") as f:
        f.write(f"[{time.ctime()}] {m}\n")

def file_hash(p):
    try:
        h=hashlib.sha256()
        with open(p,"rb") as f:
            for c in iter(lambda:f.read(8192),b""):
                h.update(c)
        return h.hexdigest()
    except:
        return None

def risky(p):
    p=p.lower()
    return any(p.startswith(x) for x in DANGEROUS_ZONES)

# ================= BLOCKED =================

def load_blocked():
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE) as f:
            return set(x.strip() for x in f if x.strip())
    return set()

BLOCKED_HASHES=load_blocked()

def save_blocked(h):
    with open(BLOCKLIST_FILE,"a") as f:
        f.write(h+"\n")

# ================= SIEM =================

def siem(event,data):
    with open(SIEM_FILE,"a") as f:
        f.write(json.dumps({
            "time":time.time(),
            "event":event,
            "details":data
        })+"\n")

# ================= QUARANTINE (FIXED) =================

def quarantine(path):
    try:
        if not os.path.exists(path):
            return

        os.makedirs(QUARANTINE_DIR,exist_ok=True)

        name=os.path.basename(path)
        dest=os.path.join(QUARANTINE_DIR,name)

        shutil.copy2(path,dest)
        os.remove(path)

        META[name]=path   # 🔥 ORIGINAL LOCATION SAVED
        save_meta()

        h=file_hash(dest)
        if h and h not in BLOCKED_HASHES:
            BLOCKED_HASHES.add(h)
            save_blocked(h)

        log(f"[QUARANTINED] {path}")
        siem("quarantine",path)

    except Exception as e:
        log(f"[QUARANTINE ERROR] {e}")

# ================= RESTORE (REAL) =================

def restore_file(name):
    if name not in META:
        return

    src=os.path.join(QUARANTINE_DIR,name)
    dst=META[name]

    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst),exist_ok=True)
        shutil.move(src,dst)

        META.pop(name)
        save_meta()

        log(f"[RESTORED] {dst}")
        siem("restore",dst)

# ================= PROCESS KILL =================

def kill(proc):
    try:
        proc.terminate()
        time.sleep(0.5)
        if proc.is_running():
            proc.kill()
    except:
        pass

# ================= CORE ENGINE =================

def scan():
    for proc in psutil.process_iter(['pid','exe','name']):
        try:
            exe=proc.info['exe']
            name=(proc.info['name'] or "").lower()

            if not exe:
                continue

            if name in SYSTEM_IGNORE:
                continue

            if name in SECURITY_SOFTWARE or name in TRUSTED:
                continue

            h=file_hash(exe)

            if h in BLOCKED_HASHES:
                quarantine(exe)
                kill(proc)
                continue

            if risky(exe):
                quarantine(exe)
                kill(proc)

        except:
            pass

# ================= MAIN =================

def monitor():
    log("=== EndpointGuard REAL ANTIVIRUS MODE ===")

    while True:
        scan()
        time.sleep(SCAN_INTERVAL+random.randint(0,2))

if __name__=="__main__":
    monitor()
if __name__ == "__main__":
    monitor()
    input("Press Enter to exit...")
