import os
import time
import psutil
import hashlib
import shutil
import random
import json
import ctypes

# ================= BASIC CONFIG =================

APP_NAME = "EndpointGuard"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCAN_INTERVAL = 10  # testing ke liye fast, baad mein 60 kar sakte ho

QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocked_hashes.txt")
SIEM_FILE = os.path.join(BASE_DIR, "siem_events.json")
LOG_FILE = os.path.join(BASE_DIR, "security_events.log")

SYSTEM_PATHS = [
    "c:\\windows",
    "c:\\program files",
    "c:\\program files (x86)"
]

USER_PATHS = [
    os.path.expandvars(r"%USERPROFILE%").lower(),
    os.path.expandvars(r"%TEMP%").lower()
]

# ✅ TRUST MODEL (FALSE POSITIVE FIX)
TRUSTED_EXECUTABLES = [
    "python.exe",
    "pythonw.exe"
]

# ================= UTILS =================

def log(msg):
    print(msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{time.ctime()}] {msg}\n")

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except:
        return None

def is_system_path(path):
    path = path.lower()
    return any(path.startswith(p) for p in SYSTEM_PATHS)

def is_user_path(path):
    path = path.lower()
    return any(path.startswith(p) for p in USER_PATHS)

# ================= BLOCKED HASHES =================

def load_blocked():
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_blocked(h):
    with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
        f.write(h + "\n")

BLOCKED_HASHES = load_blocked()

# ================= SIEM =================

def siem_event(event_type, details):
    record = {
        "time": time.time(),
        "event": event_type,
        "details": details
    }
    with open(SIEM_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

# ================= QUARANTINE =================

def quarantine(path):
    try:
        if not os.path.exists(path):
            return

        h = file_hash(path)
        if h and h not in BLOCKED_HASHES:
            BLOCKED_HASHES.add(h)
            save_blocked(h)

        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        shutil.move(path, os.path.join(QUARANTINE_DIR, os.path.basename(path)))

        log(f"[QUARANTINE] {path}")
        siem_event("quarantine", {"file": path})

    except Exception as e:
        log(f"[ERROR] Quarantine failed: {e}")

# ================= PROCESS SCAN =================

def scan_processes():
    for proc in psutil.process_iter(['pid', 'exe', 'name']):
        try:
            exe = proc.info['exe']
            name = proc.info['name']

            if not exe:
                continue

            exe_l = exe.lower()
            exe_name = os.path.basename(exe_l)

            # ✅ Ignore trusted executables (false positive fix)
            if exe_name in TRUSTED_EXECUTABLES:
                continue

            # Block already known bad hash
            h = file_hash(exe)
            if h in BLOCKED_HASHES:
                proc.kill()
                quarantine(exe)
                continue

            # User-folder execution heuristic
            if is_user_path(exe_l) and not is_system_path(exe_l):
                log(f"[SUSPICIOUS EXEC] {exe}")
                proc.kill()
                quarantine(exe)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            log(f"[ERROR] Scan issue: {e}")

# ================= MAIN LOOP =================

def monitor():
    log("=== EndpointGuard Backend STARTED (DEBUG MODE) ===")
    try:
        admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        admin = 0

    log(f"Running as admin: {admin}")

    while True:
        try:
            scan_processes()
            time.sleep(SCAN_INTERVAL + random.randint(0, 3))
        except Exception as e:
            log(f"[CRASH RECOVERED] {e}")

# ================= ENTRY =================

if __name__ == "__main__":
    print(">>> FILE LOADED <<<")
    input(">>> PRESS ENTER TO START ENGINE <<<")
    monitor()
