# scanners/sqlmap_scanner.py

import subprocess

def run_sqlmap_scan(target):
    try:
        print("[SQLMAP] Checking for SQL injection...")
        result = subprocess.check_output(["sqlmap", "-u", f"http://{target}", "--batch", "--level=1"], text=True)
        return result
    except Exception as e:
        return f"[SQLMAP ERROR] {str(e)}"
