# scanners/nikto_scanner.py

import subprocess

def run_nikto_scan(target):
    try:
        print("[NIKTO] Scanning...")
        result = subprocess.check_output(["nikto", "-h", target], text=True)
        return result
    except Exception as e:
        return f"[NIKTO ERROR] {str(e)}"
