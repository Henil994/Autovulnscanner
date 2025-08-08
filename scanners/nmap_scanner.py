# scanners/nmap_scanner.py

import subprocess

def run_nmap_scan(target):
    try:
        print("[NMAP] Running scan...")
        result = subprocess.check_output(["nmap", "-sV", target], text=True)
        return result
    except Exception as e:
        return f"[NMAP ERROR] {str(e)}"
