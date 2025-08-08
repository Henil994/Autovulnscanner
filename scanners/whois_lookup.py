# scanners/whois_lookup.py

import subprocess

def run_whois_lookup(target):
    try:
        print("[WHOIS] Fetching domain information...")
        result = subprocess.check_output(["whois", target], text=True)
        return result
    except Exception as e:
        return f"[WHOIS ERROR] {str(e)}"
