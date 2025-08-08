import subprocess
import os

def run_sslscan(target, output_file='results/sslscan.txt'):
    if not target.startswith("https://") and not target.startswith("http://"):
        target = "https://" + target

    # Extract hostname (remove https:// and trailing /)
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    try:
        result = subprocess.run(['sslscan', host], capture_output=True, text=True)
        
        with open(output_file, 'w') as f:
            f.write(result.stdout)
        
        return result.stdout

    except Exception as e:
        print(f"[ERROR] SSLScan failed: {e}")
        return None
