import subprocess
import os

def run_dirsearch(target, output_file='results/dirsearch.txt'):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
        # Adjust path to dirsearch if not in PATH
        result = subprocess.run([
            'dirsearch', '-u', target, '-e', 'php,html,js,txt', '-o', output_file
        ], capture_output=True, text=True)

        # Optionally return output as string
        return result.stdout

    except Exception as e:
        print(f"[ERROR] Dirsearch failed: {e}")
        return None
