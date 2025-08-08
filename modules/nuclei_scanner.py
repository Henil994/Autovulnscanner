import subprocess
import json
import os

def run_nuclei_scan(target, output_file='results/nuclei_results.json', severity_filter=None):
    try:
        # Ensure results directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Run Nuclei with JSON output
        subprocess.run([
            'nuclei', '-u', target, '-json', '-o', output_file
        ], check=True)

        # Read and parse JSON lines output
        results = []
        with open(output_file, 'r') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())
                    if not severity_filter or data.get("info", {}).get("severity") in severity_filter:
                        results.append(data)
                except json.JSONDecodeError:
                    continue

        return results

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nuclei scan failed: {e}")
        return []
