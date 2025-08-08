import subprocess
import xml.etree.ElementTree as ET
from modules.logger import setup_logger

logger = setup_logger(__name__)

def run_nmap_scan(target):
    logger.info(f"Starting Nmap scan on {target} ...")
    try:
        # Run nmap with XML output for parsing
        result = subprocess.run(
            ["nmap", "-sV", "--script", "vuln", "-oX", "-", target],
            capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap scan failed: {e}")
        return None

def parse_nmap_xml(xml_data):
    vulns = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                port_id = port.attrib.get("portid")
                state = port.find("state").attrib.get("state")
                service = port.find("service").attrib.get("name")
                for script in port.findall("script"):
                    if script.attrib.get("id") == "vulners" or script.attrib.get("id").startswith("vuln"):
                        output = script.attrib.get("output")
                        vulns.append({
                            "port": port_id,
                            "service": service,
                            "state": state,
                            "details": output
                        })
        logger.info(f"Found {len(vulns)} vulnerabilities in Nmap scan.")
    except Exception as e:
        logger.error(f"Failed parsing Nmap XML: {e}")
    return vulns
