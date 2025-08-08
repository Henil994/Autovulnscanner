import shodan
import yaml

def load_api_key():
    with open("config.yaml", "r") as file:
        config = yaml.safe_load(file)
        return config.get("shodan_api_key")

def shodan_lookup(ip):
    api_key = load_api_key()
    if not api_key:
        print("[!] Missing Shodan API key in config.yaml")
        return None

    api = shodan.Shodan(api_key)

    try:
        host = api.host(ip)
        return {
            "ip": ip,
            "ports": host.get("ports", []),
            "org": host.get("org"),
            "os": host.get("os"),
            "hostnames": host.get("hostnames"),
            "vulns": host.get("vulns", []),
            "tags": host.get("tags", [])
        }

    except shodan.APIError as e:
        print(f"[Shodan Error] {e}")
        return None
