import subprocess
import socket
from urllib.parse import urlparse
from modules.results_manager import save_result, logging

def run(target_url):
    target = urlparse(target_url).netloc
    results = {"open_ports": []}

    try:
        subprocess.run(["nmap", "-sS", "-Pn", "-T4", "-p-", target], check=True)
    except Exception as e:
        logging.error(f"Nmap error: {e}")

    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080, 8443]
    for port in common_ports:
        try:
            with socket.create_connection((target, port), timeout=1):
                results["open_ports"].append(port)
        except Exception as e:
            logging.error(f"Port check error: {port} - {e}")

    save_result("recon", results)
