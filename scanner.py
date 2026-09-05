from concurrent.futures import ThreadPoolExecutor
import socket
import time

from colorama import Fore, init
from services import SERVICES
from report import save_report
from banner import grab_banner

init(autoreset=True)


# ----------------------------
# Scan One Port
# ----------------------------
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)

        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            return port

    except Exception:
        pass

    return None


# ----------------------------
# Main Scanner
# ----------------------------
def start(target, start_port, end_port, callback, progress_callback):

    # Validate Port Range
    if start_port < 1 or end_port > 65535:
        callback("❌ Port must be between 1 and 65535\n")
        return

    if start_port > end_port:
        callback("❌ Start Port cannot be greater than End Port\n")
        return

    # Resolve IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        callback("❌ Invalid Website or IP Address\n")
        return

    callback("=" * 50 + "\n")
    callback("Advanced Cyber Security Toolkit\n")
    callback("=" * 50 + "\n")
    callback(f"Target : {target}\n")
    callback(f"IP     : {ip}\n\n")

    start_time = time.time()

    open_ports = []
    futures = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_port, ip, port))

        total_ports = end_port - start_port + 1
        completed = 0
        for future in futures:
            result = future.result()
            completed += 1
            percentage = int((completed / total_ports) * 100)
            progress_callback(percentage)
            if result is not None:
                open_ports.append(result)

    end_time = time.time()

    callback("\n========== OPEN PORTS ==========\n")

    if open_ports:

        for port in open_ports:

            service = SERVICES.get(port, "Unknown Service")
            banner = grab_banner(ip, port)
            callback(f"[OPEN] Port {port} --> {service}\n")
            callback(f"Banner : {banner}\n\n")

    else:

        callback("No Open Ports Found.\n")

    callback("\n========== SUMMARY ==========\n")

    callback(f"Total Open Ports : {len(open_ports)}\n")
    callback(
        f"Scan Time        : {round(end_time-start_time,2)} Seconds\n"
    )

    save_report(target, ip, open_ports)

    callback("\n✅ Report Saved Successfully.\n")