import os
from datetime import datetime


def save_report(target, ip, open_ports):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/scan_report.txt"

    with open(filename, "w") as file:

        file.write("=" * 50 + "\n")
        file.write("Advanced Cyber Security Toolkit\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Target : {target}\n")
        file.write(f"IP Address : {ip}\n")
        file.write(f"Date : {datetime.now()}\n\n")

        file.write("Open Ports\n")
        file.write("-" * 30 + "\n")

        if open_ports:

            for port in open_ports:
                file.write(f"{port}\n")

        else:
            file.write("No Open Ports Found\n")

    return filename