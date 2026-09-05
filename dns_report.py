import os
from datetime import datetime

def save_dns_report(domain, hostname, ip, reverse_dns ):
    os.makedirs("reports", exist_ok=True)
    filename = "reports/dns_reports.txt"

    with open(filename, "w") as file:

        file.write("=" * 50 + "\n")
        file.write("Advanced Cyber Security Toolkit\n")
        file.write("DNS Lookup Report\n")
        file.write("=" * 50 + "\n\n")
        file.write(f"Data : {datetime.now()}\n\n")
        file.write(f"Domain   : {domain}\n")
        file.write(f"Hostname : {hostname}\n")
        file.write(f"IPv4 Address  : {ip}\n")
        file.write(f"Reverse DNS : {reverse_dns}\n")

        return filename