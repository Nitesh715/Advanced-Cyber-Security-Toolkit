import os
from datetime import datetime


def save_security_report(target, results):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/security_headers_report.txt"

    with open(filename, "w", encoding="utf-8") as file:

        file.write("=" * 60 + "\n")
        file.write("Advanced Cyber Security Toolkit\n")
        file.write("SECURITY HEADERS REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Date   : {datetime.now()}\n")
        file.write(f"Target : {target}\n\n")

        for header, value in results.items():

            if value == "Missing":
                status = "MISSING"
            else:
                status = "FOUND"

            file.write(f"[{status}] {header}\n")
            file.write(f"Value : {value}\n\n")

    return filename