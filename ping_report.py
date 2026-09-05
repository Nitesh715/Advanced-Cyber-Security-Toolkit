import os
from datetime import datetime


def save_ping_report(
    target,
    status,
    response_time
):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/ping_report.txt"

    with open(filename, "w", encoding="utf-8") as file:

        file.write("=" * 50 + "\n")
        file.write("Advanced Cyber Security Toolkit\n")
        file.write("PING REPORT\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Date          : {datetime.now()}\n")
        file.write(f"Target        : {target}\n")
        file.write(f"Status        : {status}\n")
        file.write(f"Response Time : {response_time}\n")

    return filename