import os
from datetime import datetime


def  save_whois_report(
    domain,
    registrar,
    creation,
    expiry,
    updated,
    name_servers,
    status,
    country,
    organization,
    emails
):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/whois_report.txt"

    with open(filename, "w", encoding="utf-8") as file:

        file.write("=" * 50 + "\n")
        file.write("Advanced Cyber Security Toolkit\n")
        file.write("WHOIS Report\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Date : {datetime.now()}\n\n")

        file.write(f"Domain       : {domain}\n")
        file.write(f"Registrar    : {registrar}\n")
        file.write(f"Creation     : {creation}\n")
        file.write(f"Expiry       : {expiry}\n")
        file.write(f"Updated      : {updated}\n")
        file.write(f"Name Servers : {name_servers}\n")
        file.write(f"Status       : {status}\n")
        file.write(f"Country      : {country}\n")
        file.write(f"Organization : {organization}\n")
        file.write(f"Emails       : {emails}\n")

    return filename