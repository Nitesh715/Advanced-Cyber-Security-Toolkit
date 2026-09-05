import csv
import os


def save_whois_csv(
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

    filename = "reports/whois_report.csv"

    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        # Header
        if not file_exists:
            writer.writerow([
                "Domain",
                "Registrar",
                "Creation",
                "Expiry",
                "Updated",
                "Name Servers",
                "Status",
                "Country",
                "Organization",
                "Emails"
            ])

        # Data
        writer.writerow([
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
        ])

    return filename