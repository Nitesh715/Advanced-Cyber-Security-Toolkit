import csv
import os


def save_security_csv(target, results):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/security_headers_report.csv"

    file_exists = os.path.isfile(filename)

    with open(
        filename,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not file_exists:

            writer.writerow([
                "Target",
                "Header",
                "Status",
                "Value"
            ])

        for header, value in results.items():

            if value == "Missing":
                status = "MISSING"
            else:
                status = "FOUND"

            writer.writerow([
                target,
                header,
                status,
                value
            ])

    return filename