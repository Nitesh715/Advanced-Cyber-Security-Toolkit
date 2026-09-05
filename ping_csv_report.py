import csv
import os


def save_ping_csv(
    target,
    status,
    response_time
):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/ping_report.csv"

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
                "Status",
                "Response Time"
            ])

        writer.writerow([
            target,
            status,
            response_time
        ])

    return filename