import csv
import hashlib
import os
import datetime


def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def get_baseline_path(file_path):
    directory = os.path.dirname(os.path.abspath(file_path))
    filename = os.path.basename(file_path)
    return os.path.join(directory, filename + ".integrity")


def save_baseline(file_path):
    file_path = os.path.abspath(file_path)
    file_hash = calculate_file_hash(file_path)
    baseline_path = get_baseline_path(file_path)

    with open(baseline_path, "w", encoding="utf-8") as baseline:
        baseline.write(file_hash)

    return f"Baseline saved for {file_path}"


def get_baseline_hash(file_path):
    file_path = os.path.abspath(file_path)
    baseline_path = get_baseline_path(file_path)

    with open(baseline_path, "r", encoding="utf-8") as baseline:
        return baseline.read().strip()


def check_integrity(file_path):
    file_path = os.path.abspath(file_path)

    if not os.path.isfile(file_path):
        return "ERROR - File not found."

    current_hash = calculate_file_hash(file_path)
    baseline_path = get_baseline_path(file_path)

    if not os.path.exists(baseline_path):
        return "ERROR - Baseline not found. Create a baseline first."

    with open(baseline_path, "r", encoding="utf-8") as baseline:
        baseline_hash = baseline.read().strip()

    print("CURRENT HASH :", current_hash)
    print("BASELINE HASH:", baseline_hash)

    if not baseline_hash:
        return "ERROR - Baseline is empty. Create a new baseline."

    if current_hash == baseline_hash:
        return "File integrity ok - File is unchanged"
    else:
        return "WARNING - File has been modified"


def save_integrity_report(file_path, current_hash, baseline_hash, result):
    file_path = os.path.abspath(file_path)
    report_folder = os.path.abspath("integrity_reports")
    os.makedirs(report_folder, exist_ok=True)

    filename = os.path.basename(file_path)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    report_file = os.path.join(
        report_folder,
        filename + "_integrity_report_" + timestamp + ".txt"
    )

    status = "SAFE" if "unchanged" in result.lower() else "WARNING"

    with open(report_file, "w", encoding="utf-8") as report:
        report.write("========== FILE INTEGRITY REPORT ==========\n\n")
        report.write(f"Date/Time        : {datetime.datetime.now()}\n")
        report.write(f"File             : {file_path}\n\n")
        report.write(f"Current SHA-256  : {current_hash}\n")
        report.write(f"Baseline SHA-256 : {baseline_hash}\n\n")
        report.write(f"Result           : {result}\n")
        report.write(f"Status           : {status}\n")

    return report_file

def save_integrity_history(file_path, result):
    file_path = os.path.abspath(file_path)

    history_folder = os.path.abspath("integrity_reports")
    os.makedirs(history_folder, exist_ok=True)

    history_file = os.path.join(
        history_folder,
        "integrity_history.csv"
    )

    status = "SAFE" if "unchanged" in result.lower() else "WARNING"

    file_exists = os.path.exists(history_file)

    with open(
        history_file,
        "a",
        newline="",
        encoding="utf-8"
    ) as history:

        writer = csv.writer(history)

        if not file_exists:
            writer.writerow([
                "Date/Time",
                "File",
                "Result",
                "Status"
            ])

        writer.writerow([
            datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            file_path,
            result,
            status
        ])

    return history_file

def get_integrity_history(file_path):
    file_path = os.path.abspath(file_path)
    history_file = os.path.abspath(
        "integrity_reports/integrity_history.csv"
    )

    if not os.path.exists(history_file):
        return []

    history = []

    with open(
        history_file,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            if os.path.abspath(row.get("File", "")) == file_path:
                history.append(row)

    return history

def clear_integrity_history():
    history_file = os.path.abspath(
        "integrity_reports/integrity_history.csv"
    )

    if os.path.exists(history_file):
        os.remove(history_file)
        return True

    return False

if __name__ == "__main__":
    try:
        print(check_integrity(os.path.abspath("text.txt")))
    except FileNotFoundError:
        print("Baseline not found. Create a baseline first.")
