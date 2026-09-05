import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import scanner
import dns_lookup
import whois_lookup
import ping_scanner
from ping_report import save_ping_report
from ping_csv_report import save_ping_csv
from security_report import save_security_report
from security_csv_report import save_security_csv
import http_checker
import csv
import os 
from datetime import datetime
scan_history = []
from password_hash import check_password_strength, generate_hash, verify_hash

import file_integrity
import packet_sniffer
import packet_sniffer
import vulnerability_scanner
import threading
import webbrowser
import log_analyzer
import ids
last_log_findings = []
last_ids_alerts = []
import database


def browse_integrity_file():
    file_path = filedialog.askopenfilename()

    if file_path:
        integrity_file_entry.delete(0, tk.END)
        integrity_file_entry.insert(0, file_path)


def create_integrity_baseline():
    file_path = integrity_file_entry.get().strip()

    if not file_path:
        messagebox.showerror("File Error", "Please select a file first.")
        return

    if not os.path.isfile(file_path):
        messagebox.showerror("File Error", "Selected file does not exist.")
        return

    try:
        result = file_integrity.save_baseline(file_path)
        baseline_path = file_integrity.get_baseline_path(file_path)

        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, "========== FILE INTEGRITY BASELINE ==========\n\n")
        result_box.insert(tk.END, f"File : {file_path}\n\n")
        result_box.insert(tk.END, f"Baseline : {baseline_path}\n\n")
        result_box.insert(tk.END, f"Result : {result}\n")
        result_box.see(tk.END)
        update_status("Baseline Created")

    except Exception as e:
        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, f"ERROR : {e}\n")
        update_status("Baseline Creation Failed")


def check_file_integrity():
    file_path = integrity_file_entry.get().strip()

    if not file_path:
        messagebox.showerror("File Error", "Please select a file first.")
        return

    if not os.path.isfile(file_path):
        messagebox.showerror("File Error", "Selected file does not exist.")
        return

    baseline_path = file_integrity.get_baseline_path(file_path)

    if not os.path.isfile(baseline_path):
        messagebox.showerror(
            "Integrity Error",
            "Baseline not found. Please create a baseline first."
        )
        update_status("Baseline Not Found")
        return

    try:
        current_hash = file_integrity.calculate_file_hash(file_path)
        baseline_hash = file_integrity.get_baseline_hash(file_path)
        print("========== INTEGRITY DEBUG ==========")
        print("FILE PATH     :", os.path.abspath(file_path))
        print("BASELINE PATH :", file_integrity.get_baseline_path(file_path))
        print("CURRENT HASH  :", current_hash)
        print("BASELINE HASH :", baseline_hash)
        print("HASH MATCH    :", current_hash == baseline_hash)
        print("====================================")

        if current_hash == baseline_hash:
            result = "File integrity ok - File is unchanged"
        else:
            result = "WARNING - File has been modified"

        report_file = file_integrity.save_integrity_report(
            file_path, current_hash, baseline_hash, result
        )
        history_file = file_integrity.save_integrity_history(
    file_path,
    result
)

        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, "========== FILE INTEGRITY CHECK ==========\n\n")
        result_box.insert(tk.END, f"File : {file_path}\n\n")
        result_box.insert(tk.END, f"Current SHA-256 : {current_hash}\n\n")
        result_box.insert(tk.END, f"Baseline SHA-256 : {baseline_hash}\n\n")
        result_box.insert(tk.END, f"Result : {result}\n\n")
        result_box.insert(tk.END, f"Report Saved : {report_file}\n")
        result_box.see(tk.END)
        update_status("Integrity Check Completed")

    except FileNotFoundError:
        messagebox.showerror(
            "Integrity Error",
            "Baseline not found. Please create a baseline first."
        )
        update_status("Baseline Not Found")

    except Exception as e:
        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, f"Integrity Error : {e}\n")
        update_status("Integrity Check Failed")


def open_integrity_report():
    file_path = integrity_file_entry.get().strip()

    if not file_path:
        messagebox.showerror("Report Error", "Please select a file first.")
        return

    report_folder = os.path.abspath("integrity_reports")

    if not os.path.isdir(report_folder):
        messagebox.showerror(
            "Report Error",
            "No integrity report found. Please run Check Integrity first."
        )
        return

    prefix = os.path.basename(file_path) + "_integrity_report_"
    reports = [
        name for name in os.listdir(report_folder)
        if name.startswith(prefix) and name.endswith(".txt")
    ]

    if not reports:
        messagebox.showerror(
            "Report Error",
            "No integrity report found. Please run Check Integrity first."
        )
        return

    latest_report = max(
        reports,
        key=lambda name: os.path.getmtime(os.path.join(report_folder, name))
    )

    os.startfile(os.path.join(report_folder, latest_report))


def open_integrity_reports_folder():
    report_folder = os.path.abspath("integrity_reports")
    os.makedirs(report_folder, exist_ok=True)
    os.startfile(report_folder)


def clear_integrity_file():
    integrity_file_entry.delete(0, tk.END)
    result_box.delete("1.0", tk.END)
    update_status("File Integrity Cleared")

def show_integrity_history():
    history_file = os.path.abspath(
        "integrity_reports/integrity_history.csv"
    )

    if not os.path.exists(history_file):
        messagebox.showinfo(
            "Integrity History",
            "No integrity history available yet."
        )
        return

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "=========== INTEGRITY CHECK HISTORY ==========\n\n"
    )

    try:
        with open(
            history_file,
            "r",
            newline="",
            encoding="utf-8"
        ) as history:

            reader =csv.DictReader(history)

            for row in reader:
                result_box.insert(
                    tk.END,
                    f"Date/Time : {row.get('Date/Time','')}\n"
                )

                result_box.insert(
                    tk.END,
                    f"File     : {row.get('File','')}\n"
                )
                result_box.insert(
                    tk.END,
                    f"Result      : {row.get('Result','')}\n"
                )

                result_box.insert(
                    tk.END,
                    f"Status     :   {row.get('Status','')}\n"
                )
                result_box.insert(
                    tk.END,
                    "_" * 50 + "\n"
                )

            update_status("Integrity History Loaded")

    except Exception as e:
        result_box.insert(
            tk.END,
            f"History Error : {e}\n"
        )

        update_status("History Load Failed")

def clear_integrity_history():
    history_file = os.path.abspath(
        "integrity_reports/integrity_history.csv"
    )

    if not os.path.exists(history_file):
        messagebox.showinfo(
            "Integrity History",
            "No integrity history available."
        )
        return

    confirm = messagebox.askyesno(
        "Clear History",
        "Are you sure you want to clear integrity history?"
    )

    if not confirm:
        return

    try:
        os.remove(history_file)

        result_box.delete("1.0", tk.END)

        result_box.insert(
            tk.END,
            "Integrity history cleared successfully.\n"
        )

        update_status("Integrity History Cleared")

    except Exception as e:
        messagebox.showerror(
            "History Error",
            f"Could not clear history.\n\n{e}"
        )


# -----------------------
# Show Result
# -----------------------
def show_result(text):
    result_box.insert(tk.END, text)
    result_box.see(tk.END)


def update_progress(value):
    progress["value"] = value
    window.update()

def save_packet_capture_report():
    import os
    from datetime import datetime

    capture_text = result_box.get("1.0", tk.END).strip()

    if not capture_text:
        messagebox.showinfo(
            "No Capture",
            "Please capture packets first."
        )
        return

    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(
        reports_dir,
        f"packet_capture_{timestamp}.txt"
    )

    report_content = (
        "==============================================\n"
        "           PACKET CAPTURE REPORT\n"
        "==============================================\n\n"
        f"Capture Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"{capture_text}\n\n"
        "==============================================\n"
        "              END OF REPORT\n"
        "==============================================\n"
    )

    with open(report_file, "w", encoding="utf-8") as file:
        file.write(report_content)

    update_status("Packet Capture Report Saved")

    messagebox.showinfo(
        "Report Saved",
        f"Packet capture report saved successfully:\n{report_file}"
    )

def save_ids_report():
    if not last_log_findings and not last_ids_alerts:
        messagebox.showinfo(
            "No IDS Data",
            "Please run Log Analyzer + IDS first."
        )
        return
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(
        reports_dir,
        f"ids_report_{timestamp}.txt"
    )
    with open(report_file, "w", encoding="utf-8") as file:
        file.write("========== LOG ANALYZER REPORT ==========\n\n")

        for finding in last_log_findings:
            file.write(finding + "\n")

        file.write("\n========== IDS ALERTS ==========\n\n")

        for alert in last_ids_alerts:
            file.write(alert + "\n")

def show_database_history():
    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "========== DATABASE HISTORY ==========\n\n"
    )

    findings = database.get_findings()
    alerts = database.get_alerts()
    result_box.insert(
        tk.END,
        "========== SAVED FINDINGS ==========\n\n"
    )

    for record in findings:
        result_box.insert(
            tk.END,
            f"ID : {record[0]}\n"
            f"Finding : {record[1]}\n"
            f"Time : {record[2]}\n\n"
        )

    result_box.insert(
        tk.END,
        "\n========== SAVED IDS ALERTS ==========\n\n"
    )

    for record in alerts:
        result_box.insert(
            tk.END,
            f"ID : {record[0]}\n"
            f"Alert : {record[1]}\n"
            f"Time : {record[2]}\n\n"
        )


def run_log_analyzer():
    log_file = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "test.log"
)

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "========== LOG ANALYZER + BASIC IDS ==========\n\n"
    )

    update_status("Log Analysis Running...")

    try:
        findings = log_analyzer.analyze_log(log_file)
        global last_log_findings
        last_log_findings = findings

        result_box.insert(
            tk.END,
            "========== LOG FINDINGS ==========\n"
        )

        if findings:
            for finding in findings:
                result_box.insert(
                    tk.END,
                    finding + "\n"
                )
                database.save_finding(finding)

        else:
            result_box.insert(
                tk.END,
                "No suspicious events detected.\n"
            )

        alerts = ids.detect_intrusions(findings)
        global last_ids_alerts
        last_ids_alerts = alerts

        result_box.insert(
            tk.END,
            "\n========== IDS ALERTS ==========\n"
        )

        if alerts:
            for alert in alerts:
                result_box.insert(
                    tk.END,
                    alert + "\n"
                )
                database.save_alert(alert)
        else:
            result_box.insert(
                tk.END,
                "No IDS alerts generated.\n"
            )

        result_box.see(tk.END)
        update_status("Log Analysis Completed")

    except Exception as e:
        result_box.insert(
            tk.END,
            f"\nLog Analyzer Error : {e}\n"
        )
        update_status("Log Analysis Failed")

def run_packet_sniffer():
    """Capture basic IPv4 packet metadata on the local authorized lab machine."""
    try:
        packet_count = int(packet_count_entry.get().strip())
        if not 1 <= packet_count <= 50:
            raise ValueError
    except ValueError:
        messagebox.showerror(
            "Packet Count Error",
            "Enter a packet count between 1 and 50."
        )
        update_status("Invalid Packet Count")
        return

    result_box.delete("1.0", tk.END)
    result_box.insert(
        tk.END,
        "Use only on your own computer or an authorized lab network.\n\n"
    )
    update_status("Packet Capture Running...")
    progress["value"] = 0
    progress_label.config(text="Progress : 0%")
    window.update_idletasks()

    try:
        # The current packet_sniffer module prints the capture output.
        # Capture that output and display it in the existing result area.
        import io
        from contextlib import redirect_stdout

        output = io.StringIO()
        with redirect_stdout(output):
            packet_sniffer.packet_sniffer(packet_count)

        captured_text = output.getvalue()
        result_box.insert(tk.END, captured_text)
        result_box.see(tk.END)
        progress["value"] = 100
        progress_label.config(text="Progress : 100%")

        if "ERROR:" in captured_text or "ERROR :" in captured_text:
            update_status("Packet Capture Failed")
        else:
            update_status("Packet Capture Completed")

    except PermissionError:
        result_box.insert(
            tk.END,
            "\nERROR: Administrator privileges are required.\n"
            "Run app.py as Administrator and try again.\n"
        )
        update_status("Administrator Permission Required")
    except Exception as e:
        result_box.insert(tk.END, f"\nPacket Sniffer Error : {e}\n")
        update_status("Packet Capture Failed")


# -----------------------------
# Password & Hash Tools
# -----------------------------

def password_strength_check():
    password = password_entry.get()

    if not password:
        messagebox.showerror("Password Error", "Please enter a password.")
        return

    strength, suggestions = check_password_strength(password)

    result_box.delete("1.0", tk.END)

    result_box.insert(tk.END, "========== PASSWORD STRENGTH ==========\n\n")
    result_box.insert(tk.END, f"Strength : {strength}\n\n")

    if suggestions:
        result_box.insert(tk.END, "Suggestions:\n")
        for suggestion in suggestions:
            result_box.insert(tk.END, f"- {suggestion}\n")
    else:
        result_box.insert(tk.END, "Password meets all basic requirements.\n")


def create_hash():
    text = hash_text_entry.get()

    if not text:
        messagebox.showerror("Hash Error", "Please enter text.")
        return

    algorithm = hash_algorithm.get()

    hash_value = generate_hash(text, algorithm)

    result_box.delete("1.0", tk.END)

    result_box.insert(tk.END, "========== HASH RESULT ==========\n\n")
    result_box.insert(tk.END, f"Algorithm : {algorithm.upper()}\n")
    result_box.insert(tk.END, f"Text      : {text}\n\n")
    result_box.insert(tk.END, f"Hash      : {hash_value}\n")


def check_hash():
    text = hash_text_entry.get()
    expected_hash = expected_hash_entry.get()

    if not text or not expected_hash:
        messagebox.showerror(
            "Verification Error",
            "Please enter text and hash."
        )
        return

    algorithm = hash_algorithm.get()

    result = verify_hash(
        text,
        expected_hash,
        algorithm
    )

    result_box.delete("1.0", tk.END)

    result_box.insert(tk.END, "========== HASH VERIFICATION ==========\n\n")
    result_box.insert(tk.END, f"Algorithm : {algorithm.upper()}\n")

    if result:
        result_box.insert(tk.END, "\nResult : MATCH ✓\n")
    else:
        result_box.insert(tk.END, "\nResult : NOT MATCHED ✗\n")
        
# -----------------------
# Start Scan
# -----------------------
def start_scan():

    update_status("Scanning...")

    result_box.delete(1.0, tk.END)

    progress["value"] = 0
    status_label.config(text="Status : Scanning...")
    window.update()

    # Get target
    target = target_entry.get().strip()

    # Target validation
    if target == "":
        messagebox.showerror(
            "Invalid Target",
            "Please enter a website or IP address."
        )
        update_status("Invalid Target")
        return

    # Port validation
    try:
        start_port = int(start_entry.get().strip())
        end_port = int(end_entry.get().strip())

        if not (1 <= start_port <= 65535):
            raise ValueError

        if not (1 <= end_port <= 65535):
            raise ValueError

        if start_port > end_port:
            messagebox.showerror(
                "Invalid Port Range",
                "Start Port must be less than or equal to End Port."
            )
            update_status("Invalid Port Range")
            return

    except ValueError:
        messagebox.showerror(
            "Invalid Port",
            "Please enter valid ports between 1 and 65535."
        )
        update_status("Invalid Port")
        return

    # Clean target URL
    if "://" in target:
        target = target.split("://", 1)[1]

    target = target.split("/", 1)[0]

    if target == "":
        messagebox.showerror(
            "Invalid Target",
            "Please enter a valid domain or IP address."
        )
        update_status("Invalid Target")
        return

    # Clear previous results
    result_box.delete("1.0", tk.END)

    progress["value"] = 0

    update_status("Scanning...")

    try:
        scanner.start(
            target,
            start_port,
            end_port,
            show_result,
            update_progress
        )

        progress["value"] = 100
        update_status("Scan Completed")
        add_history("Port Scan", target)

    except Exception as e:

        result_box.insert(
            tk.END,
            f"❌ Error : {e}\n"
        )

        update_status("Scan Failed")

def update_status(message):
    status_label.config(
        text=f"Status  : {message}"
    )
    window.update_idletasks()

def open_latest_vulnerability_report():
    reports_dir = "reports"

    if not os.path.exists(reports_dir):
        messagebox.showerror(
            "Report Not Found",
            "Reports folder does not exist yet."
        )
        return

    reports = [
        os.path.join(reports_dir, file)
        for file in os.listdir(reports_dir)
        if file.startswith("vulnerability_report_")
        and file.endswith(".txt")
    ]

    if not reports:
        messagebox.showinfo(
            "No Report",
            "No vulnerability report has been generated yet."
        )
        return

    latest_report = max(
        reports,
        key=os.path.getmtime
    )

    try:
        os.startfile(os.path.abspath(latest_report))
        update_status("Latest Vulnerability Report Opened")
    except Exception as e:
        messagebox.showerror(
            "Report Error",
            f"Could not open report:\n{e}"
        )

def start_vulnerability_scan():
    target = target_entry.get().strip()

    if not target:
        messagebox.showerror(
            "Invalid Target",
            "Please enter a website or IP address."
        )
        return

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        f"Starting vulnerability scan for {target}...\n\n"
    )

    update_status("Vulnerability Scanning...")

    threading.Thread(
        target=run_vulnerability_scan,
        args=(target,),
        daemon=True
    ).start()


def run_vulnerability_scan(target):
    try:
        findings, open_ports = vulnerability_scanner.vulnerability_scan(target)

        def display_results():
            result_box.insert(
                tk.END,
                "\nOPEN PORTS\n" + "-" * 50 + "\n"
            )

            for port in sorted(set(open_ports)):
                result_box.insert(
                    tk.END,
                    f"Port {port}\n"
                )

            result_box.insert(
                tk.END,
                "\nFINDINGS\n" + "-" * 50 + "\n"
            )

            for item in findings:
                result_box.insert(
                    tk.END,
                    f"[{item['severity']}] "
                    f"Port {item['port']} "
                    f"({item['service']})\n"
                )

                result_box.insert(
                    tk.END,
                    f"  {item['finding']}\n"
                )

            result_box.insert(
                tk.END,
                "\nScan completed.\n"
            )

            add_history("Vulnerability Scan", target)

            report_file = save_vulnerability_report(
                target,
                findings,
                open_ports
            )

            result_box.insert(
                tk.END,
                f"\nReport saved: {report_file}\n"
            )

            update_status("Vulnerability Scan Completed")

        window.after(0, display_results)

    except Exception as e:

        window.after(
            0,
            lambda: result_box.insert(
                tk.END,
                f"\n❌ Vulnerability Scan Error: {e}\n"
            )
        )

        window.after(
            0,
            lambda: update_status("Vulnerability Scan Failed")
        )
# -----------------------
# DNS Lookup
# -----------------------

def dns_scan():

    update_status("DNS Lookup...")

    result_box.delete("1.0", tk.END)

    domain = target_entry.get().strip()

    if domain == "":
        messagebox.showerror(
            "Error",
            "Please enter a domain."
        )
        update_status("Invalid Target")
        return

    try:
        dns_lookup.dns_lookup(
            domain,
            show_result
        )

        update_status("DNS Lookup Completed")

        add_history(
            "DNS Lookup",
            domain
        )

    except Exception as e:

        result_box.insert(
            tk.END,
            f"❌ DNS Error : {e}\n"
        )

        update_status("DNS Lookup Failed")

def whois_scan():
    update_status("WHOIS Lookup...")
    result_box.delete("1.0", tk.END)

    domain = target_entry.get().strip()

    if domain == "":
        messagebox.showerror(
            "Error",
            "Please enter a domain."
        )
        update_status("Invalid Target")
        return
    try:
        whois_lookup.whois_lookup(
            domain,
            show_result
        )
        update_status("WHOIS Lookup Completed")
        add_history(
            "WHOIS Lookup",
            domain
        )

    except Exception as e:
        result_box.insert(
            tk.END,
            f"❌ WHOIS Error : {e}\n"
        )

        update_status("WHOIS Lookup Failed")
  
def ping_scan():

    update_status("Scanning...")

    target = target_entry.get().strip()

    if target == "":
        messagebox.showerror(
            "Error",
            "Please enter a website or IP address."
        )
        return

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "========== PING SCANNER ==========\n\n"
    )

    try:

        status, response_time, ip_address, output = \
            ping_scanner.ping_host(target)

        if status:
            status_text = "ONLINE"
        else:
            status_text = "OFFLINE"

        result_box.insert(
            tk.END,
            f"Target        : {target}\n"
        )

        result_box.insert(
            tk.END,
            f"IP Address    : {ip_address}\n"
        )

        result_box.insert(
            tk.END,
            f"Status        : {status_text}\n"
        )

        result_box.insert(
            tk.END,
            f"Response Time : {response_time}\n\n"
        )

        # Save TXT Report
        save_ping_report(
            target,
            status_text,
            response_time
        )

        # Save CSV Report
        save_ping_csv(
            target,
            status_text,
            response_time
        )

        result_box.insert(
            tk.END,
            "✅ TXT Report Saved Successfully.\n"
        )

        result_box.insert(
            tk.END,
            "✅ CSV Report Saved Successfully.\n"
        )

    except Exception as e:

        result_box.insert(
            tk.END,
            f"❌ Error : {e}\n"
        )
        update_status("Operation Failed")

def http_check():

    update_status("HTTP Check...")

    result_box.delete("1.0", tk.END)

    target = target_entry.get().strip()

    if target == "":
        messagebox.showerror(
            "Error",
            "Please enter a website URL."
        )
        update_status("Invalid Target")
        return
    
    try:
        result = http_checker.check_url(target)

        if "error" in result:
            result_box.insert(
                tk.END,
                f"❌ HTTP Error : {result['error']}\n"
            )
            update_status("HTTP Check Failed")
            return

        result_box.insert(
            tk.END,
            "========== HTTP CHECK ==========\n\n"
        )

        result_box.insert(
            tk.END,
            f"URL           : {result['url']}\n"
        )

        result_box.insert(
            tk.END,
            f"Status Code   : {result['status_code']}\n"
        )

        result_box.insert(
            tk.END,
            f"Final URL     : {result['final_url']}\n"
        )

        result_box.insert(
            tk.END,
            f"Response Time : {result['response_time']} ms\n"
        )

        result_box.insert(
            tk.END,
            f"Server        : {result['server']}\n"
        )

        result_box.insert(
            tk.END,
            f"Content Type  : {result['content_type']}\n"
        )

        update_status("HTTP Check Completed")

        add_history(
            "HTTP Check",
            target
        )

    except Exception as e:

        result_box.insert(
            tk.END,
            f"❌ HTTP Error : {e}\n"
        )

        update_status("HTTP Check Failed")
        update_status("HTTP Check Failed")
    
def security_headers_check():
    update_status("Security Headers Completed")

    
    result_box.insert(
    tk.END,
    "\n================================\n"
    "Security Headers Scan Completed\n"
    "Report saved successfully.\n"
    "================================\n"
)

    update_status("Scan & Report Completed")

    target = target_entry.get().strip()

    if target == "":
        messagebox.showerror(
            "Error",
            "Please enter a website URL."
        )
        return

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "===== SECURITY HEADERS CHECK =====\n\n"
    )

    try:

        results = http_checker.check_security_headers(target)

        if not isinstance(results, dict):
            result_box.insert(
                tk.END,
                "❌ Error : Invalid response from security header checker.\n", "error"
            )
            update_status("Security Check Failed")
            return

        if "error" in results:

            result_box.insert(
                tk.END,
                f"❌ Error : {results['error']}\n","error"
            )

            return

        for header, value in results.items():

            if value == "Missing":

                result_box.insert(
                    tk.END,
                    f"[MISSING] {header}\n",
                    "missing"
                )

                result_box.insert(
                    tk.END,
                    "   → Security header not found\n\n",
                    "missing"
                )

            else:

                result_box.insert(
                    tk.END,
                    f"[FOUND] {header}\n",
                    "found"
                )

                result_box.insert(
                    tk.END,
                    f"   → {value}\n\n",
                    "found"
                )

        # Save TXT report
        txt_file = save_security_report(
            target,
            results
        )

        # Save CSV report
        csv_file = save_security_csv(
            target,
            results
        )

        result_box.insert(
            tk.END,
            "\n" + "=" * 40 + "\n"
        )

        result_box.insert(
            tk.END,
            "✅ TXT Report Saved\n"
        )

        result_box.insert(
            tk.END,
            "✅ CSV Report Saved\n"
        )

        result_box.insert(
            tk.END,
            f"\nTXT : {txt_file}\n","Found"
        )

        result_box.insert(
            tk.END,
            f"CSV : {csv_file}\n","Found"
        )

        update_status("Security Check Completed")

    except Exception as e:

        result_box.insert(
            tk.END,
            f"❌ Error : {e}\n"
        )
        update_status("Operation Failed")

def save_vulnerability_report(target, findings, open_ports):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = (
        f"reports/vulnerability_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    with open(filename, "w", encoding="utf-8") as report:

        report.write("========================================\n")
        report.write("       VULNERABILITY SCAN REPORT\n")
        report.write("========================================\n\n")

        report.write(f"Target    : {target}\n")
        report.write(f"Scan Time : {timestamp}\n\n")

        # Open Ports
        report.write("OPEN PORTS\n")
        report.write("-" * 40 + "\n")

        unique_ports = sorted(set(open_ports))

        if unique_ports:
            for port in unique_ports:
                report.write(f"Port: {port}\n")
        else:
            report.write("No open ports detected.\n")

        # Findings
        report.write("\nFINDINGS\n")
        report.write("-" * 40 + "\n")

        if findings:
            for item in findings:
                report.write(
                    f"[{item['severity']}] "
                    f"Port {item['port']} "
                    f"({item['service']})\n"
                )

                report.write(
                    f"Finding: {item['finding']}\n\n"
                )
        else:
            report.write("No vulnerabilities detected.\n")

        # Summary
        report.write("SUMMARY\n")
        report.write("-" * 40 + "\n")
        report.write(
            f"Total Open Ports : {len(unique_ports)}\n"
        )
        report.write(
            f"Total Findings   : {len(findings)}\n"
        )

        report.write("\n========================================\n")
        report.write("           END OF REPORT\n")
        report.write("========================================\n")

    return filename

# -----------------------
# History
# -----------------------

scan_history = []


def save_history(tool, target):
    os.makedirs("reports", exist_ok=True)

    filename = os.path.join("reports", "scan_history.csv")
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(["Date", "Tool", "Target"])

        writer.writerow([
            datetime.now().isoformat(sep=" ", timespec="seconds"),
            tool,
            target
        ])


def add_history(tool, target):
    scan_history.append({
        "Date": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "Tool": tool,
        "Target": target
    })

    save_history(tool, target)


def load_history():
    filename = os.path.join("reports", "scan_history.csv")

    if not os.path.isfile(filename):
        return []

    history = []

    try:
        with open(filename, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                if row.get("Tool") or row.get("Target"):
                    history.append(row)

    except (OSError, csv.Error):
        return []

    return history


def show_history():
    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "========== SCAN HISTORY ==========\n\n"
    )

    history = load_history()

    if not history:
        result_box.insert(
            tk.END,
            "No scan history available.\n"
        )
        status_label.config(text="Status : No History")
        return

    for row in history:
        result_box.insert(
            tk.END,
            f"Date   : {row.get('Date', 'Not Available')}\n"
        )
        result_box.insert(
            tk.END,
            f"Tool   : {row.get('Tool', 'Not Available')}\n"
        )
        result_box.insert(
            tk.END,
            f"Target : {row.get('Target', 'Not Available')}\n"
        )
        result_box.insert(
            tk.END,
            "-" * 40 + "\n"
        )

    status_label.config(text="Status : History Loaded")


def export_history():
    history = load_history()

    if not history:
        messagebox.showinfo(
            "History",
            "No scan history available."
        )
        return

    os.makedirs("reports", exist_ok=True)

    filename = "reports/scan_history.txt"

    with open(filename, "w", encoding="utf-8") as file:
        file.write("========== SCAN HISTORY ==========\n\n")

        for row in history:
            file.write(
                f"Date   : {row.get('date', '')}\n"
                f"Tool   : {row.get('tool', '')}\n"
                f"Target : {row.get('target', '')}\n"
                + "-" * 40 + "\n"
            )

    messagebox.showinfo(
        "Export",
        f"History exported successfully.\n\n{filename}"
    )

# -----------------------
# Update Status
# -----------------------

def update_status(message):
    status_label.config(
        text=f"Status : {message}"
    )
    window.update_idletasks()


# -----------------------
# Window / Layout 1
# -----------------------

database.create_database()

window = tk.Tk()
window.title("Advanced Cyber Security Toolkit")
window.geometry("1200x760")
window.minsize(1050, 700)
window.configure(bg="#eef1f5")

# -----------------------
# Header
# -----------------------

header = tk.Frame(window, bg="#17212b", height=70)
header.pack(fill="x")
header.pack_propagate(False)

title = tk.Label(
    header,
    text="Advanced Cyber Security Toolkit",
    font=("Arial", 22, "bold"),
    bg="#17212b",
    fg="white"
)
title.pack(anchor="w", padx=20, pady=(8, 0))

subtitle = tk.Label(
    header,
    text="Network scanning  •  Website security  •  File integrity  •  Password & hash tools",
    font=("Arial", 9),
    bg="#17212b",
    fg="#c8d2dc"
)
subtitle.pack(anchor="w", padx=22, pady=(0, 4))

# -----------------------
# Main dashboard
# -----------------------

dashboard = tk.Frame(window, bg="#eef1f5")
dashboard.pack(fill="both", expand=True, padx=6, pady=(3, 4))

dashboard.grid_columnconfigure(0, weight=3, uniform="main")
dashboard.grid_columnconfigure(1, weight=2, uniform="main")

dashboard.grid_rowconfigure(0, weight=0, minsize=165)
dashboard.grid_rowconfigure(1, weight=0, minsize=68)
dashboard.grid_rowconfigure(2, weight=0, minsize=82)
dashboard.grid_rowconfigure(3, weight=1, minsize=235)

# -----------------------
# Network Scanner
# -----------------------

scanner_frame = tk.LabelFrame(
    dashboard,
    text="Network Scanner",
    padx=10,
    pady=3
)
scanner_frame.grid(
    row=0, column=0,
    padx=(0, 6), pady=(0, 6),
    sticky="nsew"
)

scanner_frame.grid_columnconfigure(1, weight=1)
scanner_frame.grid_columnconfigure(2, weight=1)

for r, (label_text, width) in enumerate([
    ("Target Website / IP", 35),
    ("Start Port", 12),
    ("End Port", 12),
]):
    tk.Label(
        scanner_frame,
        text=label_text
    ).grid(
        row=r, column=0,
        padx=(5, 10), pady=2,
        sticky="w"
    )

    entry = tk.Entry(scanner_frame, width=width)
    entry.grid(
        row=r, column=1, columnspan=2,
        padx=5, pady=2,
        sticky="ew"
    )

    if r == 0:
        target_entry = entry
    elif r == 1:
        start_entry = entry
    else:
        end_entry = entry

scan_button = tk.Button(
    scanner_frame,
    text="Start Port Scan",
    command=start_scan
)
scan_button.grid(
    row=3, column=1,
    padx=5, pady=2,
    sticky="ew"
)

ping_button = tk.Button(
    scanner_frame,
    text="Ping Host",
    command=ping_scan
)
ping_button.grid(
    row=3, column=2,
    padx=5, pady=2,
    sticky="ew"
)

packet_sniffer_label = tk.Label(
    scanner_frame,
    text="Packet Count"
)
packet_sniffer_label.grid(
    row=4, column=0,
    padx=(5, 10), pady=2,
    sticky="w"
)

packet_count_entry = tk.Entry(
    scanner_frame,
    width=12
)
packet_count_entry.insert(0, "10")
packet_count_entry.grid(
    row=4, column=1, columnspan=2,
    padx=5, pady=2,
    sticky="ew"
)

packet_sniffer_button = tk.Button(
    scanner_frame,
    text="Capture Packets",
    command=run_packet_sniffer
)
packet_sniffer_button.grid(
    row=5, column=1,
    padx=5, pady=2,
    sticky="ew"
)

save_packet_button = tk.Button(
    scanner_frame,
    text="Save Packet Capture Report",
    command=save_packet_capture_report
)
save_packet_button.grid(
    row=5, column=2,
    padx=5, pady=2,
    sticky="ew"
)

log_analyzer_button = tk.Button(
    scanner_frame,
    text="Log Analyzer + IDS",
    command=run_log_analyzer
)
log_analyzer_button.grid(
    row=6, column=1,
    padx=5, pady=2,
    sticky="ew"
)

save_ids_button = tk.Button(
    scanner_frame,
    text="Save IDS Report",
    command=save_ids_report
)
save_ids_button.grid(
    row=6, column=2,
    padx=5, pady=2,
    sticky="ew"
)

# -----------------------
# Information Tools + Website Security
# -----------------------

right_top = tk.Frame(dashboard)
right_top.grid(
    row=0, column=1,
    padx=(5, 0), pady=(0, 6),
    sticky="nsew"
)
right_top.grid_columnconfigure(0, weight=1)
right_top.grid_rowconfigure(0, weight=1)
right_top.grid_rowconfigure(1, weight=1)

info_frame = tk.LabelFrame(
    right_top,
    text="Information Tools",
    padx=7,
    pady=3
)
info_frame.grid(
    row=0, column=0,
    sticky="nsew",
    pady=(0, 3)
)
info_frame.grid_columnconfigure(0, weight=1)
info_frame.grid_columnconfigure(1, weight=1)

for label, command, row, col in [
    ("DNS Lookup", dns_scan, 0, 0),
    ("WHOIS Lookup", whois_scan, 0, 1),
    ("Scan History", show_history, 1, 0),
    ("Export History", export_history, 1, 1),
    ("Database History", show_database_history, 2, 0),
]:
    tk.Button(
        info_frame,
        text=label,
        command=command
    ).grid(
        row=row, column=col,
        padx=3, pady=1,
        sticky="ew"
    )

web_frame = tk.LabelFrame(
    right_top,
    text="Website Security",
    padx=7,
    pady=4
)
web_frame.grid(
    row=1, column=0,
    sticky="nsew",
    pady=(3, 0)
)
web_frame.grid_columnconfigure(0, weight=1)
web_frame.grid_columnconfigure(1, weight=1)

tk.Button(
    web_frame,
    text="HTTP Check",
    command=http_check
).grid(
    row=0, column=0,
    padx=3, pady=1,
    sticky="ew"
)

tk.Button(
    web_frame,
    text="Security Headers",
    command=security_headers_check
).grid(
    row=0, column=1,
    padx=3, pady=1,
    sticky="ew"
)

tk.Button(
    web_frame,
    text="Vulnerability Scan",
    command=start_vulnerability_scan
).grid(
    row=1, column=0,
    padx=3, pady=1,
    sticky="ew"
)

tk.Button(
    web_frame,
    text="Open Vulnerability Report",
    command=open_latest_vulnerability_report
).grid(
    row=1, column=1,
    padx=3, pady=1,
    sticky="ew"
)

# -----------------------
# File Integrity & Audit
# -----------------------

integrity_frame = tk.LabelFrame(
    dashboard,
    text="File Integrity & Audit",
    padx=7,
    pady=3
)
integrity_frame.grid(
    row=1, column=0, columnspan=2,
    padx=0, pady=3,
    sticky="ew"
)

for col in range(1, 5):
    integrity_frame.grid_columnconfigure(col, weight=1)

integrity_file_label = tk.Label(
    integrity_frame,
    text="File"
)
integrity_file_label.grid(
    row=0, column=0,
    padx=4, pady=2,
    sticky="e"
)

integrity_file_entry = tk.Entry(integrity_frame)
integrity_file_entry.grid(
    row=0, column=1, columnspan=3,
    padx=5, pady=2,
    sticky="ew"
)

browse_integrity_button = tk.Button(
    integrity_frame,
    text="Browse",
    command=browse_integrity_file,
    width=12
)
browse_integrity_button.grid(
    row=0, column=4,
    padx=5, pady=2,
    sticky="ew"
)

integrity_buttons = [
    ("Create Baseline", create_integrity_baseline),
    ("Check Integrity", check_file_integrity),
    ("Clear File", clear_integrity_file),
    ("Open Report", open_integrity_report),
    ("Open Reports Folder", open_integrity_reports_folder),
    ("View Integrity History", show_integrity_history),
    ("Clear Integrity History", clear_integrity_history),
]

for index, (label, command) in enumerate(integrity_buttons):
    row = 1 + (index // 4)
    column = 1 + (index % 4)

    tk.Button(
        integrity_frame,
        text=label,
        command=command,
        height=1
    ).grid(
        row=row,
        column=column,
        padx=4,
        pady=2,
        sticky="ew"
    )

# -----------------------
# Password & Hash Tools
# -----------------------

hash_frame = tk.LabelFrame(
    dashboard,
    text="Password & Hash Tools",
    padx=7,
    pady=3
)
hash_frame.grid(
    row=2, column=0, columnspan=2,
    padx=0, pady=3,
    sticky="ew"
)

hash_frame.grid_columnconfigure(1, weight=1)
hash_frame.grid_columnconfigure(2, weight=1)

password_label = tk.Label(hash_frame, text="Password")
password_label.grid(
    row=0, column=0,
    padx=4, pady=2,
    sticky="e"
)

password_entry = tk.Entry(hash_frame, show="*")
password_entry.grid(
    row=0, column=1,
    padx=4, pady=2,
    sticky="ew"
)

password_button = tk.Button(
    hash_frame,
    text="Check Password Strength",
    command=password_strength_check
)
password_button.grid(
    row=0, column=2,
    padx=4, pady=2,
    sticky="ew"
)

hash_text_label = tk.Label(hash_frame, text="Text")
hash_text_label.grid(
    row=1, column=0,
    padx=4, pady=2,
    sticky="e"
)

hash_text_entry = tk.Entry(hash_frame)
hash_text_entry.grid(
    row=1, column=1,
    padx=4, pady=2,
    sticky="ew"
)

generate_hash_button = tk.Button(
    hash_frame,
    text="Generate Hash",
    command=create_hash
)
generate_hash_button.grid(
    row=1, column=2,
    padx=4, pady=2,
    sticky="ew"
)

hash_algorithm = tk.StringVar(value="sha256")

hash_algorithm_label = tk.Label(hash_frame, text="Algorithm")
hash_algorithm_label.grid(
    row=2, column=0,
    padx=4, pady=2,
    sticky="e"
)

hash_algorithm_box = ttk.Combobox(
    hash_frame,
    textvariable=hash_algorithm,
    values=["md5", "sha1", "sha256", "sha512"],
    state="readonly"
)
hash_algorithm_box.grid(
    row=2, column=1,
    padx=4, pady=2,
    sticky="ew"
)

expected_hash_label = tk.Label(hash_frame, text="Expected Hash")
expected_hash_label.grid(
    row=3, column=0,
    padx=4, pady=2,
    sticky="e"
)

expected_hash_entry = tk.Entry(hash_frame)
expected_hash_entry.grid(
    row=3, column=1,
    padx=4, pady=2,
    sticky="ew"
)

verify_hash_button = tk.Button(
    hash_frame,
    text="Verify Hash",
    command=check_hash
)
verify_hash_button.grid(
    row=3, column=2,
    padx=4, pady=2,
    sticky="ew"
)

# -----------------------
# Scan Results / Output
# -----------------------

results_frame = tk.LabelFrame(
    dashboard,
    text="Scan Results / Output",
    padx=8,
    pady=5
)
results_frame.grid(
    row=3, column=0, columnspan=2,
    padx=0, pady=(3, 0),
    sticky="nsew"
)

results_frame.grid_columnconfigure(0, weight=1)
results_frame.grid_rowconfigure(1, weight=1, minsize=90)
results_frame.grid_rowconfigure(2, weight=0, minsize=40)

status_label = tk.Label(
    results_frame,
    text="Status : Ready",
    font=("Arial", 9),
    anchor="w"
)
status_label.grid(
    row=0, column=0,
    padx=4, pady=(0, 4),
    sticky="ew"
)

result_frame = tk.Frame(results_frame)
result_frame.grid(
    row=1, column=0,
    padx=2, pady=2,
    sticky="nsew"
)
result_frame.grid_columnconfigure(0, weight=1)
result_frame.grid_rowconfigure(0, weight=1)

result_box = tk.Text(
    result_frame,
    height=4,
    wrap="none",
    font=("Consolas", 9)
)
result_box.grid(
    row=0, column=0,
    sticky="nsew"
)

result_scrollbar_y = tk.Scrollbar(
    result_frame,
    orient="vertical",
    command=result_box.yview
)
result_scrollbar_y.grid(
    row=0, column=1,
    sticky="ns"
)

result_scrollbar_x = tk.Scrollbar(
    result_frame,
    orient="horizontal",
    command=result_box.xview
)
result_scrollbar_x.grid(
    row=1, column=0,
    sticky="ew"
)

result_box.config(
    yscrollcommand=result_scrollbar_y.set,
    xscrollcommand=result_scrollbar_x.set
)

# Bottom control row: progress bar + clear button.
results_controls = tk.Frame(results_frame)
results_controls.grid(
    row=2, column=0,
    padx=2, pady=(3, 1),
    sticky="ew"
)
results_controls.grid_columnconfigure(1, weight=1)

progress_label = tk.Label(
    results_controls,
    text="Progress : 0%",
    width=10,
    anchor="w"
)
progress_label.grid(
    row=0, column=0,
    padx=(2, 7), pady=2,
    sticky="w"
)

style = ttk.Style()
try:
    style.theme_use("clam")
except tk.TclError:
    pass

style.configure(
    "App.Horizontal.TProgressbar",
    troughcolor="#d9dee5",
    background="#2e86de",
    bordercolor="#b8c0ca",
    lightcolor="#2e86de",
    darkcolor="#2e86de"
)

progress = ttk.Progressbar(
    results_controls,
    orient="horizontal",
    mode="determinate",
    maximum=100,
    style="App.Horizontal.TProgressbar"
)
progress.grid(
    row=0, column=1,
    padx=3, pady=2,
    sticky="ew"
)

def clear_results():
    result_box.delete("1.0", tk.END)
    result_box.see("1.0")
    status_label.config(text="Status : Results Cleared")
    progress["value"] = 0
    progress_label.config(text="Progress : 0%")

clear_button = tk.Button(
    results_controls,
    text="CLEAR RESULTS",
    command=clear_results,
    width=12,
    height=1
)
clear_button.grid(
    row=0, column=2,
    padx=(7, 2), pady=1,
    sticky="e"
)

# Result colors
result_box.tag_config("found", foreground="green")
result_box.tag_config("missing", foreground="red")
result_box.tag_config("error", foreground="red")

window.mainloop()