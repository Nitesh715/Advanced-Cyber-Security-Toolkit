from datetime import datetime


def analyze_log(log_file):
    """
    Basic security log analyzer.
    Detects common suspicious events from an authorized log file.
    """

    findings = []

    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            text = line.strip()

            if not text:
                continue

            lower_text = text.lower()

            # Failed login detection
            if "failed login" in lower_text or "authentication failed" in lower_text:
                findings.append(
                    f"[MEDIUM] Failed authentication detected "
                    f"(Line {line_number})"
                )

            # Brute-force indication
            elif "brute force" in lower_text:
                findings.append(
                    f"[HIGH] Possible brute-force activity "
                    f"(Line {line_number})"
                )

            # Unauthorized access
            elif "unauthorized" in lower_text or "access denied" in lower_text:
                findings.append(
                    f"[MEDIUM] Unauthorized access attempt "
                    f"(Line {line_number})"
                )

            # Suspicious scan activity
            elif "port scan" in lower_text or "scan detected" in lower_text:
                findings.append(
                    f"[HIGH] Possible scanning activity "
                    f"(Line {line_number})"
                )

        return findings

    except FileNotFoundError:
        return ["[ERROR] Log file not found."]

    except Exception as error:
        return [f"[ERROR] Log analysis failed: {error}"]


if __name__ == "__main__":
    print("Log Analyzer Module")
    print("Use analyze_log(log_file) from the GUI.")