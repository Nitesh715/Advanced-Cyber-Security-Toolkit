from collections import Counter


def detect_intrusions(findings):
    """
    Basic rule-based Intrusion Detection System.
    """

    alerts = []

    failed_auth_count = sum(
        1
        for finding in findings
        if "Failed authentication" in finding
    )

    brute_force_count = sum(
        1
        for finding in findings
        if "brute-force" in finding.lower()
    )

    scan_count = sum(
        1
        for finding in findings
        if "scanning activity" in finding.lower()
    )

    unauthorized_count = sum(
        1
        for finding in findings
        if "Unauthorized access" in finding
    )

    # Rule 1: repeated authentication failures
    if failed_auth_count >= 3:
        alerts.append(
            "[HIGH] Possible brute-force attack detected."
        )

    # Rule 2: brute-force event already reported
    if brute_force_count >= 1:
        alerts.append(
            "[HIGH] Brute-force activity detected."
        )

    # Rule 3: scanning activity
    if scan_count >= 1:
        alerts.append(
            "[HIGH] Possible network scanning activity detected."
        )

    # Rule 4: unauthorized access
    if unauthorized_count >= 2:
        alerts.append(
            "[MEDIUM] Multiple unauthorized access attempts detected."
        )

    return alerts