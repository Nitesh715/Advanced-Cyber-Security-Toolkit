import platform
import subprocess
import re
import socket


def ping_host(target):

    # Resolve IP Address
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        return False, "Invalid Host", "", "Invalid Website or IP Address"

    # Windows / Linux command
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", target]
    else:
        command = ["ping", "-c", "1", target]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="ignore"
        )

        output = str(result.stdout) + str(result.stderr)

        # Host Online
        if result.returncode == 0:

            match = re.search(
                r"time[=<]\s*(\d+)\s*ms",
                output,
                re.IGNORECASE
            )

            if match:
                response_time = match.group(1) + " ms"
            else:
                response_time = "Not Available"

            return True, response_time, ip_address, output

        # Host Offline
        return False, "Timeout", ip_address, output

    except Exception as e:

        return False, "Error", ip_address, str(e)