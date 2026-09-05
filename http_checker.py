import time
import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]


# -----------------------
# HTTP Check
# -----------------------

def check_url(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:

        start_time = time.time()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        end_time = time.time()

        response_time = round(
            (end_time - start_time) * 1000,
            2
        )

        return {
            "url": url,
            "status_code": response.status_code,
            "final_url": response.url,
            "response_time": response_time,
            "server": response.headers.get(
                "Server",
                "Not Available"
            ),
            "content_type": response.headers.get(
                "Content-Type",
                "Not Available"
            )
        }

    except requests.RequestException as e:

        return {
            "error": str(e)
        }


# -----------------------
# Security Headers
# -----------------------

def check_security_headers(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers

        results = {}

        for header in SECURITY_HEADERS:

            if header in headers:
                results[header] = headers[header]

            else:
                results[header] = "Missing"

        return results

    except requests.RequestException as e:

        return {
            "error": str(e)
        }


# -----------------------
# Test
# -----------------------

if __name__ == "__main__":

    target = input(
        "Enter Website URL : "
    )

    result = check_url(target)

    print("\n========== HTTP CHECK ==========")

    if "error" in result:

        print(
            "Error :",
            result["error"]
        )

    else:

        print(
            "URL            :",
            result["url"]
        )

        print(
            "Status Code    :",
            result["status_code"]
        )

        print(
            "Final URL      :",
            result["final_url"]
        )

        print(
            "Response Time  :",
            result["response_time"],
            "ms"
        )

        print(
            "Server         :",
            result["server"]
        )

        print(
            "Content Type   :",
            result["content_type"]
        )