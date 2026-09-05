import csv
import os

def save_dns_csv(domain, hostname, ip, reverse_dns):
    os.makedirs("reports", exist_ok=True)

    filename = "reports/ dns_reports.csv"

    file_exists =os.path.isfile(filename)
    with open(filename, "a", newline="") as file:

         writer = csv.writer(file)

         if not file_exists:
              writer.writerow([
                   "Domain",
                   "Hostname",
                   "IPv4 Address",
                   "Reverse DNS"
              ])
         writer.writerow([
             domain,
             hostname,
             ip,
             reverse_dns
        ])
    return filename
    