import socket

from dns_report import save_dns_report
from dns_csv_report import save_dns_csv 
def dns_lookup(domain, callback):

    try:

        ip = socket.gethostbyname(domain)
        hostname = socket.getfqdn(domain)

        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = "Not Available"

        callback("=" * 50 + "\n")
        callback("DNS Lookup\n")
        callback("=" * 50 + "\n")

        callback(f"Domain       : {domain}\n")
        callback(f"Hostname     : {hostname}\n")
        callback(f"IPv4 Address : {ip}\n")
        callback(f"Reverse DNS  : {reverse_dns}\n")
        save_dns_report(
            domain,
            hostname,
            ip,
            reverse_dns
        )
        callback("\nDNS Report Saved successfully.\n")
        
        save_dns_csv(
            domain,
            hostname,
            ip,
            reverse_dns
        )
        callback("CSV Report saved Successfully.\n")

    except Exception as e:
        callback(f"\nError : {e}\n")