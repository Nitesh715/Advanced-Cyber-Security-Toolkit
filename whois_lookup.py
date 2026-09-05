import whois

from whois_report import save_whois_report
from whois_csv_report import save_whois_csv


# Return first item if value is a list
def get_first(value):
    if isinstance(value, list):
        return value[0]
    return value


# Format list values nicely
def format_value(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value:
        return str(value)
    return "Not Available"


def whois_lookup(domain, callback):

    try:

        data = whois.whois(domain)

        registrar = format_value(data.registrar)
        creation = get_first(data.creation_date)
        expiry = get_first(data.expiration_date)
        updated = get_first(data.updated_date)

        callback("=" * 50 + "\n")
        callback("WHOIS LOOKUP\n")
        callback("=" * 50 + "\n")

        callback(f"Domain Name  : {format_value(data.domain_name)}\n")
        callback(f"Registrar    : {registrar}\n")
        callback(f"Creation     : {creation}\n")
        callback(f"Expiry       : {expiry}\n")
        callback(f"Updated      : {updated}\n")

        callback(f"Name Servers : {format_value(getattr(data, 'name_servers', None))}\n")
        callback(f"Status       : {format_value(getattr(data, 'status', None))}\n")
        callback(f"Country      : {format_value(getattr(data, 'country', None))}\n")
        callback(f"Organization : {format_value(getattr(data, 'org', None))}\n")
        callback(f"Emails       : {format_value(getattr(data, 'emails', None))}\n")

        save_whois_report(
    domain,
    registrar,
    creation,
    expiry,
    updated,
    format_value(getattr(data, "name_servers", None)),
    format_value(getattr(data, "status", None)),
    format_value(getattr(data, "country", None)),
    format_value(getattr(data, "org", None)),
    format_value(getattr(data, "emails", None))
)

        save_whois_csv(
    domain,
    registrar,
    creation,
    expiry,
    updated,
    format_value(getattr(data, "name_servers", None)),
    format_value(getattr(data, "status", None)),
    format_value(getattr(data, "country", None)),
    format_value(getattr(data, "org", None)),
    format_value(getattr(data, "emails", None))
)

        callback("\n✅ WHOIS TXT Report Saved Successfully.\n")
        callback("✅ WHOIS CSV Report Saved Successfully.\n")

    except Exception as e:
        callback(f"\n❌ Error : {e}\n")