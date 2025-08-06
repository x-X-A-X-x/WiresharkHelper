import pandas as pd
import re
from ipwhois import IPWhois

# ==== CONFIG ====
file_path = "Galant.csv"  # Replace with your CSV file
internal_ip_pattern = re.compile(r'^(10\.\d+\.\d+\.\d+)|(192\.168\.\d+\.\d+)|(172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)$')

# ==== FUNCTIONS ====
def is_internal_ip(ip):
    """Check if an IP address is private/internal."""
    return bool(internal_ip_pattern.match(ip))

def get_ip_info(ip):
    """Get IP owner/org info using IPWhois."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result.get("network", {}).get("name", "Unknown"), result.get("asn_description", "Unknown")
    except:
        return "Unknown", "Unknown"

# ==== LOAD CSV ====
df = pd.read_csv(file_path)

# ==== EXTRACT INTERNAL IPS ====
internal_ips = set()
for col in ["Source", "Destination"]:
    internal_ips.update(df[col].apply(lambda x: x if is_internal_ip(str(x)) else None).dropna())

print("\n[+] Internal IPs Detected:")
for ip in sorted(internal_ips):
    print(ip)

# ==== EXTRACT EXTERNAL IPS ====
external_ips = set()
for col in ["Source", "Destination"]:
    external_ips.update(df[col].apply(lambda x: x if not is_internal_ip(str(x)) else None).dropna())

print("\n[+] External IPs Detected with Owners:")
external_info = []
for ip in sorted(external_ips):
    org_name, asn_desc = get_ip_info(ip)
    external_info.append({"IP": ip, "Org": org_name, "ASN": asn_desc})
    print(f"{ip} -> {org_name} ({asn_desc})")

# ==== OPTIONAL: SAVE RESULTS ====
pd.DataFrame(external_info).to_csv("external_ip_analysis.csv", index=False)
print("\n[+] External IP details saved to external_ip_analysis.csv")
