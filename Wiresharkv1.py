import pandas as pd
import matplotlib.pyplot as plt
import re

# === 1. Load CSV ===
file_path = "Test1.csv"
df = pd.read_csv(file_path)

# === 2. Filter for IPv4 addresses only ===
ipv4_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
df = df[df['Source'].apply(lambda x: bool(re.match(ipv4_pattern, str(x)))) |
        df['Destination'].apply(lambda x: bool(re.match(ipv4_pattern, str(x))))]

# === 3. Aggregate traffic per IP ===
all_ips = pd.concat([
    df[['Source', 'Protocol', 'Length']].rename(columns={'Source': 'IP'}),
    df[['Destination', 'Protocol', 'Length']].rename(columns={'Destination': 'IP'})
])

ip_summary = all_ips.groupby('IP').agg(
    packets=('IP', 'count'),
    total_bytes=('Length', 'sum'),
    unique_protocols=('Protocol', 'nunique')
).reset_index()

# === 4. Threat detection logic ===
def determine_threat(row):
    if row['packets'] > 500 or row['total_bytes'] > 500000:
        return "High"
    elif row['packets'] > 100 or row['unique_protocols'] > 3:
        return "Medium"
    else:
        return "Low"

ip_summary["threat_level"] = ip_summary.apply(determine_threat, axis=1)

# === 5. Map threat levels to colors ===
color_map = {"Low": "green", "Medium": "orange", "High": "red"}
colors = ip_summary["threat_level"].map(color_map)

# === 6. Show summary table in terminal ===
print("\n===== IP Threat Summary =====\n")
print(ip_summary)
ip_summary.to_csv("ipv4_advanced_threat_summary.csv", index=False)
print("\nSummary saved as 'ipv4_advanced_threat_summary.csv'")

# === 7. Visualization 1: Packet Volume ===
plt.figure(figsize=(12, max(6, len(ip_summary) * 0.4)))
plt.barh(ip_summary['IP'], ip_summary['packets'], color=colors)
plt.xlabel("Packet Count")
plt.ylabel("IPv4 Address")
plt.title("Packet Volume per IP")
plt.tight_layout()
plt.show()

# === 8. Visualization 2: Total Traffic Size ===
plt.figure(figsize=(12, max(6, len(ip_summary) * 0.4)))
plt.barh(ip_summary['IP'], ip_summary['total_bytes'], color=colors)
plt.xlabel("Total Traffic (Bytes)")
plt.ylabel("IPv4 Address")
plt.title("Total Traffic Size per IP")
plt.tight_layout()
plt.show()

# === 9. Visualization 3: Protocol Diversity ===
plt.figure(figsize=(12, 6))
plt.scatter(ip_summary['packets'], ip_summary['unique_protocols'], c=colors)
for i, row in ip_summary.iterrows():
    plt.text(row['packets'], row['unique_protocols'] + 0.1, row['IP'], fontsize=7)
plt.xlabel("Packet Count")
plt.ylabel("Unique Protocols")
plt.title("Protocol Diversity vs Packet Volume (Possible Port Scanning Detection)")
plt.grid(True)
plt.tight_layout()
plt.show()
