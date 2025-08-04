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

# === 3. Aggregate traffic per IP with more features ===
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
    # Basic heuristic:
    if row['packets'] > 500 or row['total_bytes'] > 500000:
        return "High"
    elif row['packets'] > 100 or row['unique_protocols'] > 3:
        return "Medium"
    else:
        return "Low"

ip_summary["threat_level"] = ip_summary.apply(determine_threat, axis=1)

# === 5. Sort for visualization ===
ip_summary = ip_summary.sort_values("packets", ascending=True)

# === 6. Map threat levels to colors ===
color_map = {"Low": "green", "Medium": "orange", "High": "red"}
colors = ip_summary["threat_level"].map(color_map)

# === 7. Visualize as horizontal bar chart ===
plt.figure(figsize=(12, max(6, len(ip_summary) * 0.4)))
bars = plt.barh(ip_summary['IP'], ip_summary['packets'], color=colors)

# Add labels
for i, bar in enumerate(bars):
    width = bar.get_width()
    plt.text(width + 1, bar.get_y() + bar.get_height()/2,
             f"{ip_summary['packets'].iloc[i]} pkts, {ip_summary['unique_protocols'].iloc[i]} protos ({ip_summary['threat_level'].iloc[i]})",
             va='center', fontsize=8)

plt.xlabel("Packet Count")
plt.ylabel("IPv4 Address")
plt.title("IPv4 Threat Analysis (Packets, Protocols, Bytes)")
plt.tight_layout()
plt.show()

# === 8. Save results ===
print(ip_summary)
ip_summary.to_csv("ipv4_advanced_threat_summary.csv", index=False)
print("\nSummary saved as 'ipv4_advanced_threat_summary.csv'")
