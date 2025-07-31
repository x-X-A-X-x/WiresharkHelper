import pandas as pd
import matplotlib.pyplot as plt

# === 1. Load CSV ===
file_path = "Test1.csv"  # Change this to your CSV file path
df = pd.read_csv(file_path)

# === 2. Combine Source and Destination IPs ===
all_ips = pd.concat([
    df[['Source', 'Length']].rename(columns={'Source': 'IP'}),
    df[['Destination', 'Length']].rename(columns={'Destination': 'IP'})
])

# === 3. Aggregate IP traffic ===
ip_summary = all_ips.groupby('IP').agg(
    packets=('IP', 'count'),
    total_bytes=('Length', 'sum')
).reset_index()

# === 4. Assign threat levels based on packet count ===
ip_summary["threat_level"] = pd.cut(
    ip_summary["packets"],
    bins=[0, 10, 100, float("inf")],
    labels=["Low", "Medium", "High"]
)

# === 5. Sort for visualization ===
ip_summary = ip_summary.sort_values("packets", ascending=False)

# === 6. Map threat levels to colors ===
color_map = {"Low": "green", "Medium": "orange", "High": "red"}
colors = ip_summary["threat_level"].map(color_map)

# === 7. Visualize ===
plt.figure(figsize=(14, 6))
bars = plt.bar(ip_summary['IP'], ip_summary['packets'], color=colors)

# Add threat level labels above each bar
for i, bar in enumerate(bars):
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height + 1,
             ip_summary["threat_level"].iloc[i],
             ha='center', fontsize=8, rotation=90)

plt.xticks(rotation=90)
plt.xlabel("IP Address")
plt.ylabel("Packet Count")
plt.title("IP Addresses and Threat Levels")
plt.tight_layout()
plt.show()

# === 8. Print or save the summary table ===
print(ip_summary)
ip_summary.to_csv("ip_threat_summary.csv", index=False)
print("\nSummary saved as 'ip_threat_summary.csv'")
