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

# === 5. Sort by packet count (descending) ===
ip_summary = ip_summary.sort_values("packets", ascending=True)  # ascending for horizontal bar chart

# === 6. Map threat levels to colors ===
color_map = {"Low": "green", "Medium": "orange", "High": "red"}
colors = ip_summary["threat_level"].map(color_map)

# === 7. Visualize as horizontal bar chart ===
plt.figure(figsize=(12, max(6, len(ip_summary) * 0.4)))  # Adjust height dynamically
bars = plt.barh(ip_summary['IP'], ip_summary['packets'], color=colors)

# Add packet counts and threat levels next to bars
for i, bar in enumerate(bars):
    width = bar.get_width()
    plt.text(width + 1, bar.get_y() + bar.get_height()/2,
             f"{ip_summary['packets'].iloc[i]} ({ip_summary['threat_level'].iloc[i]})",
             va='center', fontsize=8)

plt.xlabel("Packet Count")
plt.ylabel("IP Address")
plt.title("IP Addresses and Threat Levels (Horizontal View)")
plt.tight_layout()
plt.show()

# === 8. Print or save the summary table ===
print(ip_summary)
ip_summary.to_csv("ip_threat_summary.csv", index=False)
print("\nSummary saved as 'ip_threat_summary.csv'")
