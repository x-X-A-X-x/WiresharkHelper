import pandas as pd
import matplotlib.pyplot as plt
import re
import streamlit as st

# === Streamlit App Title ===
st.title("Wireshark IP Threat Analysis Dashboard")

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

# === 6. Display the summary table ===
st.subheader("IP Threat Summary")
st.dataframe(ip_summary)

# === 7. Visualization 1: Packet Volume ===
st.subheader("Packet Volume per IP")
fig1, ax1 = plt.subplots(figsize=(12, max(6, len(ip_summary) * 0.4)))
ax1.barh(ip_summary['IP'], ip_summary['packets'], color=colors)
ax1.set_xlabel("Packet Count")
ax1.set_ylabel("IPv4 Address")
ax1.set_title("Packet Volume per IP")
st.pyplot(fig1)

# === 8. Visualization 2: Total Traffic Size ===
st.subheader("Total Traffic Size per IP")
fig2, ax2 = plt.subplots(figsize=(12, max(6, len(ip_summary) * 0.4)))
ax2.barh(ip_summary['IP'], ip_summary['total_bytes'], color=colors)
ax2.set_xlabel("Total Traffic (Bytes)")
ax2.set_ylabel("IPv4 Address")
ax2.set_title("Total Traffic Size per IP")
st.pyplot(fig2)

# === 9. Visualization 3: Protocol Diversity ===
st.subheader("Protocol Diversity vs Packet Volume")
fig3, ax3 = plt.subplots(figsize=(12, 6))
ax3.scatter(ip_summary['packets'], ip_summary['unique_protocols'], c=colors)
for i, row in ip_summary.iterrows():
    ax3.text(row['packets'], row['unique_protocols'] + 0.1, row['IP'], fontsize=7)
ax3.set_xlabel("Packet Count")
ax3.set_ylabel("Unique Protocols")
ax3.set_title("Protocol Diversity vs Packet Volume")
ax3.grid(True)
st.pyplot(fig3)

# === 10. Save results ===
ip_summary.to_csv("ipv4_advanced_threat_summary.csv", index=False)
st.success("Summary saved as 'ipv4_advanced_threat_summary.csv'")
