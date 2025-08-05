import pandas as pd
import matplotlib.pyplot as plt
import re
import tkinter as tk
from tkinter import filedialog, messagebox

def analyze_csv():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return
    
    df = pd.read_csv(file_path)

    # Filter IPv4
    ipv4_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    df = df[df['Source'].apply(lambda x: bool(re.match(ipv4_pattern, str(x)))) |
            df['Destination'].apply(lambda x: bool(re.match(ipv4_pattern, str(x))))]

    # Aggregate traffic
    all_ips = pd.concat([
        df[['Source', 'Protocol', 'Length']].rename(columns={'Source': 'IP'}),
        df[['Destination', 'Protocol', 'Length']].rename(columns={'Destination': 'IP'})
    ])

    ip_summary = all_ips.groupby('IP').agg(
        packets=('IP', 'count'),
        total_bytes=('Length', 'sum'),
        unique_protocols=('Protocol', 'nunique')
    ).reset_index()

    # Threat detection
    def determine_threat(row):
        if row['packets'] > 500 or row['total_bytes'] > 500000:
            return "High"
        elif row['packets'] > 100 or row['unique_protocols'] > 3:
            return "Medium"
        else:
            return "Low"

    ip_summary["threat_level"] = ip_summary.apply(determine_threat, axis=1)

    # Save summary
    ip_summary.to_csv("ipv4_advanced_threat_summary.csv", index=False)
    messagebox.showinfo("Success", "Analysis complete! Results saved to ipv4_advanced_threat_summary.csv")

    # Colors
    color_map = {"Low": "green", "Medium": "orange", "High": "red"}
    colors = ip_summary["threat_level"].map(color_map)

    # Plot graphs
    plt.figure(figsize=(12, max(6, len(ip_summary) * 0.4)))
    plt.barh(ip_summary['IP'], ip_summary['packets'], color=colors)
    plt.xlabel("Packet Count")
    plt.ylabel("IPv4 Address")
    plt.title("Packet Volume per IP")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(12, max(6, len(ip_summary) * 0.4)))
    plt.barh(ip_summary['IP'], ip_summary['total_bytes'], color=colors)
    plt.xlabel("Total Traffic (Bytes)")
    plt.ylabel("IPv4 Address")
    plt.title("Total Traffic Size per IP")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(12, 6))
    plt.scatter(ip_summary['packets'], ip_summary['unique_protocols'], c=colors)
    for i, row in ip_summary.iterrows():
        if row["threat_level"] == "High":  # Only label high threat
            plt.text(row['packets'], row['unique_protocols'] + 0.1, row['IP'], fontsize=7, color='red')
    plt.xlabel("Packet Count")
    plt.ylabel("Unique Protocols")
    plt.title("Protocol Diversity vs Packet Volume")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# Create simple GUI
root = tk.Tk()
root.title("Wireshark IP Threat Analyzer")

analyze_button = tk.Button(root, text="Analyze CSV", command=analyze_csv, font=("Arial", 14))
analyze_button.pack(pady=20)

root.mainloop()
