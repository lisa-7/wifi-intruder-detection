# This code is the main application for the Wi-Fi Intruder Detector, which scans the local network for devices,

# identifies them, and allows users to mark devices as trusted. It uses threading for scanning to keep the GUI responsive,

# and it provides a simple interface for managing trusted devices. The application also fetches vendor information  

# for MAC addresses using an external API. The trusted devices are stored in text files for persistence.

# The GUI is built using Tkinter, providing a user-friendly experience with progress updates and device management features.

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import subprocess
import threading
import time
import ipaddress
import re
import os
import socket
import uuid
import requests

TRUSTED_DEVICES_FILE = "trusted_devices.txt"

# ------------------ Utility Functions ------------------
def get_local_device_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode())).upper()
    return ip_address, mac_address, hostname

def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"

def get_mac(ip):
    try:
        output = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode()
        match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", output)
        if match:
            return match.group(0).upper().replace("-", ":")
    except:
        pass
    return "Unknown"

def ping_ip(ip):
    try:
        subprocess.check_output(["ping", "-n", "1", "-w", "300", str(ip)], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

# ------------------ Trusted Devices ------------------
def load_trusted_devices():
    trusted = {}
    if not os.path.exists(TRUSTED_DEVICES_FILE):
        open(TRUSTED_DEVICES_FILE, "w").close()
    with open(TRUSTED_DEVICES_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                trusted[parts[0].upper()] = parts[1]
            elif len(parts) == 1:
                trusted[parts[0].upper()] = "Trusted Device"
    return trusted

def add_to_trusted(mac, label="Trusted Device"):
    trusted = load_trusted_devices()
    trusted[mac.upper()] = label
    with open(TRUSTED_DEVICES_FILE, "w") as f:
        for mac_addr, name in trusted.items():
            f.write(f"{mac_addr},{name}\n")
    messagebox.showinfo("Trusted", f"{mac} saved as '{label}'")

# ------------------ Network Scanner ------------------
def scan_network_progress(ip_list, on_progress):
    devices = []
    threads = []
    total = len(ip_list)
    completed = [0]

    def scan(ip):
        if ping_ip(ip):
            mac = get_mac(str(ip))
            hostname = socket.getfqdn(str(ip))
            vendor = get_vendor(mac)
            devices.append((str(ip), mac, hostname, vendor))
        completed[0] += 1
        on_progress(completed[0], total)

    for ip in ip_list:
        thread = threading.Thread(target=scan, args=(ip,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return devices

# ------------------ GUI ------------------
def run_scan_background():
    scan_btn.config(state="disabled")
    trust_btn.config(state="disabled")
    result_table.delete(*result_table.get_children())
    status_label.config(text="🔍 Scanning network... Please wait.")
    progress_bar["value"] = 0

    def update_progress(done, total):
        percent = int((done / total) * 100)
        progress_bar["value"] = percent
        status_label.config(text=f"Scanning... {percent}%")

    def task():
        ip_net = ipaddress.IPv4Network("192.168.1.1/24", strict=False)
        ip_list = list(ip_net.hosts())
        trusted = load_trusted_devices()

        start = time.time()
        devices = scan_network_progress(ip_list, update_progress)
        local_ip, local_mac, local_hostname = get_local_device_info()
        local_vendor = get_vendor(local_mac)
        devices.append((local_ip, local_mac, local_hostname, local_vendor))

        shown_macs = set()
        for ip, mac, hostname, vendor in devices:
            if mac in shown_macs:
                continue
            shown_macs.add(mac)
            label = trusted.get(mac, "⚠️ Unknown")
            display_name = f"{label} ({hostname})" if hostname != ip else label
            result_table.insert("", "end", values=(ip, mac, display_name, vendor))

        duration = round(time.time() - start, 2)
        status_label.config(text=f"✅ Scan complete in {duration}s. {len(devices)} devices found.")
        scan_btn.config(state="normal")
        trust_btn.config(state="normal")
        progress_bar["value"] = 100

    threading.Thread(target=task).start()

def on_add_trust():
    selected = result_table.selection()
    if not selected:
        messagebox.showwarning("No Selection", "Please select a device to trust.")
        return
    item = result_table.item(selected[0])
    mac = item["values"][1]
    label = simpledialog.askstring("Device Label", "Enter a friendly name for this device:", parent=root)
    if label:
        add_to_trusted(mac, label)
        run_scan_background()

# ------------------ GUI Setup ------------------
root = tk.Tk()
root.title("Wi-Fi Intruder Detector")
root.geometry("750x550")

tk.Label(root, text="Wi-Fi Intruder Detector", font=("Helvetica", 16, "bold")).pack(pady=10)

scan_btn = tk.Button(root, text="Scan Network", command=run_scan_background, bg="green", fg="white", padx=10, pady=5)
scan_btn.pack()

progress_bar = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(pady=5)

columns = ("IP Address", "MAC Address", "Name / Status", "Vendor")
result_table = ttk.Treeview(root, columns=columns, show="headings", height=15)
for col in columns:
    result_table.heading(col, text=col)
    result_table.column(col, width=180, anchor="center")
result_table.pack(expand=True, fill="both", pady=10)

trust_btn = tk.Button(root, text="Add Selected to Trusted List", command=on_add_trust, bg="blue", fg="white")
trust_btn.pack(pady=5)

status_label = tk.Label(root, text="Ready", font=("Arial", 10), fg="gray")
status_label.pack(pady=5)

root.mainloop()

# --- End of main.py ---
