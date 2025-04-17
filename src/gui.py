import tkinter as tk
from tkinter import ttk
from scanner import scan_target  # Import your scan function
import threading  # ✅ Import threading at the top of gui.py

# Create main window
root = tk.Tk()
root.title("ReconX Network Scanner")
root.geometry("600x500")  # Increase height to prevent cutoff

# Title Label
title_label = tk.Label(root, text="ReconX - Network Security Toolkit", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# Dropdown Menu for Scan Type
scan_type_label = tk.Label(root, text="Select Scan Type:")
scan_type_label.pack()
scan_type = ttk.Combobox(root, values=["Port Scan", "OS Fingerprinting", "Service Detection", "Full Scan"])
scan_type.pack()

# Target IP Entry
target_ip_label = tk.Label(root, text="Enter Target IP:")
target_ip_label.pack()
target_ip_entry = tk.Entry(root)
target_ip_entry.pack()

# Port Entry Field
port_label = tk.Label(root, text="Enter Ports (comma-separated):")
port_label.pack()
port_entry = tk.Entry(root)
port_entry.pack()

# Scan Button
from scanner import scan_target  # Import scanning function

# Terminal Output Box
output_frame = tk.Frame(root)
output_frame.pack(fill="both", expand=True, padx=10, pady=10)

output_text = tk.Text(output_frame, wrap="word", height=10, width=70, bg="black", fg="green", font=("Courier", 10))
output_text.pack(fill="both", expand=True)

# Scrollbar for Output Box
scrollbar = tk.Scrollbar(output_frame, command=output_text.yview)
scrollbar.pack(side="right", fill="y")
output_text.config(yscrollcommand=scrollbar.set)

def update_terminal(message):
    try:
        # Ensure UTF-8 encoding and remove unsupported characters
        message = message.encode("utf-8", "ignore").decode("utf-8")  
        output_text.insert("end", message + "\n")
        output_text.see("end")  # Auto-scroll to latest output
    except Exception as e:
        print(f"Encoding Error: {e}")  # Debugging in case of issues

import threading  # Ensure threading is imported

def start_scan():
    selected_scan = scan_type.get()
    target_ip = target_ip_entry.get()
    port_input = port_entry.get()

    # Convert input string into a list of ports
    custom_ports = [int(port.strip()) for port in port_input.split(",") if port.strip().isdigit()]

    # Ensure UTF-8 encoding for terminal output
    safe_target_ip = target_ip.encode("utf-8", "ignore").decode("utf-8")
    safe_ports = str(custom_ports).encode("utf-8", "ignore").decode("utf-8")

    update_terminal(f"🚀 Starting {selected_scan} scan on {safe_target_ip} with ports {safe_ports}...")

    # ✅ Run scan in a new thread to prevent UI freezing
    scan_thread = threading.Thread(target=scan_target, args=(target_ip, custom_ports, update_terminal))
    scan_thread.start()

# Create scan button AFTER defining function
scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=10)

# Run GUI
root.mainloop()