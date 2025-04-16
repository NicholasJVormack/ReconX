import socket  # Handles basic network connections
import threading  # Enables multi-threading for faster port scanning
import subprocess  # Runs external Nmap scans
import datetime  # Used for timestamps
import csv  # Enables CSV writing
import os # Required for folder creation

# Generate a unique folder name based on the scan timestamp
scan_folder = f"scan_results_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
os.makedirs(scan_folder)  # Create the folder

# Generate unique filenames for each scan
timestamp_filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
CSV_FILE = os.path.join(scan_folder, f"scan_results_{timestamp_filename}.csv")
HTML_FILE = os.path.join(scan_folder, f"scan_results_{timestamp_filename}.html")
LOG_FILE = os.path.join(scan_folder, f"scan_results_{timestamp_filename}.txt")



def log_result(message, section="General"):
    """
    Writes structured scan results to a log file inside the scan folder.

    Parameters:
    message (str): The text to be written into the log file.
    section (str): The category of the message (e.g., 'Port Scan', 'Banner Grab', 'Nmap Results').
    """
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{timestamp} [{section}]\n{message}\n\n")

    print(f"DEBUG: Log entry added to {LOG_FILE}")  # Prints file location for debugging

def log_to_csv(data):
    """
    Writes scan results to a uniquely named CSV file inside the scan folder.

    Parameters:
    data (list): A list of dictionaries containing scan result data.
    """
    if not data:
        print("DEBUG: No scan results to save!")
        return

    print(f"DEBUG: Writing CSV report to {CSV_FILE}")
    with open(CSV_FILE, mode="w", newline="") as file:
        fieldnames = ["Timestamp", "Target IP", "Port", "Status", "Banner"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for row in data:
            writer.writerow(row)

    print(f"\nCSV report saved inside {scan_folder}")

def log_to_html(data):
    """
    Writes scan results to a uniquely named HTML report inside the scan folder.

    Parameters:
    data (list): A list of dictionaries containing scan result data.
    """
    if not data:
        print("DEBUG: No scan results to save!")
        return

    print(f"DEBUG: Writing HTML report to {HTML_FILE}")  # Confirm filename in output

    with open(HTML_FILE, "w") as file:
        file.write("<html><head><title>ReconX Scan Report</title></head><body>")
        file.write(f"<h2>ReconX Network Scan Report</h2>")
        file.write(f"<p>Scan performed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        file.write("<table border='1'><tr><th>Timestamp</th><th>Target IP</th><th>Port</th><th>Status</th><th>Banner</th></tr>")

        for row in data:
            file.write(f"<tr><td>{row['Timestamp']}</td><td>{row['Target IP']}</td><td>{row['Port']}</td><td>{row['Status']}</td><td>{row['Banner']}</td></tr>")

        file.write("</table></body></html>")

    print(f"\nHTML report saved inside {scan_folder}")

def grab_banner(s):
    """
    Attempts to retrieve a banner from an open port.

    Parameters:
    s (socket): The socket object connected to a target port.

    Returns:
    str: The retrieved banner, or None if unavailable.
    """
    try:
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")  # Basic HTTP request
        banner = s.recv(1024).decode().strip()  # Read banner data
        return banner if banner else "No banner retrieved"
    except Exception:
        return "No banner retrieved"

def scan_port(target, port, scan_results):
    """
    Scans a single port and retrieves results.

    Parameters:
    target (str): The IP address to scan.
    port (int): The port number to check.
    scan_results (list): The list to store scan results.
    """
    try:
        print(f"DEBUG: Checking port {port} on {target}...")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # Increased timeout for better accuracy
        result = s.connect_ex((target, port))

        if result == 0:
            message = f"Port {port} is OPEN on {target}"
            print(message)
            log_result(message, "Port Scan")

            # Banner grabbing for additional information
            banner = grab_banner(s)
            banner_message = f"Banner on port {port}: {banner}"
            print(banner_message)
            log_result(banner_message, "Banner Grab")

            # Append results to existing scan_results list (without reinitializing it)
            scan_results.append({
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Target IP": target,
                "Port": port,
                "Status": "OPEN",
                "Banner": banner
            })

        s.close()

    except Exception as e:
        error_message = f"Error scanning port {port}: {e}"
        print(error_message)
        log_result(error_message)

def scan_target(target, ports):
    """
    Uses multi-threading to scan multiple ports and retrieve banners.

    Parameters:
    target (str): The IP address to scan.
    ports (list): List of ports to check.
    """
    # Initialize structured scan data storage
    scan_results = []  

    # Capture the start time of the scan
    scan_start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nScan started at: {scan_start_time}")
    log_result(f"Scan started at: {scan_start_time}", "Scan Metadata")

    print(f"Scanning {target} with {len(ports)} ports...\n")
    log_result(f"Scanning {target} with {len(ports)} ports...\n", "Port Scan")

    threads = []
    for port in ports:
        print(f"DEBUG: Starting scan for port {port}...")
        t = threading.Thread(target=scan_port, args=(target, port, scan_results))  # Pass scan_results
        threads.append(t)
        t.start()

    for t in threads:
        t.join()  # Ensure all threads complete before proceeding

    scan_with_nmap(target)  # Perform deeper Nmap analysis

    # Capture the end time of the scan
    scan_end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nScan completed at: {scan_end_time}")
    log_result(f"Scan completed at: {scan_end_time}", "Scan Metadata")

    # Save reports AFTER all scans complete
    log_to_csv(scan_results)
    print("\nScan results saved to scan_results.csv")
    log_to_html(scan_results)
    print("\nScan results saved to scan_results.html")

def scan_with_nmap(target):
    """
    Uses Nmap to perform a deeper scan of open ports and services.
    """
    print(f"\nDEBUG: Running Nmap scan on {target}...\n")
    log_result(f"\nRunning Nmap scan on {target}...\n")

    try:
        result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True)
        print(result.stdout)
        log_result(result.stdout, "Nmap Results")  # Logs under "Nmap Results"
    except Exception as e:
        error_message = f"Error running Nmap scan: {e}"
        print(error_message)
        log_result(error_message)

def detect_active_hosts(network_prefix):
    """
    Scans a network range to detect active hosts.

    Parameters:
    network_prefix (str): The first three octets of the network (e.g., '192.168.1')

    Returns:
    list: List of active IP addresses detected.
    """
    print(f"\nScanning network {network_prefix}.x for active hosts...\n")

    active_hosts = []
    for i in range(1, 255):  # Scan IPs from .1 to .254
        ip = f"{network_prefix}.{i}"
        result = subprocess.run(["ping", "-n", "1", "-w", "500", ip], capture_output=True, text=True)

        if "Reply from" in result.stdout:  # If the ping gets a response, the host is active
            print(f"Active host detected: {ip}")
            active_hosts.append(ip)

    return active_hosts

# Entry point of the script
if __name__ == "__main__":
    print("Select mode:")
    print("(1) Scan specific target")
    print("(2) Detect active hosts in a network\n")
    
    scan_choice = input("Enter 1 or 2: ").strip()

    if scan_choice == "1":
        # Prompt user for target IP
        target_ip = input("Enter target IP: ")

        # Prompt user to enter custom ports
        custom_ports_input = input("Enter ports to scan (comma-separated, e.g., 22,80,443): ")
        custom_ports = [int(port.strip()) for port in custom_ports_input.split(",") if port.strip().isdigit()]

        scan_target(target_ip, custom_ports)  # Start scanning

    elif scan_choice == "2":
        # Detect active hosts
        network_prefix = input("Enter first three octets of the network (e.g., 192.168.1): ").strip()
        active_hosts = detect_active_hosts(network_prefix)

        # Display detected hosts
        print("\nActive hosts detected:")
        for host in active_hosts:
            print(host)

    else:
        print("Invalid selection. Please restart the script and enter either 1 or 2.")

    print("\n===== Scan Summary Report =====")
    print(f"Target: {target_ip}")
    print(f"Ports Scanned: {', '.join(map(str, custom_ports))}")

    log_result(f"\n===== Scan Summary Report =====\nTarget: {target_ip}\nPorts Scanned: {', '.join(map(str, custom_ports))}", "Scan Summary")

    print(f"\nScan results saved to {LOG_FILE}")