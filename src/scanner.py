import socket  # Handles basic network connections
import threading  # Enables multi-threading for faster port scanning
import subprocess  # Runs external Nmap scans

# Define log file name
LOG_FILE = "scan_results.txt"

def log_result(message):
    """
    Writes scan results to a log file.

    Parameters:
    message (str): The text to be written into the log file.
    """
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")

def scan_port(target, port):
    """
    Scans a single port on a target IP using a basic socket connection.
    If successful, marks the port as open and logs the result.

    Parameters:
    target (str): The IP address to scan.
    port (int): The port number to check.
    """
    try:
        # Print debug message to show progress
        print(f"DEBUG: Checking port {port} on {target}...")

        # Create a socket for the scan
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Set timeout to prevent long waits

        result = s.connect_ex((target, port))  # Attempt connection

        if result == 0:
            message = f"Port {port} is OPEN on {target}"
            print(message)
            log_result(message)  # Log the open port result

        s.close()  # Close socket to free resources
    except Exception as e:
        error_message = f"Error scanning port {port}: {e}"
        print(error_message)
        log_result(error_message)  # Log errors

def scan_target(target, ports):
    """
    Uses multi-threading to scan multiple ports on a target IP simultaneously.
    Also triggers an Nmap scan for deeper insights.

    Parameters:
    target (str): The IP address to scan.
    ports (list): List of ports to check.
    """
    print(f"Scanning {target} with {len(ports)} ports...\n")
    log_result(f"Scanning {target} with {len(ports)} ports...\n")

    # Create and start a thread for each port scan
    threads = []
    for port in ports:
        print(f"DEBUG: Starting scan for port {port}...")
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

    # Ensure all threads finish before continuing
    for t in threads:
        t.join()

    # After basic scanning, run an Nmap scan for deeper insights
    scan_with_nmap(target)

def scan_with_nmap(target):
    """
    Performs an advanced scan on a target IP using Nmap and logs the results.

    Parameters:
    target (str): The IP address to scan.
    
    Nmap will check for:
    - Open ports
    - Running services
    - Additional security details
    """
    print(f"\nDEBUG: Running Nmap scan on {target}...\n")
    log_result(f"\nRunning Nmap scan on {target}...\n")

    try:
        # Execute Nmap to detect open ports and services
        result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True)

        # Print and log the scan results
        print(result.stdout)
        log_result(result.stdout)

    except Exception as e:
        error_message = f"Error running Nmap scan: {e}"
        print(error_message)
        log_result(error_message)

# Entry point of the script
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")  # Prompt user for target IP
    
    # Expanded list of common ports to scan
    common_ports = [22, 80, 443, 3306, 8080, 21, 25, 53, 110, 143]
    
    # Start scanning process
    scan_target(target_ip, common_ports)

    print("\nScan results saved to scan_results.txt")