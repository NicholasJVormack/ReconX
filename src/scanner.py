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

def scan_port(target, port):
    """
    Scans a single port on a target IP using a basic socket connection.
    If successful, marks the port as open and logs the result.

    Parameters:
    target (str): The IP address to scan.
    port (int): The port number to check.
    """
    try:
        print(f"DEBUG: Checking port {port} on {target}...")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # Increased timeout for better accuracy
        result = s.connect_ex((target, port))

        if result == 0:
            message = f"Port {port} is OPEN on {target}"
            print(message)
            log_result(message)

            # Banner grabbing for additional information
            banner = grab_banner(s)
            banner_message = f"Banner on port {port}: {banner}"
            print(banner_message)
            log_result(banner_message)

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
    print(f"Scanning {target} with {len(ports)} ports...\n")
    log_result(f"Scanning {target} with {len(ports)} ports...\n")

    threads = []
    for port in ports:
        print(f"DEBUG: Starting scan for port {port}...")
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    scan_with_nmap(target)

def scan_with_nmap(target):
    """
    Uses Nmap to perform a deeper scan of open ports and services.
    """
    print(f"\nDEBUG: Running Nmap scan on {target}...\n")
    log_result(f"\nRunning Nmap scan on {target}...\n")

    try:
        result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True)
        print(result.stdout)
        log_result(result.stdout)
    except Exception as e:
        error_message = f"Error running Nmap scan: {e}"
        print(error_message)
        log_result(error_message)

# Entry point of the script
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")  # Prompt user for target IP

    common_ports = [22, 80, 443, 3306, 8080, 21, 25, 53, 110, 143]

    scan_target(target_ip, common_ports)

    print("\nScan results saved to scan_results.txt")