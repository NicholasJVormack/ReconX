import socket  # Import socket module to handle network connections
import threading  # Import threading for concurrent scanning

def scan_port(target, port):
    """
    Attempts to connect to a target IP on a specific port.
    If successful, it marks the port as open.

    Parameters:
    target (str): The target IP address.
    port (int): The port number to scan.
    """
    try:
        # Create a new socket object for each port scan
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Set timeout for the connection attempt

        # Attempt to connect to the target on the specified port
        result = s.connect_ex((target, port))

        # If connection is successful, the port is open
        if result == 0:
            print(f"Port {port} is OPEN")
        
        # Close the socket to free resources
        s.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")  # Catch and display any errors

def scan_target(target, ports):
    print(f"Scanning {target} with {len(ports)} ports...")

    threads = []
    for port in ports:
        print(f"Checking port {port}...")  # Debugging output
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# Entry point of the script
if __name__ == "__main__":
    # Prompt user for target IP address
    target_ip = input("Enter target IP: ")
    
    # Expanded list of common ports to scan
    common_ports = [22, 80, 443, 3306, 8080, 21, 25, 53, 110, 143]
    
    # Start scanning the target using multi-threading
    scan_target(target_ip, common_ports)