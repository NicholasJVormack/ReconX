# ReconX

## Overview
ReconX is a lightweight vulnerability scanner designed to identify security risks in networks, systems, and web applications. It automates security assessments by detecting open ports, outdated software, and common misconfigurations.
## ReconX GUI Preview  
Here’s a screenshot of the ReconX GUI in action:  
![ReconX GUI](https://raw.githubusercontent.com/NicholasJVormack/ReconX/main/ReconXPicture.png)
## Scope & Objectives
Target Systems:
✔ Web applications, local machines, enterprise networks, IoT devices.
Vulnerability Types:
✔ Open ports, outdated software versions, misconfigurations, weak encryption, default credentials.
Scanning Techniques:
✔ Active & passive reconnaissance using Nmap, requests.
✔ Banner grabbing for fingerprinting service versions.
✔ Packet analysis for deeper insight into network activity.
Report Format:
✔ JSON-based structured results with optional CSV, HTML, and PDF exports.
✔ Clear risk classification of detected vulnerabilities.
Security Considerations:
✔ Compliance with ethical hacking guidelines and industry standards (OWASP, NIST, MITRE ATT&CK).
✔ Zero-touch reconnaissance mode for stealthy scanning operations.


## Features
✔️ Real-time network and system vulnerability scanning
✔️ Open port detection & service enumeration
✔️ Detection of outdated software & insecure configurations
✔️ Interactive GUI for streamlined scanning operations
✔️ Detailed, structured security reports with multi-format export
✔️ Multi-threaded scanning to optimize performance
✔️ Stealth scanning mode to minimize detection risk


## Installation
```sh
git clone https://github.com/NicholasJVormack/ReconX.git
cd ReconX
pip install -r requirements.txt

##Usage
python scanner.py --target 192.168.1.1 --ports 88,443,22

##GUI Version
python src/gui.py

##MIT License

