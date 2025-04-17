# ReconX

## Overview
ReconX is a lightweight vulnerability scanner designed to identify security risks in networks, systems, and web applications. It automates security assessments by detecting open ports, outdated software, and common misconfigurations.

## Scope & Objectives
- **Target Systems:** Web applications, local machines, and networks.
- **Vulnerability Types:** Open ports, outdated software versions, misconfigurations.
- **Scanning Techniques:** Using `nmap`, `requests`, and `scapy` for analysis.
- **Report Format:** JSON-based results with optional PDF export.
- **Security Considerations:** Compliance with ethical hacking guidelines.

## Features
✔️ Network and system vulnerability scanning  
✔️ Open port detection  
✔️ Identification of outdated software  
✔️ Detailed security reports  

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

