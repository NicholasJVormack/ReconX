 
# Architecture Overview

## System Components
ReconX consists of the following key modules:

### 1. Scanning Engine
- Performs network reconnaissance and vulnerability checks.
- Uses `nmap` for open port detection and `requests` for web analysis.
- Multi-threaded scanning for efficiency.

### 2. Report Generator
- Formats scan results into JSON and optional PDF reports.
- Highlights security risks with severity levels.

### 3. Configuration Management
- Stores user-defined scan parameters.
- Allows exclusions for specific IPs or ports.

### 4. CLI Interface
- Command-line tool for users to interact with ReconX.
- Supports flags for custom scan options.

## Workflow Diagram *(To be added later)*