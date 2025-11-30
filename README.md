# HIDS - Host-based Intrusion Detection System

A Python-based Host Intrusion Detection System (HIDS) that monitors your system for security threats through file integrity monitoring, process analysis, and threat intelligence integration.

## 🔍 Overview

HIDS is a comprehensive security monitoring tool designed to detect suspicious activities on your host system. It provides real-time monitoring of files, processes, and network connections, with an intuitive terminal-based user interface.

### Key Features

- **📁 File Integrity Monitoring**: Track changes to critical files using SHA-256 hashing
- **⚙️ Process Monitoring**: Detect and analyze running processes for malicious behavior
- **🛡️ Threat Intelligence**: Integrate with VirusTotal API for real-time threat detection
- **📊 Log Analysis**: Centralized logging and alert management system
- **🖥️ Terminal UI**: Modern, interactive interface built with Textual
- **🔔 Alert System**: Real-time notifications for security events

## 🏗️ Architecture

The HIDS system is organized into modular components:

```
HIDS/
├── sysmon/          # System monitoring (files & processes)
├── netmon/          # Network monitoring components
├── threat_detector/ # VirusTotal integration & threat analysis
├── log_analysis/    # Alert management and logging
├── database/        # SQLite database for persistent storage
└── UI/              # Terminal user interface
```

### How It Works

1. **File Monitoring**: Uses [`watchdog`](https://github.com/gorakhargosh/watchdog) to monitor filesystem events in real-time. When a file is added to the monitoring list, its SHA-256 hash is stored as a baseline. Any modifications trigger integrity checks.

2. **Process Monitoring**: Leverages [`psutil`](https://github.com/giampaolo/psutil) to track running processes. New processes are queued and examined for malicious indicators by hashing their executables and checking against VirusTotal.

3. **Threat Detection**: Integrates with the VirusTotal API to analyze file hashes, IP addresses, and domains. Uses heuristic rules to determine if an entity is malicious based on vendor detections.

4. **Network Capture**: Uses [`scapy`](https://scapy.net/) for packet capture and analysis (work in progress).

## 📋 Prerequisites

- Python 3.8 or higher
- Linux operating system (tested on Ubuntu/Debian)
- VirusTotal API key (free tier available at [VirusTotal](https://www.virustotal.com/))
- Root/sudo privileges (required for network packet capture)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/HIDS.git
cd HIDS
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate     # On Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```bash
VIRUS_TOTAL=your_virustotal_api_key_here
```

To get a free VirusTotal API key:
1. Sign up at [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Navigate to your profile and copy your API key

### 5. Run the Application

```bash
python3 -m HIDS.main
# or
python3 HIDS/main.py
```

## 🎮 Usage

Once launched, the HIDS terminal UI provides several views:

- **Press 'f'**: File Monitor - Track file integrity and directory monitoring.
- **Press 'p'**: Process Monitor - View running processes and threats
- **Press 'n'**: Network Monitor - Capture and analyze network traffic
- **Press 'l'**: Log Viewer - Review system alerts and events
- **Press 'q'**: Quit the application

### File Monitoring Example

1. Navigate to the File Monitor view
2. Add files or directories to monitor
3. The system will create SHA-256 baselines
4. Any modifications will be detected and reported

### Process Monitoring Example

1. Open the Process Monitor view
2. The system automatically tracks new processes
3. Process executables are hashed and checked against VirusTotal
4. Malicious processes trigger high-priority alerts

## 🔧 Core Python Libraries

### Security & System Monitoring

- **[psutil](https://github.com/giampaolo/psutil) (7.1.3)**: Cross-platform library for retrieving information on running processes and system utilization. Used for process monitoring and examination.

- **[watchdog](https://github.com/gorakhargosh/watchdog) (6.0.0)**: Python API and shell utilities to monitor filesystem events. Powers the real-time file integrity monitoring system.

- **[scapy](https://scapy.net/) (2.6.1)**: Powerful interactive packet manipulation program. Used for network packet capture and analysis.


### User Interface

- **[textual](https://github.com/Textualize/textual) (1.14.0)**: Modern framework for building sophisticated terminal user interfaces. Powers the entire HIDS UI.

- **[Pygments](https://pygments.org/) (2.19.2)**: Syntax highlighting library. Used for colorizing log output and code snippets.



## 🗄️ Database Schema

The system uses SQLite for persistent storage with the following main tables:

- `file_monitoring`: Stores file paths, names, and baseline hashes
- `alerts`: Logs security events and notifications
- `process_cache`: Caches process information for performance

## ⚠️ Current Limitations

- **Network Monitoring**: The [`network_mon.py`](HIDS/netmon/network_mon.py) module is currently incomplete. While packet capture functionality exists in the UI layer, the core network analysis logic is not yet implemented.

- **VirusTotal Rate Limits**: Free tier API keys have rate limits (4 requests/minute). The system implements rate limiting but may experience delays.

- **Platform Support**: Primarily tested on Linux. Some features may not work on Windows or macOS.


## NOTE!!

1. **Root Privileges**: Network packet capture requires root/sudo access.   
2.**Alert Monitoring**: Regularly review the alert log for security events.

