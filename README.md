# Python Virus Scanner Tool 🔍🛡️

![Python Version](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A lightweight, cross-platform security scanner for detecting system vulnerabilities, suspicious activities, and performance issues. Designed for both educational and practical use.

---

## Features ✨
- **Rootkit Detection**: Identify hidden processes using PID cross-checking.
- **Network Traffic Monitoring**: Flag connections to known malicious IP addresses.
- **Dynamic App Permission Checks**: Scan installed apps for suspicious write permissions and network activity (Windows-only).
- **OS Version & Update Checks**: Warn about outdated operating systems.
- **Disk Space Monitoring**: Alert on low disk space across partitions.
- **CPU/Memory Usage Tracking**: Detect resource-heavy processes.
- **Open Port Detection**: List open ports with security warnings.
- **Scheduled Scans**: Run daily/weekly scans automatically.
- **Colorful UI**: Animated banners, loading spinners, and color-coded alerts.
- **Report Generation**: Save scan results to `scan_report.txt`.

---

## Installation 🛠️

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/python-virus-scanner.git
   cd python-virus-scanner
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt

