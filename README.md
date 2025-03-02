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
   _Requirements:_
   ```bash
   plaintext
   Copy
   psutil
   colorama
   schedule

## Usage 🚀

Run the tool:
```bash
python virus.py
```

**Menu Options**:  
1. **One-Time Scan**: Immediate full system check.  
2. **Daily Scan**: Automated scans daily at 3:00 AM.  
3. **Weekly Scan**: Scans every Monday at 3:00 AM.  

**Output**:  
- Real-time alerts in the console (color-coded warnings).  
- Detailed logs in `security_scan.log`.  
- Scan summary in `scan_report.txt`.  

![Untitled design](https://github.com/user-attachments/assets/620e6c99-ce12-4ac9-b1fc-68c533542775)

---

## Scheduled Scans ⏰  
To stop scheduled scans, press `Ctrl+C`. The tool will exit gracefully.

---

## Report Format 📄  
Example `scan_report.txt`:  
```plaintext
Scan Report - Thu Oct 5 12:00:00 2023
OS Version: Windows 10
Suspicious Processes: ["trojan.exe", "malware_app"]
Disk Space: C:\ (15 GiB free, 9.5%)
Open Ports: 80, 443, 8080
```

---

## Contributing 🤝  
Contributions are welcome!  
1. Fork the repository.  
2. Create a feature branch (`git checkout -b feature/your-feature`).  
3. Commit changes (`git commit -m 'Add some feature'`).  
4. Push to the branch (`git push origin feature/your-feature`).  
5. Open a Pull Request.

---

## License 📜  
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Notes ⚠️  
- **Windows-Centric Features**: Dynamic app checks rely on PowerShell and Windows directories.  
- **Known Malware Signatures**: Includes test signatures like `eicar.com` (non-executable).  
- **Customize Bad IPs**: Update `known_bad_ips` in `virus.py` for your environment.

---

**Crafted with ❤️ by Yogendra Badu**  
*Credit to `psutil`, `colorama`, and `schedule` libraries.*
``` 
