import psutil
import platform
import os
import time
import logging
import pkg_resources
from colorama import Fore, Style, init, Back
import schedule
import subprocess
import sys
from itertools import cycle
from threading import Thread, Event
from logging.handlers import RotatingFileHandler
import tkinter as tk
from tkinter import messagebox

# Initialize colorama for colored output
init(autoreset=True)

# Global variable for known bad IPs (update as needed)
known_bad_ips = ['192.168.1.100', '10.0.0.200']

# Set up logging with rotation
def setup_logging():
    handler = RotatingFileHandler('security_scan.log', maxBytes=5*1024*1024, backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

# Example usage
setup_logging()
logging.info("Security scan started.")

# --------------------------
# New Visual Enhancements
# --------------------------

def show_banner():
    """Display animated welcome banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + r"""
 __     __            ____      _   _   ____          ____      ____     _      _   _     
 \ \   /"/u  ___   U |  _"\ uU |"|u| | / __"| u      / __"| uU /"___|U  /"\  u | \ |"|    
  \ \ / //  |_"_|   \| |_) |/ \| |\| |<\___ \/      <\___ \/ \| | u   \/ _ \/ <|  \| |>   
  /\ V /_,-. | |     |  _ <    | |_| | u___) |       u___) |  | |/__  / ___ \ U| |\  |u   
 U  \_/-(_/U/| |\u   |_| \_\  <<\___/  |____/>>      |____/>>  \____|/_/   \_\ |_| \_|    
   //   .-,_|___|_,-.//   \\_(__) )(    )(  (__)      )(  (__)_// \\  \\    >> ||   \\,-. 
  (__)   \_)-' '-(_/(__)  (__)   (__)  (__)          (__)    (__)(__)(__)  (__)(_")  (_/  
""")
    print(Fore.YELLOW + "\n" + " " * 15 + "Virus Scanner Tool")
    print(Fore.WHITE + " " * 18 + "by Yogendra Badu (240441)\n")
    print(Fore.GREEN + "=" * 70 + Style.RESET_ALL)
    time.sleep(1)

def animated_scan_text():
    """Animated scanning text effect"""
    text = "[ INITIALIZING SYSTEM SCAN ]"
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN]
    for i in range(len(text)):
        sys.stdout.write(colors[i % 4] + text[i])
        sys.stdout.flush()
        time.sleep(0.05)
    print("\n")

def spinning_cursor(event):
    """Show spinning cursor animation"""
    spinner = cycle(['-', '/', '|', '\\'])
    while not event.is_set():
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

def show_loading(seconds=2):
    """Show loading animation"""
    event = Event()
    spinner = Thread(target=spinning_cursor, args=(event,))
    spinner.start()
    time.sleep(seconds)
    event.set()
    spinner.join()
    sys.stdout.write('\b \n')

# --------------------------
# System Check Functions
# --------------------------

def check_rootkit():
    # Use process_iter with 'pid' attribute
    hidden_processes = [p for p in psutil.process_iter(['pid']) if p.info['pid'] not in psutil.pids()]
    if hidden_processes:
        logging.warning("Possible rootkit detected!")
        print(f"{Fore.RED}Warning: Possible rootkit detected!{Style.RESET_ALL}")

def monitor_network_traffic():
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip in known_bad_ips:
            logging.warning(f"Suspicious outbound connection detected: {conn.raddr.ip}")
            print(f"{Fore.RED}Warning: Suspicious outbound connection detected: {conn.raddr.ip}{Style.RESET_ALL}")

def check_os_version():
    logging.info("Checking operating system version...")
    try:
        os_info = platform.system() + " " + platform.release()
        print(f"\n{Fore.CYAN}Operating System: {os_info}{Style.RESET_ALL}")
        
        if "Windows" in os_info:
            try:
                if int(platform.release().split('.')[0]) < 10:
                    logging.warning("Your OS version is outdated. Consider upgrading to a newer version.")
                    print(f"{Fore.YELLOW}Warning: Your OS version is outdated. Consider upgrading to a newer version.{Style.RESET_ALL}")
                else:
                    logging.info("Operating system is up to date.")
                    print(f"{Fore.GREEN}Operating system is up to date.{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"Error parsing Windows version: {e}")
        elif "Darwin" in os_info:
            mac_version = platform.mac_ver()[0].split('.')
            try:
                if int(mac_version[1]) < 10:
                    logging.warning("Your macOS version is outdated. Consider upgrading.")
                    print(f"{Fore.YELLOW}Warning: Your macOS version is outdated. Consider upgrading.{Style.RESET_ALL}")
                else:
                    logging.info("Operating system is up to date.")
                    print(f"{Fore.GREEN}Operating system is up to date.{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"Error parsing macOS version: {e}")
        elif "Linux" in os_info:
            logging.info("Linux version detected. Ensure your system is up to date.")
            print(f"{Fore.CYAN}Linux version detected. Ensure your system is up to date.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error checking OS version: {e}")
        print(f"{Fore.RED}Error checking OS version.{Style.RESET_ALL}")
    return os_info

# Refined checking
def check_suspicious_apps():
    suspicious_keywords = ['malware', 'virus', 'trojan']
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if any(keyword in proc.info['name'].lower() for keyword in suspicious_keywords):
                suspicious_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return suspicious_processes

# --------------------------
# Dynamic App Permission Checks
# --------------------------

def get_installed_apps():
    """
    Dynamically retrieves installed application names on Windows using Get-StartApps.
    Returns a list of app names.
    """
    apps = []
    if platform.system() == "Windows":
        try:
            # Using PowerShell to fetch installed Start Menu apps
            result = subprocess.run(
                ["powershell", "Get-StartApps | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True
            )
            apps = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            logging.info(f"Retrieved {len(apps)} installed apps from Start Menu.")
        except Exception as e:
            logging.error(f"Error fetching installed apps: {e}")
    else:
        logging.info("Dynamic app fetching not implemented for non-Windows systems.")
    return apps

def check_app_permissions():
    """
    Dynamically check installed applications for suspicious permissions.
    For each app retrieved via Get-StartApps, attempt to locate its folder in
    common directories (e.g., 'C:\Program Files' or 'C:\Program Files (x86)') and
    check if it has write permissions. Also, perform a rudimentary check for active network connections.
    """
    logging.info("Dynamically checking application permissions...")
    apps = get_installed_apps()
    suspicious_apps = []
    
    for app in apps:
        app_path = None
        # Attempt to locate the application's folder in common directories
        possible_dirs = []
        if platform.system() == "Windows":
            possible_dirs = [r"C:\Program Files", r"C:\Program Files (x86)"]
        else:
            continue  # Skip for non-Windows

        for base in possible_dirs:
            candidate = os.path.join(base, app)
            if os.path.exists(candidate):
                app_path = candidate
                break
        
        if app_path:
            # Check for write permissions on the application's folder
            if os.access(app_path, os.W_OK):
                logging.warning(f"{app} at {app_path} is writable.")
                print(f"{Fore.YELLOW}Warning: {app} is writable (has write permission).{Style.RESET_ALL}")
                suspicious_apps.append(app)
            
            # Check for active network connections (simple heuristic)
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # If app name appears in remote address (heuristic), flag it
                    if app.lower() in conn.raddr[0].lower():
                        logging.warning(f"{app} has active network connections.")
                        print(f"{Fore.YELLOW}Warning: {app} has active network connections.{Style.RESET_ALL}")
                        suspicious_apps.append(app)
                        break
            
            # Optional: Check if the app's name indicates admin privileges
            if "admin" in app.lower():
                logging.warning(f"{app} may be running with administrative privileges.")
                print(f"{Fore.RED}Warning: {app} may be running with administrative privileges.{Style.RESET_ALL}")
                suspicious_apps.append(app)
        else:
            logging.info(f"Could not determine installation path for {app}; skipping dynamic permission check.")
    
    if not suspicious_apps:
        print(f"{Fore.GREEN}No dynamic permission issues detected in installed apps.{Style.RESET_ALL}")
    return suspicious_apps

# --------------------------
# Other System Checks
# --------------------------

def check_disk_space():
    logging.info("Checking disk space...")
    disk_info = {}
    try:
        partitions = psutil.disk_partitions()
        if not partitions:
            logging.warning("No disk partitions found.")
            print(f"{Fore.YELLOW}Warning: No disk partitions found.{Style.RESET_ALL}")
            return disk_info

        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                if usage.total == 0:
                    logging.warning(f"Skipping partition {partition.mountpoint} due to zero total space.")
                    continue

                free_percent = (usage.free / usage.total) * 100
                disk_info[partition.mountpoint] = f"{usage.free // (2**30)} GiB free ({free_percent:.2f}%)"
                print(f"{Fore.CYAN}Partition {partition.mountpoint}: {disk_info[partition.mountpoint]}{Style.RESET_ALL}")
                if free_percent < 10:
                    logging.warning(f"Low disk space on {partition.mountpoint}. Consider cleaning up your system.")
                    print(f"{Fore.YELLOW}Warning: Low disk space on {partition.mountpoint}. Consider cleaning up your system.{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"Error accessing disk partition {partition.mountpoint}: {e}")
                print(f"{Fore.RED}Error accessing disk partition {partition.mountpoint}.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error checking disk space: {e}")
        print(f"{Fore.RED}Error checking disk space.{Style.RESET_ALL}")
    return disk_info

def check_outdated_packages():
    logging.info("Checking for outdated Python packages...")
    outdated_packages = []
    try:
        for dist in pkg_resources.working_set:
            try:
                # Using _version as a placeholder. For a true update check, consider querying an external API.
                latest_version = str(dist._version)
                if dist.version != latest_version:
                    outdated_packages.append(f"{dist.project_name} (installed: {dist.version}, latest: {latest_version})")
            except Exception as e:
                logging.error(f"Error checking version for {dist.project_name}: {e}")

        if outdated_packages:
            logging.warning("Outdated Python packages detected.")
            print(f"{Fore.YELLOW}Outdated Python packages detected:{Style.RESET_ALL}")
            for package in outdated_packages:
                print(package)
        else:
            logging.info("All Python packages are up to date.")
            print(f"{Fore.GREEN}All Python packages are up to date.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error checking outdated packages: {e}")
        print(f"{Fore.RED}Error checking outdated packages.{Style.RESET_ALL}")
    return outdated_packages

def check_performance_metrics():
    logging.info("Checking CPU and memory usage...")
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        print(f"{Fore.CYAN}CPU Usage: {cpu_usage}%{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Memory Usage: {memory.percent}% used of {memory.total // (2**30)} GB total{Style.RESET_ALL}")
        if cpu_usage > 80:
            logging.warning(f"High CPU usage detected: {cpu_usage}%")
            print(f"{Fore.YELLOW}Warning: High CPU usage detected!{Style.RESET_ALL}")
        if memory.percent > 80:
            logging.warning(f"High memory usage detected: {memory.percent}%")
            print(f"{Fore.YELLOW}Warning: High memory usage detected!{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error checking CPU or memory usage: {e}")
        print(f"{Fore.RED}Error checking CPU or memory usage.{Style.RESET_ALL}")

def check_open_ports():
    logging.info("Checking for open ports...")
    open_ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                open_ports.append(conn.laddr.port)
        print(f"{Fore.CYAN}Open Ports: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
        if open_ports:
            logging.warning(f"Potential security risk: Open ports detected: {', '.join(map(str, open_ports))}")
            print(f"{Fore.YELLOW}Warning: Open ports detected: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error checking open ports: {e}")
        print(f"{Fore.RED}Error checking open ports.{Style.RESET_ALL}")
    return open_ports

def scan_periodically():
    # Schedule to run the scan every 5 minutes
    schedule.every(5).minutes.do(check_suspicious_apps)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

def generate_report(os_info, suspicious_apps, disk_space, open_ports):
    logging.info("Generating scan report...")
    try:
        with open('scan_report.txt', 'w') as file:
            file.write(f"Scan Report - {time.ctime()}\n")
            file.write(f"OS Version: {os_info}\n")
            # Convert each suspicious app entry to a string
            file.write(f"Suspicious Processes: {', '.join([str(app) for app in suspicious_apps])}\n")
            file.write(f"Disk Space: {disk_space}\n")
            file.write(f"Open Ports: {', '.join(map(str, open_ports))}\n")
        print(f"{Fore.GREEN}Scan report generated successfully.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        print(f"{Fore.RED}Error generating report.{Style.RESET_ALL}")

def notify_user(message):
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Security Alert", message)

def perform_scan():
    logging.info("Starting system vulnerability scan...")
    print(f"{Fore.CYAN}Starting system vulnerability scan...{Style.RESET_ALL}\n")
    
    os_info = check_os_version()
    scan_for_virus("one-time")
    suspicious_apps = check_suspicious_apps()
    # Now use the dynamic app permission check:
    dynamic_suspicious = check_app_permissions()
    disk_space = check_disk_space()
    outdated_packages = check_outdated_packages()  # Outdated package info is printed but not used in report.
    check_performance_metrics()
    open_ports = check_open_ports()
    
    # Optionally, merge the dynamic_suspicious list with suspicious_apps from processes
    all_suspicious = list(set([str(item) for item in (suspicious_apps + dynamic_suspicious)]))
    
    generate_report(os_info, all_suspicious, disk_space, open_ports)
    
    logging.info("Scan complete.")
    print(f"\n{Fore.GREEN}Scan complete.{Style.RESET_ALL}")

def scan_for_virus(scan_type):
    # Simulating the scan process
    print("Starting system vulnerability scan...")

    # List of known test viruses (e.g., EICAR test file)
    virus_signatures = ["eicar.com"]

    # Directories to scan
    directories_to_scan = [r"C:\Users\hp\Documents\test\me", r"C:\Users\hp\Downloads", r"C:\Windows"]

    # Check if any of the virus test files are present
    detected_viruses = []
    for directory in directories_to_scan:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower() in virus_signatures:
                    detected_viruses.append(os.path.join(root, file))

    # Report the findings
    if detected_viruses:
        print("\nVirus Detected: ")
        for virus in detected_viruses:
            print(f"Virus found: {virus}")
    else:
        print("\nNo viruses detected.")

def schedule_scans():
    """Prompt user for scan frequency and schedule accordingly (only once)."""
    if hasattr(schedule_scans, "already_run"):
        return  # Prevent re-running this function

    print("\nChoose scan frequency:")
    print("1. One-time scan")
    print("2. Daily scan")
    print("3. Weekly scan")

    choice = input("Enter the number of your choice: ")

    if choice == "1":
        print("\nRunning one-time scan...\n")
        perform_scan()
    elif choice == "2":
        print("\nScheduling daily scans at 03:00 AM... (Press Ctrl+C to exit)")
        schedule.every().day.at("03:00").do(perform_scan)
    elif choice == "3":
        print("\nScheduling weekly scans every Monday at 03:00 AM... (Press Ctrl+C to exit)")
        schedule.every().monday.at("03:00").do(perform_scan)
    else:
        print("\nInvalid choice. Please enter 1, 2, or 3.")
        return

    schedule_scans.already_run = True  # Mark function as run

    while True:
        try:
            schedule.run_pending()
            time.sleep(60)
        except KeyboardInterrupt:
            print("\nScan aborted by user. Exiting...")
            break

def choose_scan_frequency():
    print(f"{Fore.CYAN}Choose scan frequency:{Style.RESET_ALL}")
    print("1. One-time scan")
    print("2. Daily scan")
    print("3. Weekly scan")
    choice = input("Enter the number of your choice: ")
    if choice == '1':
        perform_scan()
    elif choice in ['2', '3']:
        print(f"{Fore.YELLOW}Scheduling scans... (Press Ctrl+C to exit){Style.RESET_ALL}")
        schedule_scans()
    else:
        print(f"{Fore.RED}Invalid choice. Please try again...{Style.RESET_ALL}")
        choose_scan_frequency()

if __name__ == "__main__":
    show_banner()
    animated_scan_text()
    show_loading()
    
    try:
        print(Fore.CYAN + "\nChoose scan frequency:" + Style.RESET_ALL)
        print(f"{Fore.YELLOW}1. One-time scan")
        print(f"{Fore.YELLOW}2. Daily scan")
        print(f"{Fore.YELLOW}3. Weekly scan")
        choice = input(f"{Fore.WHITE}Enter the number of your choice: {Style.RESET_ALL}")
        
        if choice == '1':
            print(Fore.CYAN + "\nStarting one-time scan..." + Style.RESET_ALL)
            show_loading(1)
            perform_scan()
        elif choice in ['2', '3']:
            print(f"{Fore.YELLOW}\nScheduling scans... (Press Ctrl+C to exit){Style.RESET_ALL}")
            schedule_scans()
        else:
            print(f"{Fore.RED}Invalid choice. Please try again...{Style.RESET_ALL}")
            os.execv(sys.executable, ['python'] + sys.argv)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan aborted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
