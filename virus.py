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
import threading
from tkinter import simpledialog

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
# GUI Setup
# --------------------------
root=None #GLobal variable

def create_gui():
    """Create the main application window with a button to start the scan."""
    global root
    root = tk.Tk()
    root.title("Virus Scanner Tool")
    
    # Set up window size and layout
    root.geometry("400x300")
    root.config(bg="white")

    # Create a Label for the title
    label = tk.Label(root, text="Virus Scanner Tool", font=("Arial", 16), fg="blue", bg="white")
    label.pack(pady=20)

    # Create a button to start scanning
    start_button = tk.Button(root, text="Start Scan", font=("Arial", 12), command=start_scan)
    start_button.pack(pady=20)
    
    add_results_text_box(root)
    # Start the GUI loop
    root.mainloop()

def add_results_text_box(root):
    global result_text
    result_text = tk.Text(root, height=15, width=70)
    result_text.pack(pady=10)

# --------------------------
# Scan Start Function
# --------------------------

def start_scan():
    """Start the security scan and display results in a Tkinter text box."""
    
    # Start scan checks in separate threads
    threading.Thread(target=run_security_checks).start()

def run_security_checks():
    """Run security checks and update the GUI with results."""
    check_rootkit()
    monitor_network_traffic()
    os_info = check_os_version()
    suspicious_apps = check_suspicious_apps()
    disk_info = check_disk_space()

    # After scan completes, show a message box
    messagebox.showinfo("Scan Completed", "Security scan completed successfully!")
# --------------------------
# Display Results in GUI
# --------------------------

def update_gui_results(results):
    root.after(0, _update_gui, results)  # Execute in main thread

def _update_gui(results):
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, results)

def add_results_text_box(root):
    """Add a text box to the GUI window to display results."""
    global result_text
    result_text = tk.Text(root, height=10, width=50)
    result_text.pack(pady=10)

# --------------------------
# System Check Functions
# --------------------------

def check_rootkit():
    """Check for hidden rootkit processes and display results in GUI."""
    hidden_processes = [p for p in psutil.process_iter(['pid']) if p.info['pid'] not in psutil.pids()]
    if hidden_processes:
        result = f"{Fore.RED}Warning: Possible rootkit detected!{Style.RESET_ALL}"
    else:
        result = "No rootkit detected."
    
    update_gui_results(result)  # Update the GUI with the result

def monitor_network_traffic():
    suspicious_traffic = []
    for connection in psutil.net_connections(kind='inet'):
        if connection.status == 'ESTABLISHED' and connection.raddr:
            if connection.raddr.ip in known_bad_ips:
                suspicious_traffic.append(f"Connection to known bad IP: {connection.raddr.ip}")
    
    if suspicious_traffic:
        result = "\n".join(suspicious_traffic)
    else:
        result = "No suspicious network traffic detected."
    
    update_gui_results(result)

def check_os_version():
    """Check the operating system version and display the result in the GUI."""
    update_gui_results("Checking operating system version...")  # Display status in GUI
    try:
        os_info = platform.system() + " " + platform.release()
        result = f"Operating System: {os_info}"

        if "Windows" in os_info:
            try:
                if int(platform.release().split('.')[0]) < 10:
                    logging.warning("Your OS version is outdated. Consider upgrading to a newer version.")
                    result += f"\n{Fore.YELLOW}Warning: Your OS version is outdated. Consider upgrading to a newer version.{Style.RESET_ALL}"
                else:
                    logging.info("Operating system is up to date.")
                    result += f"\n{Fore.GREEN}Operating system is up to date.{Style.RESET_ALL}"
            except Exception as e:
                logging.error(f"Error parsing Windows version: {e}")
                result += f"\n{Fore.RED}Error parsing Windows version.{Style.RESET_ALL}"
        elif "Darwin" in os_info:
            mac_version = platform.mac_ver()[0].split('.')
            try:
                if int(mac_version[1]) < 10:
                    logging.warning("Your macOS version is outdated. Consider upgrading.")
                    result += f"\n{Fore.YELLOW}Warning: Your macOS version is outdated. Consider upgrading.{Style.RESET_ALL}"
                else:
                    logging.info("Operating system is up to date.")
                    result += f"\n{Fore.GREEN}Operating system is up to date.{Style.RESET_ALL}"
            except Exception as e:
                logging.error(f"Error parsing macOS version: {e}")
                result += f"\n{Fore.RED}Error parsing macOS version.{Style.RESET_ALL}"
        elif "Linux" in os_info:
            logging.info("Linux version detected. Ensure your system is up to date.")
            result += f"\n{Fore.CYAN}Linux version detected. Ensure your system is up to date.{Style.RESET_ALL}"

        update_gui_results(result)  # Update the GUI with the result
    except Exception as e:
        logging.error(f"Error checking OS version: {e}")
        update_gui_results(f"{Fore.RED}Error checking OS version.{Style.RESET_ALL}")  # Update the GUI with error
    return os_info

# Refined checking
def check_suspicious_apps():
    """Check for suspicious processes with known malware/virus keywords and display the result in the GUI."""
    suspicious_keywords = ['malware', 'virus', 'trojan']
    suspicious_processes = []

    update_gui_results("Checking for suspicious processes...")  # Update status in GUI

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Check if any suspicious keyword is in the process name
            if any(keyword in proc.info['name'].lower() for keyword in suspicious_keywords):
                suspicious_processes.append(proc.info)
                logging.warning(f"Suspicious process found: {proc.info['name']} (PID: {proc.info['pid']})")
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            # Handle processes that are no longer available, inaccessible, or zombie
            logging.debug(f"Error accessing process {proc.info['pid']}: {str(e)}")
            continue
    
    if suspicious_processes:
        result = f"\nSuspicious processes detected:\n"
        for proc in suspicious_processes:
            result += f"Process: {proc['name']} (PID: {proc['pid']})\n"
        update_gui_results(result)  # Update the GUI with suspicious processes found
    else:
        update_gui_results("No suspicious processes found.")  # Update GUI with no suspicious processes
    
    return suspicious_processes

# --------------------------
# Dynamic App Permission Checks
# --------------------------

def get_installed_apps():
    """
    Dynamically retrieves installed application names on Windows using Get-StartApps.
    Returns a list of app names and updates the GUI accordingly.
    """
    apps = []

    update_gui_results("Retrieving installed applications...")  # Update status in GUI

    if platform.system() == "Windows":
        try:
            # Using PowerShell to fetch installed Start Menu apps
            logging.info("Fetching installed apps using PowerShell...")
            result = subprocess.run(
                ["powershell", "Get-StartApps | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                apps = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                logging.info(f"Successfully retrieved {len(apps)} installed apps from the Start Menu.")
                
                # Update GUI with the list of apps
                if apps:
                    result_str = f"\n{len(apps)} Installed applications:\n" + "\n".join(apps)
                    update_gui_results(result_str)
                else:
                    update_gui_results("No applications found.")
            else:
                logging.error(f"PowerShell command failed with return code {result.returncode}.")
                update_gui_results("Failed to retrieve installed apps.")
        except subprocess.SubprocessError as e:
            logging.error(f"Subprocess error while fetching installed apps: {e}")
            update_gui_results(f"Error fetching installed apps: {str(e)}")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            update_gui_results(f"Unexpected error: {str(e)}")
    else:
        logging.info("Dynamic app fetching is only implemented for Windows systems.")
        update_gui_results("Dynamic app fetching is not implemented for non-Windows systems.")

    return apps

def check_app_permissions():
    """
    Dynamically check installed applications for suspicious permissions.
    For each app retrieved via Get-StartApps, attempts to locate its folder in
    common directories (e.g., 'C:\Program Files' or 'C:\Program Files (x86)') and
    checks if it has write permissions. Also, performs a rudimentary check for active network connections.
    """
    update_gui_results("Checking application permissions...")  # Update the GUI with status

    logging.info("Dynamically checking application permissions...")
    apps = get_installed_apps()
    suspicious_apps = []

    if not apps:
        update_gui_results("No applications found to check permissions.")  # Update GUI if no apps found
        return suspicious_apps

    for app in apps:
        app_path = None
        possible_dirs = []

        if platform.system() == "Windows":
            possible_dirs = [r"C:\Program Files", r"C:\Program Files (x86)"]
        else:
            continue  # Skip for non-Windows platforms

        for base in possible_dirs:
            candidate = os.path.join(base, app)
            if os.path.exists(candidate):
                app_path = candidate
                break

        if app_path:
            app_warning = []

            # Check for write permissions on the application's folder
            if os.access(app_path, os.W_OK):
                warning_msg = f"{app} at {app_path} is writable."
                logging.warning(warning_msg)
                app_warning.append(warning_msg)
                suspicious_apps.append(app)

            # Check for active network connections (simple heuristic)
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    if app.lower() in conn.raddr[0].lower():
                        warning_msg = f"{app} has active network connections."
                        logging.warning(warning_msg)
                        app_warning.append(warning_msg)
                        suspicious_apps.append(app)
                        break

            # Optional: Check if the app's name indicates admin privileges
            if "admin" in app.lower():
                warning_msg = f"{app} may be running with administrative privileges."
                logging.warning(warning_msg)
                app_warning.append(warning_msg)
                suspicious_apps.append(app)

            if app_warning:
                update_gui_results("\n".join(app_warning))  # Update GUI with app-specific warnings

        else:
            logging.info(f"Could not determine installation path for {app}; skipping dynamic permission check.")
            update_gui_results(f"Could not determine installation path for {app}.")

    if not suspicious_apps:
        update_gui_results(f"{Fore.GREEN}No dynamic permission issues detected in installed apps.{Style.RESET_ALL}")
    return suspicious_apps

# --------------------------
# Other System Checks
# --------------------------

def check_disk_space():
    """
    Check disk space across all partitions and update GUI and log the results.
    Warns about partitions with low disk space (less than 10% free).
    """
    update_gui_results("Checking disk space...")  # Update GUI with the status of the check
    
    logging.info("Checking disk space...")
    disk_info = {}
    
    try:
        partitions = psutil.disk_partitions()
        if not partitions:
            update_gui_results(f"{Fore.YELLOW}Warning: No disk partitions found.{Style.RESET_ALL}")  # Update GUI
            logging.warning("No disk partitions found.")
            return disk_info

        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                
                if usage.total == 0:
                    logging.warning(f"Skipping partition {partition.mountpoint} due to zero total space.")
                    continue

                # Calculate free space as a percentage
                free_percent = (usage.free / usage.total) * 100
                free_space_gb = usage.free // (2**30)
                disk_info[partition.mountpoint] = f"{free_space_gb} GiB free ({free_percent:.2f}%)"
                
                # Update GUI with partition information
                update_gui_results(f"{Fore.CYAN}Partition {partition.mountpoint}: {disk_info[partition.mountpoint]}{Style.RESET_ALL}")

                # Check if free space is below threshold (10%)
                if free_percent < 10:
                    warning_msg = f"Low disk space on {partition.mountpoint}. Consider cleaning up your system."
                    logging.warning(warning_msg)
                    update_gui_results(f"{Fore.YELLOW}Warning: Low disk space on {partition.mountpoint}. Consider cleaning up your system.{Style.RESET_ALL}")

            except Exception as e:
                error_msg = f"Error accessing disk partition {partition.mountpoint}: {e}"
                logging.error(error_msg)
                update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")

    except Exception as e:
        error_msg = f"Error checking disk space: {e}"
        logging.error(error_msg)
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")

    return disk_info

def check_outdated_packages():
    """
    Check for outdated Python packages in the environment and update the GUI and logs with the results.
    """
    update_gui_results("Checking for outdated Python packages...")  # Update GUI with the status of the check
    
    logging.info("Checking for outdated Python packages...")
    outdated_packages = []

    try:
        for dist in pkg_resources.working_set:
            try:
                # In real-world scenarios, query an external API like PyPI to check for the latest version
                latest_version = str(dist._version)  # Placeholder; this would ideally come from an external API
                if dist.version != latest_version:
                    outdated_packages.append(f"{dist.project_name} (installed: {dist.version}, latest: {latest_version})")
            
            except Exception as e:
                error_msg = f"Error checking version for {dist.project_name}: {e}"
                logging.error(error_msg)
                update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")

        if outdated_packages:
            logging.warning("Outdated Python packages detected.")
            update_gui_results(f"{Fore.YELLOW}Outdated Python packages detected:{Style.RESET_ALL}")  # Update GUI

            for package in outdated_packages:
                logging.warning(package)  # Log each outdated package
                update_gui_results(package)  # Update GUI with each outdated package
        else:
            logging.info("All Python packages are up to date.")
            update_gui_results(f"{Fore.GREEN}All Python packages are up to date.{Style.RESET_ALL}")  # Update GUI

    except Exception as e:
        error_msg = f"Error checking outdated packages: {e}"
        logging.error(error_msg)
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")  # Update GUI on error

    return outdated_packages

def check_performance_metrics():
    logging.info("Checking CPU and memory usage...")
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        update_gui_results(f"{Fore.CYAN}CPU Usage: {cpu_usage}%{Style.RESET_ALL}")
        update_gui_results(f"{Fore.CYAN}Memory Usage: {memory.percent}% used of {memory.total // (2**30)} GB total{Style.RESET_ALL}")
        if cpu_usage > 80:
            logging.warning(f"High CPU usage detected: {cpu_usage}%")
            update_gui_results(f"{Fore.YELLOW}Warning: High CPU usage detected!{Style.RESET_ALL}")
        if memory.percent > 80:
            logging.warning(f"High memory usage detected: {memory.percent}%")
            update_gui_results(f"{Fore.YELLOW}Warning: High memory usage detected!{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error checking CPU or memory usage: {e}")
        update_gui_results(f"{Fore.RED}Error checking CPU or memory usage.{Style.RESET_ALL}")

def check_open_ports():
    """
    Check for open network ports and update the GUI and logs accordingly.
    Flags open ports and potential security risks.
    """
    update_gui_results("Checking for open ports...")  # Update the GUI with the status

    logging.info("Checking for open ports...")
    open_ports = []

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                open_ports.append(conn.laddr.port)
        
        if open_ports:
            open_ports_str = ', '.join(map(str, open_ports))
            logging.warning(f"Potential security risk: Open ports detected: {open_ports_str}")
            update_gui_results(f"{Fore.YELLOW}Warning: Open ports detected: {open_ports_str}{Style.RESET_ALL}")  # Update GUI
            update_gui_results(f"{Fore.YELLOW}Warning: Open ports detected: {open_ports_str}{Style.RESET_ALL}")  # Show warning in GUI and console
        else:
            logging.info("No open ports detected.")
            update_gui_results(f"{Fore.GREEN}No open ports detected.{Style.RESET_ALL}")  # Update GUI
            update_gui_results(f"{Fore.GREEN}No open ports detected.{Style.RESET_ALL}")  # Inform in GUI and console

    except Exception as e:
        error_msg = f"Error checking open ports: {e}"
        logging.error(error_msg)
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")  # Update GUI with error
        update_gui_results(f"{Fore.RED}Error checking open ports.{Style.RESET_ALL}")  # Show error in GUI and console

    return open_ports

def run_scan_and_update_gui():
    """
    Runs the scan for suspicious apps and updates the GUI with the results.
    Handles any errors gracefully and logs relevant information.
    """
    try:
        # Perform the scan and capture the suspicious apps
        suspicious_apps = check_suspicious_apps()
        
        if suspicious_apps:
            result_msg = f"Suspicious apps detected: {', '.join(suspicious_apps)}"
            logging.warning(result_msg)
            update_gui_results(f"{Fore.YELLOW}Warning: {result_msg}{Style.RESET_ALL}")
            update_gui_results(f"{Fore.YELLOW}Suspicious apps detected: {', '.join(suspicious_apps)}{Style.RESET_ALL}")
        else:
            result_msg = "No suspicious apps detected."
            logging.info(result_msg)
            update_gui_results(f"{Fore.GREEN}{result_msg}{Style.RESET_ALL}")
            update_gui_results(f"{Fore.GREEN}{result_msg}{Style.RESET_ALL}")

    except Exception as e:
        error_msg = f"Error during scan: {e}"
        logging.error(error_msg)
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")


def scan_periodically():
    """
    Periodically scans for suspicious applications every 5 minutes and updates the GUI.
    Handles any errors gracefully and logs relevant information.
    """
    logging.info("Starting periodic scan for suspicious apps...")
    update_gui_results("Starting periodic scan for suspicious apps...")  # Update GUI with the start of the scan

    # Schedule the scan to run every 5 minutes
    schedule.every(5).minutes.do(run_scan_and_update_gui)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)  # Sleep for 1 second to prevent high CPU usage
    except Exception as e:
        error_msg = f"Error during periodic scan: {e}"
        logging.error(error_msg)
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
        update_gui_results(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")

# Assuming some predefined `update_gui_results` function and `create_gui` to update the GUI with messages.

def generate_report(os_info, suspicious_apps, disk_space, open_ports):
    logging.info("Generating scan report...")
    try:
        # Update the GUI with the scan report information instead of writing to a file
        report = f"Scan Report - {time.ctime()}\n"
        report += f"OS Version: {os_info}\n"
        report += f"Suspicious Processes: {', '.join([str(app) for app in suspicious_apps])}\n"
        report += f"Disk Space: {disk_space}\n"
        report += f"Open Ports: {', '.join(map(str, open_ports))}\n"

        update_gui_results(report)  # Update the GUI with the generated report
        update_gui_results(f"{Fore.GREEN}Scan report generated successfully.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        update_gui_results(f"{Fore.RED}Error generating report.{Style.RESET_ALL}")
        update_gui_results(f"{Fore.RED}Error generating report.{Style.RESET_ALL}")

def notify_user(message):
    """Show a GUI notification instead of using a messagebox."""
    update_gui_results(f"{Fore.YELLOW}Security Alert: {message}{Style.RESET_ALL}")  # Show alert on GUI

def perform_scan():
    logging.info("Starting system vulnerability scan...")
    update_gui_results(f"{Fore.CYAN}Starting system vulnerability scan...{Style.RESET_ALL}\n")
    
    os_info = check_os_version()
    scan_for_virus("one-time")
    suspicious_apps = check_suspicious_apps()
    dynamic_suspicious = check_app_permissions()
    disk_space = check_disk_space()
    outdated_packages = check_outdated_packages()
    check_performance_metrics()
    open_ports = check_open_ports()
    
    # Merge dynamic suspicious apps with previously detected suspicious apps
    all_suspicious = list(set([str(item) for item in (suspicious_apps + dynamic_suspicious)]))
    
    generate_report(os_info, all_suspicious, disk_space, open_ports)
    
    logging.info("Scan complete.")
    update_gui_results(f"\n{Fore.GREEN}Scan complete.{Style.RESET_ALL}")

def scan_for_virus(scan_type):
    update_gui_results("Starting system vulnerability scan...")
    virus_signatures = ["eicar.com"]
    directories_to_scan = [
        os.path.join(os.path.expanduser("~"), "Documents", "test", "me"),
        os.path.join(os.path.expanduser("~"), "Downloads")
    ]
    if platform.system() == "Windows":
        directories_to_scan.append(r"C:\Windows")  # Windows-only path

    detected_viruses = []
    for directory in directories_to_scan:
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.lower() in virus_signatures:
                        detected_viruses.append(os.path.join(root, file))
        except Exception as e:
            logging.error(f"Error scanning {directory}: {e}")
    
    if detected_viruses:
        update_gui_results("\nVirus Detected: ")
        for virus in detected_viruses:
            update_gui_results(f"Virus found: {virus}")
    else:
        update_gui_results("\nNo viruses detected.")

def schedule_scans():
    if hasattr(schedule_scans, "already_run"):
        return

    update_gui_results("\nChoose scan frequency:")
    update_gui_results("1. One-time scan\n2. Daily scan\n3. Weekly scan")

    choice = simpledialog.askstring("Enter the number of your choice: ")

    if choice == "1":
        update_gui_results("\nRunning one-time scan...\n")
        perform_scan()
    elif choice == "2":
        update_gui_results("\nScheduling daily scans at 03:00 AM... (Press Ctrl+C to exit)")
        schedule.every().day.at("03:00").do(perform_scan)
    elif choice == "3":
        update_gui_results("\nScheduling weekly scans every Monday at 03:00 AM... (Press Ctrl+C to exit)")
        schedule.every().monday.at("03:00").do(perform_scan)
    else:
        update_gui_results("\nInvalid choice. Please enter 1, 2, or 3.")
        return

    def scheduler_loop():
        while True:
            schedule.run_pending()
            time.sleep(1)

    threading.Thread(target=scheduler_loop, daemon=True).start()
    schedule_scans.already_run = True
if __name__ == "__main__":
    create_gui()  # Start the GUI when the script is run