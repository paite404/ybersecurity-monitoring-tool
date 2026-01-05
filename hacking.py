#!/usr/bin/env python3
"""
Enhanced Cybersecurity Monitoring Tool
Author: Giningakpio Stephen Paite Justin
Roll No: 012230331
ISBAT University - Cyber Security
For Educational Use Only
"""

import os
import sys
import time
import json
import socket
import subprocess
import platform
import datetime
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import signal

# Check and import dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[!] psutil not installed. Some features will be limited.")
    print("    Install with: pip install psutil")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests not installed. IP location features disabled.")
    print("    Install with: pip install requests")

try:
    import phonenumbers
    from phonenumbers import carrier, timezone, geocoder
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False
    print("[!] phonenumbers not installed. Phone lookup disabled.")
    print("    Install with: pip install phonenumbers")

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] scapy not installed. Advanced network scanning disabled.")
    print("    Install with: pip install scapy")

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("[!] netifaces not installed. Network interface info limited.")
    print("    Install with: pip install netifaces")

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Global variables
monitoring_active = False
reports_dir = Path("reports")
logs_dir = Path("logs")
reports_dir.mkdir(exist_ok=True)
logs_dir.mkdir(exist_ok=True)

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the main header"""
    clear_screen()
    print(f"{Colors.BLUE}{'═'*75}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'ENHANCED CYBERSECURITY MONITORING TOOL'.center(75)}{Colors.ENDC}")
    print(f"{Colors.BLUE}{'ISBAT University - Cyber Security'.center(75)}{Colors.ENDC}")
    print(f"{Colors.BLUE}{'═'*75}{Colors.ENDC}")
    print(f"{Colors.YELLOW}👤 Author: Giningakpio Stephen Paite Justin{Colors.ENDC}")
    print(f"{Colors.YELLOW}🎓 Program: BSc Networking & Cyber Security{Colors.ENDC}")
    print(f"{Colors.YELLOW}📚 Roll No: 012230331{Colors.ENDC}")
    print(f"{Colors.YELLOW}👨‍🏫 Supervisor: Mr. Shameem{Colors.ENDC}")
    print(f"{Colors.YELLOW}📧 Contact: cybergurus@hotmail.com{Colors.ENDC}")
    print(f"{Colors.YELLOW}📱 Phone: +211 925 791 177{Colors.ENDC}")
    print(f"\n{Colors.RED}{Colors.BOLD}⚠️  FOR EDUCATIONAL AND AUTHORIZED USE ONLY ⚠️{Colors.ENDC}")
    print(f"{Colors.BLUE}{'═'*75}{Colors.ENDC}\n")

def get_system_info() -> Dict:
    """Get comprehensive system information"""
    info = {
        "timestamp": datetime.datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "username": os.getenv('USER') or os.getenv('USERNAME'),
        "current_dir": os.getcwd(),
        "home_dir": os.path.expanduser("~"),
    }
    return info

def display_system_info():
    """Display system information"""
    info = get_system_info()
    print(f"\n{Colors.BOLD}📊 SYSTEM INFORMATION:{Colors.ENDC}")
    for key, value in info.items():
        print(f"  {key}: {value}")

def real_time_monitoring():
    """Real-time system monitoring dashboard"""
    global monitoring_active
    
    if not PSUTIL_AVAILABLE:
        print(f"{Colors.RED}[!] psutil is required for real-time monitoring{Colors.ENDC}")
        return
    
    monitoring_active = True
    
    def signal_handler(sig, frame):
        global monitoring_active
        monitoring_active = False
        print(f"\n{Colors.YELLOW}[!] Monitoring stopped{Colors.ENDC}")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"\n{Colors.BOLD}{'═'*75}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'REAL-TIME SYSTEM MONITOR'.center(75)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'═'*75}{Colors.ENDC}")
    
    try:
        while monitoring_active:
            clear_screen()
            print(f"\n{Colors.BOLD}{'═'*75}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'REAL-TIME SYSTEM MONITOR'.center(75)}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'═'*75}{Colors.ENDC}")
            
            # Current time
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {Colors.GREEN}Time: {current_time}{Colors.ENDC}\n")
            
            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=0.5)
            cpu_bar = create_progress_bar(cpu_percent, 40)
            print(f"{Colors.BLUE}🚀 CPU Usage: {cpu_percent:.1f}%{Colors.ENDC}")
            print(f"    {cpu_bar}\n")
            
            # Memory Usage
            memory = psutil.virtual_memory()
            mem_percent = memory.percent
            mem_bar = create_progress_bar(mem_percent, 40)
            print(f"{Colors.GREEN}💾 Memory Usage: {mem_percent:.1f}%{Colors.ENDC}")
            print(f"    {mem_bar}")
            print(f"    Total: {memory.total // (1024**3)}GB, Used: {memory.used // (1024**3)}GB, Free: {memory.free // (1024**3)}GB\n")
            
            # Disk Usage
            try:
                disk = psutil.disk_usage('/')
                disk_percent = disk.percent
                disk_bar = create_progress_bar(disk_percent, 40)
                print(f"{Colors.YELLOW}💿 Disk Usage: {disk_percent:.1f}%{Colors.ENDC}")
                print(f"    {disk_bar}")
                print(f"    Total: {disk.total // (1024**3)}GB, Used: {disk.used // (1024**3)}GB, Free: {disk.free // (1024**3)}GB\n")
            except:
                print(f"{Colors.YELLOW}💿 Disk Usage: N/A{Colors.ENDC}\n")
            
            # Network
            net_io = psutil.net_io_counters()
            print(f"{Colors.CYAN}🌐 Network:{Colors.ENDC}")
            print(f"  Received: {net_io.bytes_recv / (1024**2):.2f} MB")
            print(f"  Transmitted: {net_io.bytes_sent / (1024**2):.2f} MB\n")
            
            # Top Processes
            print(f"{Colors.RED}🔥 Top Processes:{Colors.ENDC}")
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        processes.append((proc.info['cpu_percent'] or 0, proc.info['name']))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                processes.sort(reverse=True)
                for i, (cpu, name) in enumerate(processes[:5], 1):
                    print(f"  {i}. {name[:40]} (CPU: {cpu:.1f}%)")
            except:
                print("  Could not retrieve process information")
            
            print(f"\n{Colors.YELLOW}Press Ctrl+C to stop monitoring{Colors.ENDC}")
            print(f"{Colors.BOLD}{'═'*75}{Colors.ENDC}")
            
            time.sleep(1)
    
    except KeyboardInterrupt:
        monitoring_active = False
        print(f"\n{Colors.YELLOW}[!] Monitoring stopped{Colors.ENDC}")

def create_progress_bar(percentage: float, width: int = 40) -> str:
    """Create a text-based progress bar"""
    filled = int(width * percentage / 100)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}]"

def network_scan():
    """Scan local network for active devices"""
    if not SCAPY_AVAILABLE:
        print(f"{Colors.RED}[!] scapy is required for network scanning{Colors.ENDC}")
        return
    
    try:
        # Get local IP and network
        if NETIFACES_AVAILABLE:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            interface = gateways['default'][netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(interface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip_address = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate network range
            ip_parts = list(map(int, ip_address.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            network = '.'.join(map(str, network_parts))
            
            # Calculate number of hosts (simplified)
            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
            target = f"{network}/{cidr}"
        else:
            # Fallback method
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
            target = f"{ip_address.rsplit('.', 1)[0]}.0/24"
        
        print(f"{Colors.GREEN}[+] Your IP: {ip_address}{Colors.ENDC}")
        print(f"{Colors.GREEN}[+] Scanning network: {target}{Colors.ENDC}")
        
        # Create ARP request
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send packet
        result = srp(packet, timeout=3, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        print(f"\n{Colors.BOLD}📡 Active Devices:{Colors.ENDC}")
        for i, device in enumerate(devices, 1):
            print(f"  {Colors.GREEN}✅ {device['ip']} - {device['mac']}{Colors.ENDC}")
        
        print(f"\n{Colors.GREEN}[+] Found {len(devices)} active devices{Colors.ENDC}")
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error scanning network: {e}{Colors.ENDC}")

def port_scanner():
    """Scan ports on a target host"""
    print(f"\n{Colors.BOLD}🔍 Port Scanner{Colors.ENDC}")
    
    target = input(f"{Colors.YELLOW}Target (default: localhost): {Colors.ENDC}").strip()
    if not target:
        target = "127.0.0.1"
    
    start_port = input(f"{Colors.YELLOW}Start port (default: 1): {Colors.ENDC}").strip()
    if not start_port:
        start_port = 1
    else:
        start_port = int(start_port)
    
    end_port = input(f"{Colors.YELLOW}End port (default: 100): {Colors.ENDC}").strip()
    if not end_port:
        end_port = 100
    else:
        end_port = int(end_port)
    
    print(f"\n{Colors.GREEN}[+] Scanning Ports {start_port}-{end_port} on {target}...{Colors.ENDC}")
    
    open_ports = []
    common_ports = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Alt",
    }
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    for port in range(start_port, end_port + 1):
        if scan_port(port):
            service = common_ports.get(port, "Unknown")
            open_ports.append((port, service))
            print(f"  {Colors.GREEN}✅ Port {port:>5} open - {service}{Colors.ENDC}")
    
    print(f"\n{Colors.GREEN}[+] Found {len(open_ports)} open ports{Colors.ENDC}")

def phone_lookup():
    """Lookup phone number information (Ethical use only)"""
    if not PHONENUMBERS_AVAILABLE:
        print(f"{Colors.RED}[!] phonenumbers library is required for phone lookup{Colors.ENDC}")
        return
    
    print(f"\n{Colors.BOLD}{'═'*75}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.RED}{'ETHICAL USE WARNING'.center(75)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'═'*75}{Colors.ENDC}")
    print(f"{Colors.YELLOW}This feature is for EDUCATIONAL PURPOSES ONLY.{Colors.ENDC}")
    print(f"{Colors.YELLOW}Use only on phone numbers you OWN or have PERMISSION to check.{Colors.ENDC}")
    print(f"{Colors.BOLD}{'═'*75}{Colors.ENDC}\n")
    
    consent = input(f"{Colors.YELLOW}Do you agree to ethical use? (yes/no): {Colors.ENDC}").strip().lower()
    if consent != 'yes':
        print(f"{Colors.RED}[!] Operation cancelled{Colors.ENDC}")
        return
    
    phone_number = input(f"{Colors.YELLOW}Enter phone number (with country code, e.g., +256770386114): {Colors.ENDC}").strip()
    
    print(f"\n{Colors.GREEN}[+] Getting Phone Information...{Colors.ENDC}")
    
    try:
        # Parse phone number
        parsed_number = phonenumbers.parse(phone_number)
        
        # Validate number
        is_valid = phonenumbers.is_valid_number(parsed_number)
        
        if is_valid:
            print(f"{Colors.GREEN}✅ Valid Phone Number{Colors.ENDC}")
            print(f"\n{Colors.BOLD}📱 Basic Information:{Colors.ENDC}")
            
            # Format international
            intl_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            print(f"  International: {intl_format}")
            
            # Country code and national number
            print(f"  Country Code: +{parsed_number.country_code}")
            print(f"  National Number: {parsed_number.national_number}")
            
            # Location
            location = geocoder.description_for_number(parsed_number, "en")
            if location:
                print(f"  📍 Location: {location}")
            
            # Carrier
            try:
                carrier_name = carrier.name_for_number(parsed_number, "en")
                if carrier_name:
                    print(f"  🏢 Carrier: {carrier_name}")
            except:
                pass
            
            # Timezone
            try:
                time_zones = timezone.time_zones_for_number(parsed_number)
                if time_zones:
                    print(f"  🕐 Timezone: {', '.join(time_zones)}")
            except:
                pass
            
            # Number type
            number_type = phonenumbers.number_type(parsed_number)
            type_names = {
                0: "FIXED_LINE",
                1: "MOBILE",
                2: "FIXED_LINE_OR_MOBILE",
                3: "TOLL_FREE",
                4: "PREMIUM_RATE",
                5: "SHARED_COST",
                6: "VOIP",
                7: "PERSONAL_NUMBER",
                8: "PAGER",
                9: "UAN",
                10: "VOICEMAIL",
                27: "UNKNOWN"
            }
            print(f"  Type: {type_names.get(number_type, 'UNKNOWN')}")
            
        else:
            print(f"{Colors.RED}❌ Invalid Phone Number{Colors.ENDC}")
            
    except phonenumbers.NumberParseException as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}❌ Unexpected error: {e}{Colors.ENDC}")

def ip_location():
    """Lookup IP address location"""
    if not REQUESTS_AVAILABLE:
        print(f"{Colors.RED}[!] requests library is required for IP location lookup{Colors.ENDC}")
        return
    
    ip_address = input(f"{Colors.YELLOW}Enter IP address: {Colors.ENDC}").strip()
    
    print(f"\n{Colors.GREEN}[+] Getting IP Location...{Colors.ENDC}")
    
    try:
        # Check if private IP
        def is_private_ip(ip):
            priv_ranges = [
                ("10.0.0.0", "10.255.255.255"),
                ("172.16.0.0", "172.31.255.255"),
                ("192.168.0.0", "192.168.255.255"),
            ]
            ip_num = int(''.join(f"{int(x):08b}" for x in ip.split('.')), 2)
            for start, end in priv_ranges:
                start_num = int(''.join(f"{int(x):08b}" for x in start.split('.')), 2)
                end_num = int(''.join(f"{int(x):08b}" for x in end.split('.')), 2)
                if start_num <= ip_num <= end_num:
                    return True
            return False
        
        if is_private_ip(ip_address):
            print(f"{Colors.YELLOW}⚠️  Private IP address - limited information{Colors.ENDC}")
            print(f"  IP: {ip_address}")
            print(f"  Type: Private")
            print(f"  Range: Private Class B")
            return
        
        # Public IP lookup
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        
        if data['status'] == 'success':
            print(f"{Colors.GREEN}✅ Location Found{Colors.ENDC}")
            print(f"\n{Colors.BOLD}🌍 Information:{Colors.ENDC}")
            print(f"  IP: {data.get('query', ip_address)}")
            print(f"  Country: {data.get('country', 'Unknown')}")
            print(f"  Region: {data.get('regionName', 'Unknown')}")
            print(f"  City: {data.get('city', 'Unknown')}")
            print(f"  ISP: {data.get('isp', 'Unknown')}")
            print(f"  Organization: {data.get('org', 'Unknown')}")
            print(f"  AS: {data.get('as', 'Unknown')}")
            
            if data.get('lat') and data.get('lon'):
                print(f"  Coordinates: {data.get('lat')}, {data.get('lon')}")
                print(f"  Timezone: {data.get('timezone', 'Unknown')}")
                print(f"  🗺️  Map: https://maps.google.com/?q={data.get('lat')},{data.get('lon')}")
        else:
            print(f"{Colors.RED}❌ Could not retrieve location information{Colors.ENDC}")
            
    except requests.RequestException as e:
        print(f"{Colors.RED}❌ Network error: {e}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.ENDC}")

def system_logs():
    """Display system logs"""
    print(f"\n{Colors.BOLD}📝 System Logs{Colors.ENDC}")
    
    lines_input = input(f"{Colors.YELLOW}Number of log lines (default: 50): {Colors.ENDC}").strip()
    lines = int(lines_input) if lines_input.isdigit() else 50
    
    print(f"\n{Colors.GREEN}[+] Getting System Logs...{Colors.ENDC}")
    
    log_commands = [
        ("System", "journalctl -n {lines} --no-pager"),
        ("Kernel", "dmesg -T | tail -n {lines}"),
        ("Auth", "tail -n {lines} /var/log/auth.log 2>/dev/null || echo 'No auth log available'"),
        ("Syslog", "tail -n {lines} /var/log/syslog 2>/dev/null || echo 'No syslog available'"),
    ]
    
    for log_name, command in log_commands:
        try:
            result = subprocess.run(
                command.format(lines=lines),
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.stdout:
                print(f"\n{Colors.BOLD}{log_name} Logs:{Colors.ENDC}")
                print(result.stdout[:1000])  # Limit output
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}  [!] {log_name} log retrieval timed out{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}  [!] Error reading {log_name} logs: {e}{Colors.ENDC}")

def enhanced_logging():
    """Enhanced logging system with user analysis"""
    print(f"\n{Colors.BOLD}{'═'*75}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'ENHANCED LOGGING SYSTEM'.center(75)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'═'*75}{Colors.ENDC}")
    
    while True:
        print(f"\n{Colors.BOLD}1.{Colors.ENDC} 👤 User Accounts Analysis")
        print(f"{Colors.BOLD}2.{Colors.ENDC} 📅 Current Sessions")
        print(f"{Colors.BOLD}3.{Colors.ENDC} 📊 User Session Analysis")
        print(f"{Colors.BOLD}4.{Colors.ENDC} 🔙 Back to Main Menu")
        
        choice = input(f"\n{Colors.YELLOW}Select option (1-4): {Colors.ENDC}").strip()
        
        if choice == '1':
            # User accounts analysis
            try:
                with open('/etc/passwd', 'r') as f:
                    users = [line.strip().split(':') for line in f.readlines()]
                
                print(f"\n{Colors.GREEN}[+] Analyzing User Accounts...{Colors.ENDC}")
                print(f"\n{Colors.BOLD}📊 Found {len(users)} user accounts:{Colors.ENDC}")
                
                # Show first 20 users
                for user in users[:20]:
                    username = user[0]
                    uid = user[2]
                    shell = user[6]
                    
                    if uid == '0':
                        print(f"  {Colors.RED}🔓 {username} (UID: {uid}) - {shell}{Colors.ENDC}")
                    elif int(uid) < 1000:
                        print(f"  {Colors.YELLOW}🔒 {username} (UID: {uid}) - {shell}{Colors.ENDC}")
                    else:
                        print(f"  {Colors.GREEN}👤 {username} (UID: {uid}) - {shell}{Colors.ENDC}")
                
                if len(users) > 20:
                    print(f"  ... and {len(users) - 20} more users")
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error reading user accounts: {e}{Colors.ENDC}")
                
        elif choice == '2':
            # Current sessions
            try:
                result = subprocess.run(['who', '-u'], capture_output=True, text=True)
                if result.stdout:
                    print(f"\n{Colors.GREEN}[+] Currently Logged In Users:{Colors.ENDC}")
                    for line in result.stdout.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 5:
                            print(f"  👤 {parts[0]}  {parts[1]}         {parts[2]} {parts[3]}")
                else:
                    print(f"{Colors.YELLOW}[!] No active sessions found{Colors.ENDC}")
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error reading sessions: {e}{Colors.ENDC}")
                
        elif choice == '3':
            # User session analysis
            if not PSUTIL_AVAILABLE:
                print(f"{Colors.RED}[!] psutil required for session analysis{Colors.ENDC}")
                continue
                
            print(f"\n{Colors.GREEN}[+] User Session Analysis:{Colors.ENDC}")
            
            user_processes = {}
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    info = proc.info
                    username = info['username']
                    if username not in user_processes:
                        user_processes[username] = []
                    user_processes[username].append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            for username, processes in user_processes.items():
                print(f"\n  👤 User: {username}")
                print(f"    Active processes: {len(processes)}")
                for proc in processes[:3]:  # Show first 3 processes
                    print(f"    📊 PID {proc['pid']}: {proc['name'][:50]}")
                if len(processes) > 3:
                    print(f"    ... and {len(processes) - 3} more processes")
                    
        elif choice == '4':
            break
        else:
            print(f"{Colors.RED}[!] Invalid choice{Colors.ENDC}")

def security_check():
    """Perform basic security checks"""
    print(f"\n{Colors.GREEN}[+] Running Security Checks...{Colors.ENDC}")
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}SECURITY CHECK RESULTS{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
    
    checks = []
    
    # Check 1: Firewall status
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        if 'inactive' in result.stdout:
            checks.append(("⚠️  Firewall", "UFW is not active", Colors.YELLOW))
        else:
            checks.append(("✅ Firewall", "UFW is active", Colors.GREEN))
    except:
        checks.append(("ℹ️  Firewall", "UFW not installed/accessible", Colors.YELLOW))
    
    # Check 2: Open ports on localhost
    try:
        open_ports = []
        for port in [21, 22, 23, 80, 443, 3389, 5900]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                open_ports.append(port)
            sock.close()
        
        if open_ports:
            checks.append((f"⚠️  Open Ports", f"Ports open: {open_ports}", Colors.YELLOW))
        else:
            checks.append(("✅ Open Ports", "No risky ports open", Colors.GREEN))
    except:
        checks.append(("ℹ️  Open Ports", "Could not check ports", Colors.YELLOW))
    
    # Check 3: System updates
    try:
        result = subprocess.run(['apt-get', 'update'], capture_output=True, text=True)
        if 'packages can be upgraded' in result.stdout:
            checks.append(("⚠️  Updates", "System updates available", Colors.YELLOW))
        else:
            checks.append(("✅ Updates", "System is up to date", Colors.GREEN))
    except:
        checks.append(("ℹ️  Updates", "Could not check updates", Colors.YELLOW))
    
    # Display results
    for check, message, color in checks:
        print(f"\n{color}{check}: {message}{Colors.ENDC}")

def generate_report():
    """Generate comprehensive system report"""
    print(f"\n{Colors.GREEN}[+] Generating Report...{Colors.ENDC}")
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_data = {}
    
    # System information
    report_data['system_info'] = get_system_info()
    
    # Security check results
    report_data['security_checks'] = []
    try:
        # Simplified security checks for report
        security_items = []
        
        # Firewall check
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if 'inactive' in result.stdout:
                security_items.append({"check": "Firewall", "status": "⚠️ Inactive", "risk": "Medium"})
            else:
                security_items.append({"check": "Firewall", "status": "✅ Active", "risk": "Low"})
        except:
            security_items.append({"check": "Firewall", "status": "ℹ️ Unknown", "risk": "Unknown"})
        
        report_data['security_checks'] = security_items
    except Exception as e:
        report_data['security_checks'] = [{"error": str(e)}]
    
    # Save JSON report
    json_file = reports_dir / f"cyber_report_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    # Save text report
    txt_file = reports_dir / f"cyber_report_{timestamp}.txt"
    with open(txt_file, 'w') as f:
        f.write(f"Cybersecurity Report - {timestamp}\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("SYSTEM INFORMATION:\n")
        f.write("-" * 30 + "\n")
        for key, value in report_data['system_info'].items():
            f.write(f"{key}: {value}\n")
        
        f.write("\nSECURITY CHECKS:\n")
        f.write("-" * 30 + "\n")
        for check in report_data['security_checks']:
            f.write(f"{check.get('check', 'Unknown')}: {check.get('status', 'Unknown')} (Risk: {check.get('risk', 'Unknown')})\n")
    
    print(f"\n{Colors.GREEN}✅ Reports Generated:{Colors.ENDC}")
    print(f"  📄 JSON: {json_file}")
    print(f"  📝 Text: {txt_file}")

def check_dependencies():
    """Check and display installed dependencies"""
    print(f"\n{Colors.BOLD}🔍 Checking Dependencies...{Colors.ENDC}")
    
    dependencies = [
        ("psutil", PSUTIL_AVAILABLE, "System monitoring"),
        ("requests", REQUESTS_AVAILABLE, "HTTP requests for IP lookup"),
        ("phonenumbers", PHONENUMBERS_AVAILABLE, "Phone number validation"),
        ("scapy", SCAPY_AVAILABLE, "Advanced network scanning"),
        ("netifaces", NETIFACES_AVAILABLE, "Network interface info"),
    ]
    
    all_installed = True
    for name, installed, description in dependencies:
        if installed:
            print(f"  {Colors.GREEN}✅ {name}{Colors.ENDC}: {description}")
        else:
            print(f"  {Colors.RED}❌ {name}{Colors.ENDC}: {description} - NOT INSTALLED")
            all_installed = False
    
    if not all_installed:
        print(f"\n{Colors.YELLOW}📦 Install missing dependencies:{Colors.ENDC}")
        print("pip install psutil requests phonenumbers scapy netifaces")
    else:
        print(f"\n{Colors.GREEN}✅ All dependencies installed!{Colors.ENDC}")

def main_menu():
    """Display main menu and handle user input"""
    while True:
        print_header()
        print(f"{Colors.BOLD}{'MAIN MENU'.center(75)}{Colors.ENDC}")
        print(f"{Colors.BLUE}{'═'*75}{Colors.ENDC}")
        print(f"{Colors.BOLD}1.{Colors.ENDC} 📊 System Information")
        print(f"{Colors.BOLD}2.{Colors.ENDC} 🚀 Real-time Monitoring")
        print(f"{Colors.BOLD}3.{Colors.ENDC} 🌐 Network Scanner")
        print(f"{Colors.BOLD}4.{Colors.ENDC} 🔍 Port Scanner")
        print(f"{Colors.BOLD}5.{Colors.ENDC} 📱 Phone Lookup (Ethical)")
        print(f"{Colors.BOLD}6.{Colors.ENDC} 🌍 IP Location")
        print(f"{Colors.BOLD}7.{Colors.ENDC} 📝 System Logs")
        print(f"{Colors.BOLD}8.{Colors.ENDC} 🔐 Enhanced Logging")
        print(f"{Colors.BOLD}9.{Colors.ENDC} 🛡️ Security Check")
        print(f"{Colors.BOLD}10.{Colors.ENDC} 📄 Generate Report")
        print(f"{Colors.BOLD}11.{Colors.ENDC} 📦 Check Dependencies")
        print(f"{Colors.BOLD}0.{Colors.ENDC} 🚪 Exit")
        print(f"{Colors.BLUE}{'═'*75}{Colors.ENDC}")
        
        choice = input(f"\n{Colors.YELLOW}Select option (0-11): {Colors.ENDC}").strip()
        
        if choice == '0':
            print(f"\n{Colors.GREEN}[+] Exiting... Thank you for using the Cybersecurity Tool!{Colors.ENDC}")
            break
        elif choice == '1':
            display_system_info()
        elif choice == '2':
            real_time_monitoring()
        elif choice == '3':
            network_scan()
        elif choice == '4':
            port_scanner()
        elif choice == '5':
            phone_lookup()
        elif choice == '6':
            ip_location()
        elif choice == '7':
            system_logs()
        elif choice == '8':
            enhanced_logging()
        elif choice == '9':
            security_check()
        elif choice == '10':
            generate_report()
        elif choice == '11':
            check_dependencies()
        else:
            print(f"{Colors.RED}[!] Invalid choice. Please select 0-11.{Colors.ENDC}")
        
        if choice != '0':
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")

def main():
    """Main entry point"""
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Program interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
