# idps_engine.py
# Author: Bang Thien Nguyen (updated)
# Full Real-time Home IDPS: improved startup logging, severity normalization,
# payload counters (XSS, Suspicious File Upload, Malicious Packet), and sniff loop.

import json
import time
import os
import datetime
import sys
import threading
import subprocess
import re
from scapy.all import sniff, IP, TCP, Raw, get_if_list, get_if_addr, ARP, ICMP, UDP
from scapy.error import Scapy_Exception

# For getting router IP
try:
    import netifaces
except ImportError:
    print("❌ The 'netifaces' library is not installed. Please install it with: pip install netifaces")
    sys.exit(1)

# --- Configuration ---
ALERTS_FILE = "ids_alerts.json"
BLOCKED_IPS_FILE = "blocked_ips.json"
RULES_FILE = "ids_rules.json"
STOP_SNIFFING = threading.Event()
PACKET_SCAN_WINDOW = 60  # seconds

# Valid severities
VALID_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Counters for rate-based detections
port_scan_attempts = {}
ddos_attempts = {}
icmp_flood_attempts = {}
rdp_brute_force_attempts = {}
ssh_brute_force_attempts = {}
login_brute_force_attempts = {}
http_flood_attempts = {}
unauthorized_access_attempts = {}
arp_spoof_attempts = {}

# Payload-specific counters requested by user
xss_attempts = {}
suspicious_file_upload_attempts = {}
malicious_packet_attempts = {}

# SQLi and XSS fingerprints
SQL_INJECTION_KEYWORDS = [
    " union ", " select ", " and 1=1", " or 1=1", " drop ", " insert ", " into ",
    " having ", " like ", " where ", " xor ", "--", "/*", "*/", "=", "'"
]
XSS_KEYWORDS = [
    "<script>", "</script>", "alert(", "prompt(", "confirm(", "onload=", "onerror=",
    "onmouseover=", "javascript:", "eval("
]

# State
blocked_ips_cache = set()
global_rules = {}
LOCAL_IP_ADDRESS = None  # New global variable to store the local IP
ROUTER_IP = None # New global variable for the router's IP

# ANSI colors
RED = "\033[31m"
BLUE = "\033[34m"
GREEN = '\033[92m'
RESET = "\033[0m"

# --- Helpers ---
def normalize_severity(sev):
    """Return canonical severity string (LOW/MEDIUM/HIGH/CRITICAL)."""
    if not isinstance(sev, str):
        return "LOW"
    s = sev.strip().upper()
    return s if s in VALID_SEVERITIES else "LOW"

# --- File management ---
def load_rules():
    """Load rules from RULES_FILE and normalize severities."""
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            try:
                rules = json.load(f)
                for rule in rules:
                    rule["severity"] = normalize_severity(rule.get("severity", "LOW"))
                return {rule['rule']: rule for rule in rules}
            except json.JSONDecodeError:
                print(f"Error: Could not decode {RULES_FILE}. Check file format.")
                return {}
    print(f"Warning: {RULES_FILE} not found. Running with default rules.")
    return {}

def load_alerts():
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_alerts(alerts):
    try:
        with open(ALERTS_FILE, "w") as f:
            json.dump(alerts, f, indent=2)
    except IOError as e:
        print(f"Error: Could not save alerts to {ALERTS_FILE}. Reason: {e}")

def load_blocked_ips():
    """Loads a list of dictionaries from the file, each containing src_ip and time."""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            try:
                data = json.load(f)
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                print(f"Error: Could not decode {BLOCKED_IPS_FILE}. Check file format.")
                return []
    return []

def save_blocked_ips(blocked_ips_list):
    """Saves a list of dictionaries to the file."""
    try:
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(blocked_ips_list, f, indent=2)
    except IOError as e:
        print(f"Error: Could not save blocked IPs to {BLOCKED_IPS_FILE}. Reason: {e}")

# --- Blocking / alerting ---
def block_ip(src_ip):
    """Block via Windows firewall (netsh) and record locally."""
    global blocked_ips_cache
    global LOCAL_IP_ADDRESS, ROUTER_IP
    
    # Do not block the router IP or the local host IP
    if src_ip == ROUTER_IP or src_ip == LOCAL_IP_ADDRESS:
        return

    # Check if IP is already in our in-memory cache to prevent re-blocking
    if src_ip in blocked_ips_cache:
        return

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {BLUE}🛡️ Blocking IP via Windows Firewall: {src_ip}{RESET}")
    
    # Add to the in-memory cache first
    blocked_ips_cache.add(src_ip)
    
    # New logic to handle file updates
    blocked_ips_list = load_blocked_ips()
    found = False
    for item in blocked_ips_list:
        if item.get("src_ip") == src_ip:
            item["time"] = str(datetime.datetime.now())
            found = True
            break
    if not found:
        blocked_ips_list.append({"src_ip": src_ip, "time": str(datetime.datetime.now())})

    save_blocked_ips(blocked_ips_list)

    try:
        rule_name = f"IDPS_Block_{src_ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={src_ip}"
        ]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print(f"❌ Error: 'netsh' command not found. This feature is for Windows only.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error adding firewall rule for {src_ip}. Command failed with exit code {e.returncode}.")
        print(f"  Stdout: {e.stdout.strip()}")
        print(f"  Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while adding firewall rule for {src_ip}: {e}")

def handle_alert(rule_name, src_ip, ports):
    """Log/save alert, print normalized severity, and block if severity is HIGH/CRITICAL."""
    global global_rules
    rules_data = global_rules.get(rule_name, {})
    severity = normalize_severity(rules_data.get("severity", "LOW"))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alerts = load_alerts()

    # Special handling for ARP Spoof from router
    if rule_name == "ARP Spoof" and src_ip == ROUTER_IP:
        print(f"[{now}] {RED}🔔 Alert: {rule_name} from {src_ip} [{severity}]{RESET}")
        handle_arp_spoof_from_router()
        return

    # update existing alert if exists
    for alert in alerts:
        if alert.get("src_ip") == src_ip and alert.get("rule") == rule_name:
            alert["occurrences"] = alert.get("occurrences", 1) + 1
            alert["timestamp"] = str(datetime.datetime.now())
            alert["severity"] = severity
            print(f"[{now}] {RED}🔔 Alert: {rule_name} from {src_ip} (x{alert['occurrences']}) [{severity}]{RESET}")
            save_alerts(alerts)
            if severity in ["HIGH", "CRITICAL"]:
                block_ip(src_ip)
            return

    # new alert
    alerts.append({
        "rule": rule_name,
        "severity": severity,
        "src_ip": src_ip,
        "ports": list(ports) if isinstance(ports, set) else ports,
        "occurrences": 1,
        "timestamp": str(datetime.datetime.now())
    })
    print(f"[{now}] {RED}🔔 Alert: {rule_name} from {src_ip} [{severity}]{RESET}")
    save_alerts(alerts)

    if severity in ["HIGH", "CRITICAL"]:
        block_ip(src_ip)

def handle_arp_spoof_from_router():
    """Check for static ARP entry for router and create if it doesn't exist."""
    global ROUTER_IP
    if not ROUTER_IP:
        print("❌ Router IP not found. Cannot apply static ARP entry.")
        return

    try:
        # Check for static ARP entry
        arp_check_cmd = ["arp", "-a", ROUTER_IP]
        result = subprocess.run(arp_check_cmd, capture_output=True, text=True, check=True)
        
        # Regex to find a "static" or "permanent" entry
        if re.search(r"Static|Permanent", result.stdout, re.IGNORECASE):
            print(f"{GREEN}✅ A static ARP entry for router {ROUTER_IP} already exists. No action required.{RESET}")
            return

        print(f"🛠️ Creating static ARP entry for router {ROUTER_IP}....")
        
        # Get the MAC address of the router
        mac_address = None
        for line in result.stdout.splitlines():
            if ROUTER_IP in line:
                mac_address = line.split()[1]
                break
        
        if not mac_address:
            print(f"❌ Could not find MAC address for router {ROUTER_IP}. Cannot create static ARP entry.")
            return

        # Create static ARP entry
        arp_add_cmd = ["arp", "-s", ROUTER_IP, mac_address]
        subprocess.run(arp_add_cmd, capture_output=True, text=True, check=True)
        print(f"✅ Solution successfully applied: A static ARP entry for router {ROUTER_IP} has been created.")
        
    except FileNotFoundError:
        print("❌ Error: 'arp' command not found. This feature is for Windows.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error creating static ARP entry for {ROUTER_IP}. Command failed with exit code {e.returncode}.")
        print(f"  Stdout: {e.stdout.strip()}")
        print(f"  Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while creating ARP entry: {e}")

# --- Detection utilities ---
def is_ip_in_range(ip_str, start_ip_str, end_ip_str):
    try:
        ip_int = sum([int(p) << (8 * (3 - i)) for i, p in enumerate(ip_str.split('.'))])
        start_int = sum([int(p) << (8 * (3 - i)) for i, p in enumerate(start_ip_str.split('.'))])
        end_int = sum([int(p) << (8 * (3 - i)) for i, p in enumerate(end_ip_str.split('.'))])
        return start_int <= ip_int <= end_int
    except (ValueError, IndexError):
        return False

def check_packet_rate(src_ip, counter_dict, rule_name):
    """Generic rate checker: uses rule 'threshold' from global_rules."""
    global global_rules
    current_time = time.time()
    rules_data = global_rules.get(rule_name, {})
    threshold = rules_data.get("threshold", 10)

    if src_ip not in counter_dict or (current_time - counter_dict[src_ip]['first_seen'] > PACKET_SCAN_WINDOW):
        counter_dict[src_ip] = {
            'count': 1,
            'first_seen': current_time
        }
    else:
        counter_dict[src_ip]['count'] += 1
        if counter_dict[src_ip]['count'] >= threshold:
            handle_alert(rule_name, src_ip, [])
            del counter_dict[src_ip]

# --- Packet analysis callback ---
def packet_callback(packet):
    global global_rules
    global LOCAL_IP_ADDRESS
    global ROUTER_IP

    # Ignore packets from our own local IP
    if IP in packet and packet[IP].src == LOCAL_IP_ADDRESS:
        return

    # Only process IP packets
    if IP not in packet:
        # For ARP detection we still want to check ARP in outer-level (scapy handles it separately)
        if ARP in packet and "ARP Spoof" in global_rules:
            src_ip = packet[ARP].psrc if hasattr(packet[ARP], 'psrc') else None
            if src_ip and src_ip not in blocked_ips_cache:
                check_packet_rate(src_ip, arp_spoof_attempts, "ARP Spoof")
        return

    src_ip = packet[IP].src
    if src_ip in blocked_ips_cache:
        return

    # --- Forbidden IP range example (keeps behavior from earlier) ---
    if "Forbidden IP Range" in global_rules:
        forbidden_ip_start = "10.0.0.1"
        forbidden_ip_end = "10.0.0.255"
        if is_ip_in_range(src_ip, forbidden_ip_start, forbidden_ip_end):
            handle_alert("Forbidden IP Range", src_ip, [])
            return

    # --- SYN-based port scan detection ---
    if TCP in packet and hasattr(packet[TCP], "flags") and packet[TCP].flags == 'S':
        current_time = time.time()
        if src_ip not in port_scan_attempts or (current_time - port_scan_attempts[src_ip]['first_seen'] > PACKET_SCAN_WINDOW):
            port_scan_attempts[src_ip] = {
                'count': 1,
                'first_seen': current_time,
                'ports': {packet[TCP].dport}
            }
        else:
            port_scan_attempts[src_ip]['count'] += 1
            port_scan_attempts[src_ip]['ports'].add(packet[TCP].dport)

            # Port Scan Detected
            if "Port Scan Detected" in global_rules and port_scan_attempts[src_ip]['count'] >= global_rules["Port Scan Detected"]["threshold"]:
                handle_alert("Port Scan Detected", src_ip, port_scan_attempts[src_ip]['ports'])
                del port_scan_attempts[src_ip]
            # Port Scan / All Ports Open (based on number of distinct ports)
            elif "Port Scan / All Ports Open" in global_rules and len(port_scan_attempts[src_ip]['ports']) >= global_rules["Port Scan / All Ports Open"]["threshold"]:
                handle_alert("Port Scan / All Ports Open", src_ip, port_scan_attempts[src_ip]['ports'])
                del port_scan_attempts[src_ip]

    # --- Payload-based detections ---
    if Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

        # SQL Injection Attempt
        if "SQL Injection Attempt" in global_rules:
            for keyword in SQL_INJECTION_KEYWORDS:
                if keyword in payload:
                    handle_alert("SQL Injection Attempt", src_ip, [packet[TCP].dport] if TCP in packet else [])
                    # increment generic malicious counter (rate based)
                    if "Malicious Packet Detected" in global_rules:
                        check_packet_rate(src_ip, malicious_packet_attempts, "Malicious Packet Detected")
                    return

        # Suspicious File Upload
        if "Suspicious File Upload" in global_rules:
            if "filename=" in payload or "content-disposition" in payload and "filename" in payload:
                # use counter and threshold from rules
                check_packet_rate(src_ip, suspicious_file_upload_attempts, "Suspicious File Upload")
                if "Malicious Packet Detected" in global_rules:
                    check_packet_rate(src_ip, malicious_packet_attempts, "Malicious Packet Detected")
                return

        # XSS Attack Attempt
        if "XSS Attack Attempt" in global_rules:
            for keyword in XSS_KEYWORDS:
                if keyword in payload:
                    check_packet_rate(src_ip, xss_attempts, "XSS Attack Attempt")
                    if "Malicious Packet Detected" in global_rules:
                        check_packet_rate(src_ip, malicious_packet_attempts, "Malicious Packet Detected")
                    return

    # --- Rate-based rules for protocol/port events ---
    # DDoS Attack Signature (port list)
    if "DDoS Attack Signature" in global_rules and TCP in packet and packet[TCP].dport in global_rules["DDoS Attack Signature"].get("ports", []):
        check_packet_rate(src_ip, ddos_attempts, "DDoS Attack Signature")

    # Telnet Scan
    if "Telnet Scan" in global_rules and TCP in packet and packet[TCP].dport == global_rules["Telnet Scan"].get("port"):
        check_packet_rate(src_ip, {}, "Telnet Scan")  # using ephemeral dict won't persist — keep as originally intended

    # ICMP Flood
    if "ICMP Flood" in global_rules and ICMP in packet:
        check_packet_rate(src_ip, icmp_flood_attempts, "ICMP Flood")

    # Login Brute Force (RDP + SSH)
    login_ports = []
    if "RDP Brute Force" in global_rules:
        login_ports.append(global_rules["RDP Brute Force"].get("port"))
    if "SSH Brute Force" in global_rules:
        login_ports.append(global_rules["SSH Brute Force"].get("port"))
    if TCP in packet and packet[TCP].dport in login_ports:
        check_packet_rate(src_ip, login_brute_force_attempts, "Login Brute Force")

    # SMB Exploit (immediate alert)
    if "SMB Exploit" in global_rules and TCP in packet and packet[TCP].dport in global_rules["SMB Exploit"].get("ports", []):
        handle_alert("SMB Exploit", src_ip, [packet[TCP].dport])

    # DNS Hijack (UDP/53)
    if "DNS Hijack" in global_rules and UDP in packet and packet[UDP].dport == global_rules["DNS Hijack"].get("port"):
        handle_alert("DNS Hijack", src_ip, [packet[UDP].dport])

    # ARP Spoof (ARP processed earlier if needed)
    if ARP in packet and "ARP Spoof" in global_rules:
        check_packet_rate(src_ip, arp_spoof_attempts, "ARP Spoof")

    # HTTP Flood
    if "HTTP Flood" in global_rules and TCP in packet and packet[TCP].dport in global_rules["HTTP Flood"].get("ports", []):
        check_packet_rate(src_ip, http_flood_attempts, "HTTP Flood")

    # Unauthorized Port Access
    if "Unauthorized Port Access" in global_rules and TCP in packet and packet[TCP].dport in global_rules["Unauthorized Port Access"].get("ports", []):
        check_packet_rate(src_ip, unauthorized_access_attempts, "Unauthorized Port Access")

# --- Interface helpers & main loop ---
def get_all_interfaces():
    """Return list [{'name': iface, 'ip': ip}] for all interfaces."""
    iface_list = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            iface_list.append({'name': iface, 'ip': ip})
        except Exception:
            iface_list.append({'name': iface, 'ip': None})
    return iface_list

def get_router_ip():
    """Attempts to get the default gateway (router) IP."""
    try:
        gws = netifaces.gateways()
        default_gateway = gws.get('default', {}).get(netifaces.AF_INET)
        if default_gateway:
            return default_gateway[0]
    except Exception as e:
        print(f"❌ Error getting router IP with netifaces: {e}")
    return None

def print_interfaces(interfaces):
    print("Found the following network interfaces:")
    for i, iface_info in enumerate(interfaces):
        ip_info = iface_info['ip'] if iface_info.get('ip') else 'N/A'
        print(f"  {i+1}: {iface_info['name']} (IP: {ip_info})")

def auto_select_wifi_interface(interfaces):
    """
    Attempts to find the Wi-Fi interface by heuristic:
    1. Looks for a Wi-Fi or WLAN keyword in the name.
    2. Looks for an IP in the 192.168.x.x range.
    Returns the interface name, or None if not found.
    """
    for iface in interfaces:
        # Check for common Wi-Fi keywords
        if "wi-fi" in (iface['name'] or "").lower() or "wlan" in (iface['name'] or "").lower():
            if iface.get('ip') and iface['ip'].startswith("192.168."):
                return iface
    
    # Fallback to general private IP range (192.168.x.x) if no keywords found
    for iface in interfaces:
        if iface.get('ip') and iface['ip'].startswith("192.168."):
            return iface
    return None

def main():
    print("🔐 Welcome to the Real-time Home IDPS developed by Bang Thien Nguyen, ontario1998@gmail.com.")
    print("🔎 Scanning for available network interfaces...")

    global blocked_ips_cache, global_rules, LOCAL_IP_ADDRESS, ROUTER_IP
    blocked_ips_cache = set(item.get('src_ip') for item in load_blocked_ips() if isinstance(item, dict) and 'src_ip' in item)
    global_rules = load_rules()

    print(f"✅ Loaded {len(global_rules)} rules from {RULES_FILE}.")
    print(f"✅ Loaded {len(blocked_ips_cache)} previously blocked IPs.")

    all_interfaces = get_all_interfaces()
    if not all_interfaces:
        print("No suitable network interfaces found. You may need to run as Administrator or install Npcap.")
        sys.exit(1)

    # Autodetect Wi-Fi
    selected_iface = auto_select_wifi_interface(all_interfaces)
    ROUTER_IP = get_router_ip()

    # Get interface and IP for display
    interface_name = selected_iface['name'] if selected_iface else None
    ip_address = selected_iface['ip'] if selected_iface else 'N/A'
    LOCAL_IP_ADDRESS = ip_address # Store the local IP address

    if selected_iface:
        print(f"✅ Auto-detected Wi-Fi interface: {interface_name}")
        print(f"📡 Now listening on local host IP address: {ip_address}")
        if ROUTER_IP:
            print(f"🏠 Detected router IP address: {ROUTER_IP}")
    else:
        print("❌ Could not auto-detect Wi-Fi. Please provide a valid interface name, index, or substring.")
        print_interfaces(all_interfaces)
        sys.exit(2)

    print("📡 Sniffing started. Press CTRL+C to stop the engine and save alerts.")

    try:
        sniff(iface=interface_name, prn=packet_callback, store=False, stop_filter=lambda p: STOP_SNIFFING.is_set())
        # sniff returned without exception
        print("⚠️ sniff() ended (capture loop exited).")
    except PermissionError:
        print("❌ Permission denied: sniffing requires Administrator privileges. Please run the shell as Administrator.")
    except IOError as e:
        print(f"❌ IO error while sniffing. Check if the interface '{interface_name}' exists and is up. Reason: {e}")
    except Scapy_Exception as e:
        print(f"❌ A Scapy-related error occurred: {e}")
    except KeyboardInterrupt:
        print("\n🛑 CTRL+C detected. Shutting down gracefully...")
    except Exception as e:
        print(f"❌ An unexpected error occurred while sniffing: {e}")
    finally:
        save_alerts(load_alerts())
        save_blocked_ips(load_blocked_ips())
        print("✅ IDS engine stopped and data saved.")

def signal_handler(sig, frame):
    STOP_SNIFFING.set()

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    main()