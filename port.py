#!/usr/bin/env python3
"""
AddisSec Port Scanner - Professional Interactive Edition
"""

import socket
import sys
import threading
import time
from datetime import datetime
import subprocess
import os
import json
import re

try:
    from colorama import init, Fore, Back, Style
    from pyfiglet import Figlet
    init(autoreset=True)
except ImportError:
    os.system("pip install colorama pyfiglet termcolor")
    exit()

open_ports = []
total_ports = 0
scanned_ports = 0
lock = threading.Lock()
scan_history = []
scan_start_time = 0
scan_running = False

class AddisSecScanner:
    def __init__(self):
        self.check_nmap()
        self.main_loop()

    def check_nmap(self):
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            self.nmap_available = True
        except:
            self.nmap_available = False

    def clear_screen(self):
        os.system('clear')

    def show_banner(self):
        self.clear_screen()
        print(Fore.CYAN + "=" * 60)
        f = Figlet(font='slant')
        print(Fore.MAGENTA + f.renderText('AddisSec'))
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "  Professional Port Scanner".center(58))
        print(Fore.CYAN + "=" * 60)
        print(Fore.WHITE + f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(58))
        print(Fore.CYAN + "=" * 60)
        print()

    def show_menu(self):
        print(Fore.CYAN + "-" * 50)
        print(Fore.YELLOW + "  MAIN MENU")
        print(Fore.CYAN + "-" * 50)
        print(Fore.GREEN + "  [1] Quick Scan (Top 20)")
        print(Fore.GREEN + "  [2] Standard Scan (Top 100)")
        print(Fore.GREEN + "  [3] Full Scan (1-65535)")
        print(Fore.GREEN + "  [4] Custom Range Scan")
        print(Fore.GREEN + "  [5] Scan History")
        print(Fore.GREEN + "  [6] Export Results")
        print(Fore.RED + "  [7] Exit")
        print(Fore.CYAN + "-" * 50)
        print()

    def get_target(self):
        return input(Fore.CYAN + "  Target (IP/Hostname): " + Fore.WHITE).strip()

    def get_port_range(self):
        try:
            start = int(input(Fore.CYAN + "  Start Port: " + Fore.WHITE))
            end = int(input(Fore.CYAN + "  End Port: " + Fore.WHITE))
            return start, end
        except:
            return None, None

    def format_time(self, seconds):
        if seconds < 0 or seconds == float('inf') or seconds != seconds:
            return "calc"
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds/60)}m {int(seconds%60)}s"
        else:
            return f"{int(seconds/3600)}h {int((seconds%3600)/60)}m"

    def check_host(self, target):
        """Check if target is up using ping"""
        print(Fore.YELLOW + f"\n  Checking if {target} is up...")
        
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', target], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                # Extract ping time
                time_match = re.search(r'time=(\d+\.\d+) ms', result.stdout)
                time_str = f" ({time_match.group(1)}ms)" if time_match else ""
                print(Fore.GREEN + f"  [+] Host {target} is UP{time_str}")
                return True
        except:
            pass
        
        # Try TCP connection if ping fails
        try:
            for port in [80, 443, 22, 21]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    print(Fore.GREEN + f"  [+] Host {target} is UP (port {port} reachable)")
                    return True
        except:
            pass
        
        print(Fore.RED + f"  [-] Host {target} is DOWN or unreachable")
        return False

    def scan_port(self, target, port):
        global scanned_ports, open_ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((target, port))
            sock.close()

            with lock:
                scanned_ports += 1
                if result == 0:
                    open_ports.append(port)

        except Exception:
            pass

    def display_status(self):
        global scanned_ports, open_ports, total_ports
        
        with lock:
            if total_ports == 0:
                return
                
            progress = (scanned_ports / total_ports) * 100
            elapsed = time.time() - scan_start_time
            ports_per_sec = scanned_ports / elapsed if elapsed > 0 else 0
            est_remaining = (total_ports - scanned_ports) / ports_per_sec if ports_per_sec > 0 else 0
            
            progress_color = Fore.GREEN if progress < 50 else Fore.YELLOW if progress < 80 else Fore.RED
            
            sys.stdout.write('\r')
            sys.stdout.write(f"{Fore.CYAN}Scanning:{Fore.WHITE} {scanned_ports:,}/{total_ports:,} "
                           f"{Fore.CYAN}[{progress_color}{progress:.1f}%{Fore.CYAN}] "
                           f"{Fore.GREEN}Open:{Fore.WHITE} {len(open_ports)} "
                           f"{Fore.CYAN}Speed:{Fore.WHITE} {ports_per_sec:.1f}/s "
                           f"{Fore.CYAN}ETA:{Fore.WHITE} {self.format_time(est_remaining)}")
            sys.stdout.flush()

    def run_service_detection(self, target, ports):
        """Run nmap service detection with root/non-root detection"""
        if not self.nmap_available or not ports:
            return

        try:
            # Check root privileges
            try:
                root_check = subprocess.run(['id', '-u'], capture_output=True, text=True)
                is_root = root_check.stdout.strip() == '0'
            except:
                is_root = False

            port_str = ",".join(map(str, ports[:20]))
            
            print(Fore.CYAN + "\n" + "-" * 50)
            
            # Show privilege status
            if is_root:
                print(Fore.GREEN + "  [+] Root privileges detected - Full service detection")
            else:
                print(Fore.YELLOW + "  [!] No root privileges - Limited service detection")
                print(Fore.YELLOW + "  [!] Run with: sudo python3 addissec_scanner.py for full detection")
            
            print(Fore.CYAN + "  " + "-" * 50)
            
            # Build base nmap command
            cmd = ['nmap', '-sV', '-p', port_str, '--version-intensity', '5', target]
            
            # Add OS detection only if root
            if is_root:
                cmd.append('-O')
            
            # Single line progress
            for progress in range(0, 101, 5):
                sys.stdout.write('\r')
                bar_length = 25
                filled = int(bar_length * progress / 100)
                bar = Fore.CYAN + "█" * filled + Fore.WHITE + "░" * (bar_length - filled)
                
                progress_color = Fore.GREEN if progress < 50 else Fore.YELLOW if progress < 80 else Fore.RED
                
                sys.stdout.write(f"{Fore.CYAN}Service:{Fore.WHITE} Detecting "
                               f"{Fore.CYAN}[{progress_color}{progress}%{Fore.CYAN}] "
                               f"{bar}")
                sys.stdout.flush()
                time.sleep(0.05)
            
            # Run nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Parse and display results
            lines = result.stdout.split('\n')
            service_found = False
            
            print()
            print(Fore.CYAN + "  " + "-" * 50)
            print(Fore.CYAN + "  PORT     STATE    SERVICE            VERSION")
            print(Fore.CYAN + "  " + "-" * 50)
            
            for line in lines:
                if 'open' in line and '/' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].replace('/tcp', '')
                        state = parts[1]
                        service = ' '.join(parts[2:])
                        print(Fore.GREEN + f"  {port:6s}  {state:8s}  {Fore.YELLOW}{service}")
                        service_found = True
                elif 'OS' in line and 'detection' not in line and 'Aggressive' not in line and is_root:
                    print(Fore.GREEN + f"  OS: {line.strip()}")
                elif 'Nmap done' in line:
                    print(Fore.CYAN + f"\n  {line.strip()}")
            
            if not service_found:
                print(Fore.YELLOW + "  No additional service details found")
            
            # Show root-required features not available
            if not is_root:
                print(Fore.YELLOW + "\n  [!] OS detection skipped (requires root)")
                print(Fore.YELLOW + "  [!] Some advanced features require root")
                
        except subprocess.TimeoutExpired:
            print(Fore.RED + "\n  Service detection timed out")
        except Exception as e:
            print(Fore.RED + f"\n  Service detection error: {e}")

    def start_scan(self, target, ports, scan_type):
        global open_ports, scanned_ports, total_ports, scan_start_time, scan_running

        # Check if target is up first
        if not self.check_host(target):
            input(Fore.CYAN + "\n  Press Enter to continue...")
            self.show_banner()
            self.show_menu()
            return

        open_ports = []
        scanned_ports = 0
        total_ports = len(ports)
        scan_start_time = time.time()
        scan_running = True

        self.clear_screen()
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + f"  {scan_type} SCAN")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + f"  Target: {target}")
        print(Fore.GREEN + f"  Ports: {total_ports:,}")
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "\n  Press Ctrl+C to stop\n")

        try:
            start_time = time.time()
            threads = []
            max_threads = 300

            stop_display = False
            
            def update_display():
                while not stop_display and scan_running:
                    self.display_status()
                    time.sleep(0.1)
            
            display_thread = threading.Thread(target=update_display)
            display_thread.start()

            for port in ports:
                if not scan_running:
                    break
                t = threading.Thread(target=self.scan_port, args=(target, port))
                threads.append(t)
                t.start()

                if len(threads) >= max_threads:
                    for thread in threads:
                        thread.join()
                    threads = []

            for thread in threads:
                thread.join()

            stop_display = True
            display_thread.join()

            scan_time = time.time() - start_time
            scan_running = False

            print("\n\n")
            print(Fore.CYAN + "=" * 60)
            print(Fore.GREEN + f"  SCAN COMPLETE")
            print(Fore.YELLOW + f"  Time: {scan_time:.2f}s")
            print(Fore.CYAN + f"  Open Ports: {len(open_ports)}")
            print(Fore.CYAN + "=" * 60)

            if open_ports:
                print(Fore.GREEN + "\n  OPEN PORTS:")
                print(Fore.CYAN + "  " + "-" * 40)
                for port in sorted(open_ports):
                    service = self.get_service_name(port)
                    print(Fore.GREEN + f"    [+] {port:6d} : {service}")

                if self.nmap_available and len(open_ports) > 0:
                    self.run_service_detection(target, open_ports)

                scan_entry = {
                    'target': target,
                    'scan_type': scan_type,
                    'timestamp': datetime.now().isoformat(),
                    'open_ports': sorted(open_ports),
                    'scan_time': scan_time
                }
                scan_history.append(scan_entry)

            else:
                print(Fore.RED + "\n  No open ports detected!")

        except KeyboardInterrupt:
            scan_running = False
            print(Fore.RED + "\n\n" + "=" * 60)
            print(Fore.RED + "  SCAN INTERRUPTED")
            print(Fore.RED + "=" * 60)
            print(Fore.YELLOW + f"  Scanned: {scanned_ports:,}/{total_ports:,}")
            print(Fore.YELLOW + f"  Open Ports: {len(open_ports)}")
            if open_ports:
                print(Fore.GREEN + f"  Ports: {', '.join(map(str, sorted(open_ports)))}")
            print(Fore.RED + "=" * 60)

        input(Fore.CYAN + "\n  Press Enter to continue...")
        self.show_banner()
        self.show_menu()

    def quick_scan(self):
        target = self.get_target()
        if not target:
            return
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.start_scan(target, ports, "QUICK")

    def standard_scan(self):
        target = self.get_target()
        if not target:
            return
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                 1723, 3306, 3389, 5900, 8080, 20, 69, 113, 119, 123, 137, 161, 162, 
                 389, 465, 514, 636, 873, 902, 1080, 1433, 1434, 1521, 1701, 1720, 
                 1812, 1813, 2121, 2401, 3544, 4000, 4321, 5432, 5800, 6000, 6667, 
                 7000, 8000, 8443, 8888, 9000, 9090, 10000]
        self.start_scan(target, ports, "STANDARD")

    def full_scan(self):
        target = self.get_target()
        if not target:
            return
        self.start_scan(target, range(1, 65536), "FULL")

    def custom_scan(self):
        target = self.get_target()
        if not target:
            return
        start, end = self.get_port_range()
        if start and end and start < end and start > 0 and end <= 65535:
            self.start_scan(target, range(start, end + 1), f"CUSTOM ({start}-{end})")
        else:
            print(Fore.RED + "  Invalid port range!")
            input(Fore.CYAN + "\n  Press Enter to continue...")
            self.show_banner()
            self.show_menu()

    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
            20: "FTP-DATA", 69: "TFTP", 113: "IDENT", 119: "NNTP", 123: "NTP",
            137: "NetBIOS-NS", 161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP",
            465: "SMTPS", 514: "SYSLOG", 636: "LDAPS", 873: "RSYNC",
            902: "VMWARE", 1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-MON",
            1521: "ORACLE", 1701: "L2TP", 1720: "H.323", 1812: "RADIUS",
            1813: "RADIUS-ACCT", 2121: "FTP-ALT", 2401: "CVS", 3544: "TEREDO",
            4000: "QQ", 4321: "RWHOIS", 5432: "POSTGRESQL", 5800: "VNC-HTTP",
            6000: "X11", 6667: "IRC", 7000: "AFS", 8000: "HTTP-ALT",
            8443: "HTTPS-ALT", 8888: "HTTP-PROXY", 9000: "HADOOP",
            9090: "HTTP-ADMIN", 10000: "WEBMIN"
        }
        return services.get(port, "Unknown")

    def show_history(self):
        self.clear_screen()
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "  SCAN HISTORY")
        print(Fore.CYAN + "=" * 60)

        if not scan_history:
            print(Fore.RED + "\n  No scan history")
            input(Fore.CYAN + "\n  Press Enter to continue...")
            self.show_banner()
            self.show_menu()
            return

        for i, scan in enumerate(scan_history, 1):
            print(Fore.CYAN + "\n  " + "-" * 50)
            print(Fore.GREEN + f"  [{i}] {scan['timestamp']}")
            print(Fore.CYAN + f"      Target: {scan['target']}")
            print(Fore.CYAN + f"      Type: {scan['scan_type']}")
            print(Fore.CYAN + f"      Time: {scan['scan_time']:.2f}s")
            print(Fore.CYAN + f"      Open Ports: {len(scan['open_ports'])}")
            if scan['open_ports']:
                ports_str = ', '.join(map(str, scan['open_ports'][:10]))
                if len(scan['open_ports']) > 10:
                    ports_str += f" ... (+{len(scan['open_ports'])-10} more)"
                print(Fore.YELLOW + f"      Ports: {ports_str}")

        input(Fore.CYAN + "\n  Press Enter to continue...")
        self.show_banner()
        self.show_menu()

    def export_results(self):
        if not scan_history:
            print(Fore.RED + "  No data to export!")
            input(Fore.CYAN + "\n  Press Enter to continue...")
            self.show_banner()
            self.show_menu()
            return

        filename = f"addissec_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(scan_history, f, indent=2)

        print(Fore.GREEN + f"\n  Exported: {filename}")
        print(Fore.CYAN + f"  Location: {os.path.abspath(filename)}")
        input(Fore.CYAN + "\n  Press Enter to continue...")
        self.show_banner()
        self.show_menu()

    def main_loop(self):
        self.show_banner()
        self.show_menu()
        
        while True:
            choice = input(Fore.YELLOW + "  AddisSec> " + Fore.WHITE)

            if choice == '1':
                self.quick_scan()
            elif choice == '2':
                self.standard_scan()
            elif choice == '3':
                self.full_scan()
            elif choice == '4':
                self.custom_scan()
            elif choice == '5':
                self.show_history()
            elif choice == '6':
                self.export_results()
            elif choice == '7':
                print(Fore.RED + "\n  Exiting...")
                sys.exit()
            else:
                print(Fore.RED + "  Invalid choice!")
                time.sleep(0.5)

if __name__ == "__main__":
    try:
        AddisSecScanner()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n  Interrupted")
        sys.exit()
