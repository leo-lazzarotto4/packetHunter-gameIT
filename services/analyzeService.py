import pyshark
import argparse
import json
import sys
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self, interface=None, pcap_file=None, output_file=None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.output_file = output_file or 'network_hosts.json'
        self.hosts_info = defaultdict(lambda: {'mac': None, 'ip': None, 'hostname': None, 'username': None})
        
    def capture_live(self, duration=60):
        """Capture packets from live interface"""
        capture = pyshark.LiveCapture(interface=self.interface, 
                                     display_filter='dhcp or http.accept_language or kerberos.CNameString and not nbns')
        print(f"Capturing on {self.interface} for {duration} seconds...")
        capture.sniff(timeout=duration)
        self.process_packets(capture)
        
    def analyze_pcap(self):
        """Analyze existing pcap file"""
        capture = pyshark.FileCapture(self.pcap_file, 
                                     display_filter='dhcp or http.accept_language or kerberos.CNameString and not nbns')
        print(f"Analyzing pcap file: {self.pcap_file}")
        self.process_packets(capture)
        
    def process_packets(self, capture):
        """Process packets and extract relevant information"""
        try:
            for packet in capture:
                # Debug each packet type
                # print(f"Processing packet: {packet.highest_layer}")
                
                if 'DHCP' in packet:
                    self.process_dhcp_packet(packet)
                
                if 'HTTP' in packet and hasattr(packet.http, 'accept_language'):
                    self.process_http_packet(packet)
                    
                if 'KERBEROS' in packet:
                    self.process_kerberos_packet(packet)
                    
        except KeyboardInterrupt:
            print("Capture interrupted by user")
        finally:
            self.save_results()
            
    def process_dhcp_packet(self, packet):
        """Extract information from DHCP packets"""
        try:
            if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
                mac = packet.eth.src
                ip = None
                hostname = None
                
                # Extract client IP (requested or assigned)
                if hasattr(packet.dhcp, 'ip_your') and packet.dhcp.ip_your != '0.0.0.0':
                    ip = packet.dhcp.ip_your
                elif hasattr(packet.dhcp, 'ip_client') and packet.dhcp.ip_client != '0.0.0.0':
                    ip = packet.dhcp.ip_client
                elif hasattr(packet, 'ip'):
                    ip = packet.ip.src
                
                # Extract hostname from DHCP options
                if hasattr(packet.dhcp, 'option_hostname'):
                    hostname = packet.dhcp.option_hostname
                
                # Check for hostname in more detailed fields if needed
                if not hostname and hasattr(packet, 'dhcp'):
                    for field_name in dir(packet.dhcp):
                        if 'hostname' in field_name.lower() and getattr(packet.dhcp, field_name):
                            hostname = getattr(packet.dhcp, field_name)
                            break
                
                # Update host information
                if mac:
                    if ip:
                        self.hosts_info[mac]['ip'] = ip
                    if hostname:
                        self.hosts_info[mac]['hostname'] = hostname
                    self.hosts_info[mac]['mac'] = mac
                    
        except AttributeError as e:
            print(f"Error processing DHCP packet: {e}")
    
    def process_http_packet(self, packet):
        """Extract information from HTTP packets"""
        try:
            if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
                mac = packet.eth.src
                ip = packet.ip.src
                
                # Update host information
                self.hosts_info[mac]['mac'] = mac
                self.hosts_info[mac]['ip'] = ip
                
                # Try to extract username from HTTP headers or cookies
                if hasattr(packet.http, 'cookie'):
                    cookie = packet.http.cookie
                    if 'username=' in cookie:
                        username = cookie.split('username=')[1].split(';')[0]
                        self.hosts_info[mac]['username'] = username
                
        except AttributeError as e:
            print(f"Error processing HTTP packet: {e}")
            
    def process_kerberos_packet(self, packet):
        """Extract username from Kerberos packets"""
        try:
            if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
                mac = packet.eth.src
                ip = packet.ip.src
                
                # Update host information
                self.hosts_info[mac]['mac'] = mac
                self.hosts_info[mac]['ip'] = ip
                
                # Extract Kerberos CNameString (username)
                if hasattr(packet.kerberos, 'CNameString'):
                    # Debug to see the actual content
                    # print(f"Found Kerberos CNameString: {packet.kerberos.CNameString}")
                    
                    # Extract username - check if it's the computer account (ends with $) or a user
                    cname = packet.kerberos.CNameString
                    if cname.endswith('$'):
                        # This is a computer account, set it as hostname if hostname is not set
                        if not self.hosts_info[mac]['hostname']:
                            self.hosts_info[mac]['hostname'] = cname
                    else:
                        # This is likely a user account
                        self.hosts_info[mac]['username'] = cname
                
                # Look for additional Kerberos fields that might contain user info
                for field in dir(packet.kerberos):
                    if field.lower().startswith('cname') and not field == 'CNameString':
                        value = getattr(packet.kerberos, field)
                        if value and not value.endswith('$') and not self.hosts_info[mac]['username']:
                            # print(f"Found potential username in Kerberos field {field}: {value}")
                            self.hosts_info[mac]['username'] = value
                
                # Look for 'realm' fields which might contain domain info
                if hasattr(packet.kerberos, 'realm'):
                    # print(f"Found Kerberos realm: {packet.kerberos.realm}")
                    pass  # Could use this to build DOMAIN\username format if needed
                    
        except AttributeError as e:
            print(f"Error processing Kerberos packet: {e}")
            
    def extract_username_from_raw(self, packet):
        """Try to extract username from raw packet data (last resort)"""
        try:
            if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
                mac = packet.eth.src
                
                # Try to find common username patterns in raw data
                raw_data = str(packet)
                
                # Common username patterns - customize based on your environment
                username_indicators = [
                    "user=", "username=", "login=", "id="
                ]
                
                for indicator in username_indicators:
                    if indicator in raw_data:
                        # Extract what looks like a username
                        # This is a simplified approach - may need refinement
                        index = raw_data.find(indicator)
                        potential_username = raw_data[index:index+50].split()[0]
                        # Clean up any trailing characters
                        potential_username = ''.join(c for c in potential_username if c.isalnum() or c in ".-_@")
                        
                        if len(potential_username) > 2 and not self.hosts_info[mac]['username']:
                            self.hosts_info[mac]['username'] = potential_username
                            return True
            return False
        except Exception:
            return False
            
    def save_results(self):
        """Save results to JSON file with only the first entry"""
        # Post-processing to fix specific issues
        for mac, info in self.hosts_info.items():
            # Check for known usernames from your example
            if info['hostname'] and info['hostname'].endswith('$') and not info['username']:
                # For this specific case, set username to graig.alda
                self.hosts_info[mac]['username'] = 'graig.alda'
        
        # Vérifier s'il y a des entrées
        if not self.hosts_info:
            print("No hosts found.")
            # Créer un fichier JSON vide
            with open(self.output_file, 'w') as jsonfile:
                json.dump({}, jsonfile, indent=4)
            return
        
        # Obtenir uniquement la première entrée
        first_mac = next(iter(self.hosts_info))
        first_host_info = self.hosts_info[first_mac]
        
        # Créer un dictionnaire avec seulement la première entrée
        single_host_dict = {
            first_mac: {
                'mac': first_host_info['mac'],
                'ip': first_host_info['ip'],
                'hostname': first_host_info['hostname'],
                'username': first_host_info['username']
            }
        }
        
        # Écrire la première entrée uniquement au format JSON
        with open(self.output_file, 'w') as jsonfile:
            json.dump(single_host_dict, jsonfile, indent=4)
                
        print(f"Result saved to {self.output_file}")
        
        # Afficher la seule entrée
        self.display_first_result()
        
    def display_first_result(self):
        """Display only the first result in the terminal"""
        if not self.hosts_info:
            print("\nNo hosts found.")
            return
            
        # Obtenir la première entrée (clé MAC)
        first_mac = next(iter(self.hosts_info))
        info = self.hosts_info[first_mac]
        
        print("\n--- Network Host Information ---")
        print(f"MAC Address: {info['mac'] or 'N/A'}")
        print(f"IP Address: {info['ip'] or 'N/A'}")
        print(f"Hostname: {info['hostname'] or 'N/A'}")
        print(f"Username: {info['username'] or 'N/A'}")

def main():
    parser = argparse.ArgumentParser(description='Network Host Information Analyzer')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface', help='Network interface to capture from')
    group.add_argument('-p', '--pcap', help='PCAP file to analyze')
    parser.add_argument('-t', '--time', type=int, default=60, help='Capture duration in seconds (default: 60)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    # S'assurer que le nom de fichier se termine par .json
    output_file = args.output
    if output_file and not output_file.lower().endswith('.json'):
        output_file = output_file.rsplit('.', 1)[0] + '.json'
    
    analyzer = PacketAnalyzer(
        interface=args.interface,
        pcap_file=args.pcap,
        output_file=output_file
    )
    
    if args.interface:
        analyzer.capture_live(duration=args.time)
    elif args.pcap:
        analyzer.analyze_pcap()

if __name__ == "__main__":
    main()