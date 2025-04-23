import argparse
import json
import os
import pyshark
import sys
from openai import OpenAI
from datetime import datetime

class PCAPAttackAnalyzer:
    def __init__(self, pcap_file, json_file, api_key, output_file=None):
        self.pcap_file = pcap_file
        self.json_file = json_file
        self.api_key = api_key
        self.output_file = output_file or f"attack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.target_info = None
        self.suspicious_activities = []
        self.analysis_results = {}
        
    def load_target_info(self):
        """Load target information from JSON file"""
        try:
            with open(self.json_file, 'r') as f:
                data = json.load(f)
                if 'Host Information' in data:
                    self.target_info = data['Host Information']
                    print(f"Target information loaded: {self.target_info}")
                else:
                    print("Error: Invalid JSON structure. Expected 'Host Information' key.")
                    sys.exit(1)
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            sys.exit(1)
            
    def analyze_pcap(self):
        """Analyze the PCAP file for suspicious activities"""
        try:
            print(f"Analyzing PCAP file: {self.pcap_file}")
            capture = pyshark.FileCapture(self.pcap_file)
            
            # Initialize analysis data
            connection_attempts = {}
            tcp_connections = {}
            http_requests = []
            dns_queries = []
            target_ip = self.target_info.get('ip')
            
            # Process packets
            for packet in capture:
                # Skip packets without IP layer
                if not hasattr(packet, 'ip'):
                    continue
                    
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                # Track connections to/from our target
                if target_ip and (src_ip == target_ip or dst_ip == target_ip):
                    # Track TCP connections
                    if hasattr(packet, 'tcp'):
                        conn_key = f"{src_ip}:{packet.tcp.srcport}-{dst_ip}:{packet.tcp.dstport}"
                        
                        # Track TCP flags
                        if hasattr(packet.tcp, 'flags'):
                            # Track SYN packets (potential port scanning)
                            if hasattr(packet.tcp, 'flags_syn'):
                                # Fix: Convert string 'True' to boolean/integer safely
                                syn_flag = 1 if packet.tcp.flags_syn == 'True' or packet.tcp.flags_syn == '1' else 0
                                
                                if syn_flag == 1 and dst_ip == target_ip:  # Someone scanning our target
                                    if src_ip not in connection_attempts:
                                        connection_attempts[src_ip] = []
                                    
                                    # Safely get dst port and convert to int
                                    try:
                                        dst_port = int(packet.tcp.dstport)
                                    except (ValueError, TypeError):
                                        dst_port = 0
                                        
                                    connection_attempts[src_ip].append({
                                        'port': dst_port,
                                        'timestamp': getattr(packet, 'sniff_timestamp', 'unknown')
                                    })
                                    
                            # Track established connections
                            if conn_key not in tcp_connections:
                                tcp_connections[conn_key] = {
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'src_port': packet.tcp.srcport,
                                    'dst_port': packet.tcp.dstport,
                                    'packet_count': 0,
                                    'data_size': 0
                                }
                            tcp_connections[conn_key]['packet_count'] += 1
                            if hasattr(packet, 'length'):
                                # Fix: Handle non-integer length values safely
                                try:
                                    length = int(packet.length)
                                except (ValueError, TypeError):
                                    length = 0
                                tcp_connections[conn_key]['data_size'] += length
                    
                    # Track HTTP traffic
                    if hasattr(packet, 'http'):
                        http_data = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'timestamp': getattr(packet, 'sniff_timestamp', 'unknown'),
                        }
                        
                        # Extract HTTP method and URI
                        if hasattr(packet.http, 'request_method'):
                            http_data['method'] = packet.http.request_method
                        if hasattr(packet.http, 'request_uri'):
                            http_data['uri'] = packet.http.request_uri
                        if hasattr(packet.http, 'user_agent'):
                            http_data['user_agent'] = packet.http.user_agent
                            
                        http_requests.append(http_data)
                
                # Track DNS queries
                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    dns_queries.append({
                        'src_ip': src_ip,
                        'query': packet.dns.qry_name,
                        'timestamp': getattr(packet, 'sniff_timestamp', 'unknown')
                    })
            
            # Analyze the collected data
            
            # 1. Check for port scanning
            for src_ip, attempts in connection_attempts.items():
                if len(attempts) > 5:  # Threshold for suspicious port scanning
                    unique_ports = len(set(attempt['port'] for attempt in attempts))
                    self.suspicious_activities.append({
                        'type': 'port_scan',
                        'source_ip': src_ip,
                        'target_ip': target_ip,
                        'unique_ports': unique_ports,
                        'total_attempts': len(attempts)
                    })
            
            # 2. Check for suspicious HTTP traffic
            suspicious_uris = ['/admin', '/login', '/wp-admin', '/phpMyAdmin', '/shell', '/.env', '/config']
            for req in http_requests:
                if 'uri' in req:
                    for pattern in suspicious_uris:
                        if pattern in req['uri']:
                            self.suspicious_activities.append({
                                'type': 'suspicious_http',
                                'source_ip': req['src_ip'],
                                'target_ip': req['dst_ip'],
                                'uri': req['uri'],
                                'timestamp': req['timestamp']
                            })
            
            # Initialize dictionary structure to prevent KeyError later
            self.analysis_results = {
                'target_info': self.target_info,
                'suspicious_activities': self.suspicious_activities,
                'connection_summary': {
                    'total_connections': len(tcp_connections),
                    'unique_source_ips': len(set(conn['src_ip'] for conn in tcp_connections.values() 
                                               if conn['dst_ip'] == target_ip)) if tcp_connections else 0,
                    'top_connections': []
                },
                'http_summary': {
                    'total_requests': len(http_requests),
                    'unique_uris': len(set(req['uri'] for req in http_requests if 'uri' in req))
                },
                'dns_summary': {
                    'total_queries': len(dns_queries),
                    'unique_domains': len(set(q['query'] for q in dns_queries))
                }
            }
            
            # Add top connections if we have any
            if tcp_connections:
                top_connections = sorted(
                    [{'source_ip': c['src_ip'], 'count': c['packet_count']} 
                     for c in tcp_connections.values() if c['dst_ip'] == target_ip],
                    key=lambda x: x['count'], reverse=True)[:5]
                self.analysis_results['connection_summary']['top_connections'] = top_connections
            
            print(f"PCAP analysis complete. Found {len(self.suspicious_activities)} suspicious activities.")
            
        except Exception as e:
            import traceback
            print(f"Error analyzing PCAP file: {e}")
            print(traceback.format_exc())
            # Initialize with empty values to prevent further errors
            self.analysis_results = {
                'target_info': self.target_info,
                'suspicious_activities': self.suspicious_activities,
                'connection_summary': {'total_connections': 0, 'unique_source_ips': 0, 'top_connections': []},
                'http_summary': {'total_requests': 0, 'unique_uris': 0},
                'dns_summary': {'total_queries': 0, 'unique_domains': 0}
            }
            
    def get_ai_analysis(self):
        """Get attack analysis from Mistral AI"""
        try:
            # Make sure we have analysis_results populated
            if not self.analysis_results:
                self.analysis_results = {
                    'target_info': self.target_info,
                    'suspicious_activities': self.suspicious_activities,
                    'connection_summary': {'total_connections': 0, 'unique_source_ips': 0, 'top_connections': []},
                    'http_summary': {'total_requests': 0, 'unique_uris': 0},
                    'dns_summary': {'total_queries': 0, 'unique_domains': 0}
                }
            
            prompt = f"""
Analyze the following network traffic data and identify potential attacks:

TARGET INFORMATION:
MAC: {self.target_info.get('mac', 'Unknown')}
IP: {self.target_info.get('ip', 'Unknown')}
Hostname: {self.target_info.get('hostname', 'Unknown')}
Username: {self.target_info.get('username', 'Unknown')}

SUSPICIOUS ACTIVITIES DETECTED:
{json.dumps(self.suspicious_activities, indent=2)}

CONNECTION SUMMARY:
- Total connections: {self.analysis_results['connection_summary']['total_connections']}
- Unique source IPs connecting to target: {self.analysis_results['connection_summary']['unique_source_ips']}
- Top connections by packet count: {json.dumps(self.analysis_results['connection_summary'].get('top_connections', []), indent=2)}

HTTP SUMMARY:
- Total HTTP requests: {self.analysis_results['http_summary']['total_requests']}
- Unique URIs requested: {self.analysis_results['http_summary']['unique_uris']}

DNS SUMMARY:
- Total DNS queries: {self.analysis_results['dns_summary']['total_queries']}
- Unique domains queried: {self.analysis_results['dns_summary']['unique_domains']}

Based on this information:
1. Is there evidence of an attack? If so, what type of attack?
2. Which IP address appears to be the attacker?
3. What was the attack methodology used?
4. What might be the attacker's objective?
5. What defensive measures would you recommend?
"""
            
            print("Sending analysis to Mistral AI...")
            client = OpenAI(
                base_url="https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1",
                api_key=self.api_key
            )
            
            response = client.chat.completions.create(
                model="mistral-nemo-instruct-2407",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specialized in network traffic analysis and attack detection."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1024,
                temperature=0.3,
                top_p=1
            )
            
            ai_analysis = response.choices[0].message.content
            print("AI analysis received.")
            
            return ai_analysis
            
        except Exception as e:
            import traceback
            print(f"Error getting AI analysis: {e}")
            print(traceback.format_exc())
            return "Error: Could not get AI analysis due to an unexpected error."
    
    def save_results(self, ai_analysis):
        """Save analysis results to output file"""
        try:
            # Make sure we have analysis_results populated
            if not self.analysis_results:
                self.analysis_results = {
                    'target_info': self.target_info,
                    'suspicious_activities': self.suspicious_activities,
                    'connection_summary': {'total_connections': 0, 'unique_source_ips': 0, 'top_connections': []},
                    'http_summary': {'total_requests': 0, 'unique_uris': 0},
                    'dns_summary': {'total_queries': 0, 'unique_domains': 0}
                }
            
            with open(self.output_file, 'w') as f:
                f.write("=== PCAP ATTACK ANALYSIS REPORT ===\n\n")
                f.write(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"PCAP File: {self.pcap_file}\n")
                f.write(f"Target Info File: {self.json_file}\n\n")
                
                f.write("TARGET INFORMATION:\n")
                f.write(f"MAC: {self.target_info.get('mac', 'Unknown')}\n")
                f.write(f"IP: {self.target_info.get('ip', 'Unknown')}\n")
                f.write(f"Hostname: {self.target_info.get('hostname', 'Unknown')}\n")
                f.write(f"Username: {self.target_info.get('username', 'Unknown')}\n\n")
                
                f.write("SUSPICIOUS ACTIVITIES DETECTED:\n")
                if self.suspicious_activities:
                    for i, activity in enumerate(self.suspicious_activities, 1):
                        f.write(f"Activity {i}:\n")
                        for key, value in activity.items():
                            f.write(f"  {key}: {value}\n")
                        f.write("\n")
                else:
                    f.write("No suspicious activities detected.\n\n")
                
                f.write("CONNECTION SUMMARY:\n")
                f.write(f"- Total connections: {self.analysis_results['connection_summary']['total_connections']}\n")
                f.write(f"- Unique source IPs connecting to target: {self.analysis_results['connection_summary']['unique_source_ips']}\n")
                f.write("- Top connections by packet count:\n")
                for conn in self.analysis_results['connection_summary'].get('top_connections', []):
                    f.write(f"  {conn['source_ip']}: {conn['count']} packets\n")
                f.write("\n")
                
                f.write("AI ANALYSIS:\n")
                f.write("=" * 40 + "\n")
                f.write(ai_analysis)
                f.write("\n" + "=" * 40 + "\n")
                
                print(f"Results saved to {self.output_file}")
                # Also display summary to console
                print("\n=== SUMMARY ===")
                print(f"Target IP: {self.target_info.get('ip', 'Unknown')}")
                print(f"Suspicious activities: {len(self.suspicious_activities)}")
                print(f"Full report saved to: {self.output_file}")
                
        except Exception as e:
            import traceback
            print(f"Error saving results: {e}")
            print(traceback.format_exc())
    
    def run_analysis(self):
        """Run the complete analysis pipeline"""
        self.load_target_info()
        self.analyze_pcap()
        ai_analysis = self.get_ai_analysis()
        self.save_results(ai_analysis)

def main():
    parser = argparse.ArgumentParser(description='PCAP Attack Analyzer with AI')
    parser.add_argument('-p', '--pcap', required=True, help='PCAP file to analyze')
    parser.add_argument('-j', '--json', required=True, help='Target information JSON file (from analyze_network.py)')
    parser.add_argument('-k', '--key', required=True, help='Mistral API key')
    parser.add_argument('-o', '--output', help='Output analysis file')
    
    args = parser.parse_args()
    
    # Validate input files
    if not os.path.isfile(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    if not os.path.isfile(args.json):
        print(f"Error: JSON file not found: {args.json}")
        sys.exit(1)
    
    analyzer = PCAPAttackAnalyzer(
        pcap_file=args.pcap,
        json_file=args.json,
        api_key=args.key,
        output_file=args.output
    )
    
    analyzer.run_analysis()

if __name__ == "__main__":
    main()