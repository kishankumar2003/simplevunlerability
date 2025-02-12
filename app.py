from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import os
from dotenv import load_dotenv
import requests
import json
from datetime import datetime, timedelta
import psutil
import platform
import sys
from packaging import version
import socket
import threading
import time
import concurrent.futures

# Load environment variables
load_dotenv()

app = Flask(__name__, 
    static_url_path='',
    static_folder='static',
    template_folder='templates'
)

CORS(app, resources={
    r"/*": {
        "origins": "*",  # For development, you might want to restrict this in production
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# NVD API base URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_network_interfaces():
    interfaces = []
    try:
        # Get hostname and IP
        hostname = socket.gethostname()
        host_ip = socket.gethostbyname(hostname)
        
        # Get all network interfaces using psutil
        net_if_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in net_if_addrs.items():
            for addr in interface_addresses:
                if addr.family == socket.AF_INET:  # Only IPv4 addresses
                    interfaces.append({
                        'interface': interface_name,
                        'ip': addr.address,
                        'netmask': addr.netmask if hasattr(addr, 'netmask') else 'Unknown'
                    })
    except Exception as e:
        print(f"Error getting network interfaces: {str(e)}")
    return interfaces

class NetworkScanner:
    def __init__(self):
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
        
    def scan_port(self, ip, port, timeout=2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                        # Try to get banner information
                        banner = ""
                        try:
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        except:
                            pass
                        
                        return {
                            'port': port,
                            'state': 'open',
                            'service': service,
                            'version': banner if banner else 'unknown',
                            'product': self.guess_product(service, banner)
                        }
                    except:
                        return {
                            'port': port,
                            'state': 'open',
                            'service': 'unknown',
                            'version': 'unknown',
                            'product': 'unknown'
                        }
        except:
            pass
        return None

    def guess_product(self, service, banner):
        """Try to guess the product based on service and banner information"""
        if not banner:
            return 'unknown'
            
        banner = banner.lower()
        if 'apache' in banner:
            return 'Apache'
        elif 'nginx' in banner:
            return 'Nginx'
        elif 'microsoft' in banner:
            return 'Microsoft'
        elif 'ssh' in banner:
            return 'OpenSSH'
        elif 'mysql' in banner:
            return 'MySQL'
        return 'unknown'

    def get_os_info(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                'name': 'Unknown',
                'accuracy': '0',
                'version': 'Unknown',
                'hostname': hostname
            }
        except:
            return {
                'name': 'Unknown',
                'accuracy': '0',
                'version': 'Unknown',
                'hostname': 'Unknown'
            }

    def scan_host(self, ip):
        try:
            # Check if host is up using a more reliable method
            try:
                socket.gethostbyaddr(ip)
                is_up = True
            except socket.herror:
                # If hostname lookup fails, try connecting to common ports
                is_up = False
                common_check_ports = [80, 443, 22, 3389]
                for port in common_check_ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            if sock.connect_ex((ip, port)) == 0:
                                is_up = True
                                break
                    except:
                        continue

            if not is_up:
                return None

            # Scan ports in parallel with increased timeout
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, ip, port, timeout=2): port 
                    for port in self.common_ports
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)

            # Get OS info
            os_info = self.get_os_info(ip)
            
            host_info = {
                'ip': ip,
                'status': 'up',
                'hostname': os_info['hostname'],
                'os': {
                    'name': os_info['name'],
                    'accuracy': os_info['accuracy'],
                    'version': os_info['version']
                },
                'ports': sorted(open_ports, key=lambda x: x['port']),
                'vulnerabilities': []
            }
            
            # Match vulnerabilities based on detected services
            host_info['vulnerabilities'] = self.match_vulnerabilities(host_info)
            return host_info
        except Exception as e:
            print(f"Error scanning host {ip}: {str(e)}")
            return None

    def expand_ip_range(self, target):
        try:
            if '/' in target:  # CIDR notation
                network = target.split('/')[0]
                bits = int(target.split('/')[1])
                netmask = (1 << 32) - (1 << (32 - bits))
                network_int = sum(int(x) << (24 - 8 * i) for i, x in enumerate(network.split('.')))
                start = network_int & netmask
                end = start | ((1 << (32 - bits)) - 1)
                return [f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"
                       for ip in range(start, end + 1)]
            elif '-' in target:  # Range notation (e.g., 192.168.1.1-10)
                start_ip = target.split('-')[0]
                end_num = int(target.split('-')[1])
                base_ip = '.'.join(start_ip.split('.')[:-1])
                start_num = int(start_ip.split('.')[-1])
                return [f"{base_ip}.{num}" for num in range(start_num, end_num + 1)]
            else:  # Single IP
                # Validate IP address format
                socket.inet_aton(target)  # This will raise an error if IP is invalid
                return [target]
        except Exception as e:
            print(f"Error expanding IP range: {str(e)}")
            return []

    def scan_network(self, target, scan_type='basic'):
        try:
            ip_list = self.expand_ip_range(target)
            if not ip_list:
                return []

            results = []
            max_workers = 10 if scan_type == 'basic' else 5  # Reduce workers for comprehensive scan
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ip_list}
                for future in concurrent.futures.as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        results.append(result)
            
            # Sort results by IP address
            results.sort(key=lambda x: sum(int(part) << (24 - 8 * i) 
                                         for i, part in enumerate(x['ip'].split('.'))))
            return results
        except Exception as e:
            print(f"Scan error: {str(e)}")
            return []
    
    def match_vulnerabilities(self, host_info):
        vulnerabilities = []
        
        # Check OS vulnerabilities
        if host_info['os']['name'] != 'Unknown':
            os_name = host_info['os']['name']
            os_version = host_info['os']['version']
            
            # Create multiple search queries for better matching
            os_queries = [
                f"{os_name} {os_version}",
                os_name,
                f"{os_name} vulnerability",
                f"{os_name} exploit"
            ]
            
            for query in os_queries:
                os_vulns = query_nvd(query)
                if os_vulns:
                    for vuln in os_vulns:
                        # Check if this vulnerability is already added
                        if not any(v['id'] == vuln['id'] for v in vulnerabilities):
                            vuln['matched_component'] = f"Operating System ({os_name} {os_version})"
                            vuln['severity_level'] = self.get_severity_level(vuln.get('severity', 'UNKNOWN'))
                            vuln['match_type'] = 'os'
                            vuln['match_confidence'] = self.calculate_match_confidence(query, vuln)
                            vulnerabilities.append(vuln)
        
        # Check service vulnerabilities
        for port in host_info['ports']:
            if port['service'] and port['service'] != 'unknown':
                service = port['service']
                product = port['product']
                version = port['version']
                
                # Create multiple search queries for better matching
                service_queries = []
                if product != 'unknown':
                    service_queries.extend([
                        f"{product} {version}",
                        f"{product} vulnerability",
                        f"{service} {product}"
                    ])
                
                service_queries.extend([
                    service,
                    f"{service} vulnerability",
                    f"{service} exploit"
                ])
                
                for query in service_queries:
                    service_vulns = query_nvd(query)
                    if service_vulns:
                        for vuln in service_vulns:
                            # Check if this vulnerability is already added
                            if not any(v['id'] == vuln['id'] for v in vulnerabilities):
                                vuln['matched_component'] = f"Service ({service} on port {port['port']})"
                                if product != 'unknown':
                                    vuln['matched_component'] += f" - {product} {version}"
                                vuln['severity_level'] = self.get_severity_level(vuln.get('severity', 'UNKNOWN'))
                                vuln['match_type'] = 'service'
                                vuln['match_confidence'] = self.calculate_match_confidence(query, vuln)
                                vulnerabilities.append(vuln)
        
        # Sort vulnerabilities by severity level and match confidence
        vulnerabilities.sort(key=lambda x: (x.get('severity_level', 4), -x.get('match_confidence', 0)))
        
        # Add exploit availability information
        for vuln in vulnerabilities:
            vuln['exploit_available'] = self.check_exploit_availability(vuln['id'])
            vuln['remediation'] = self.generate_remediation_advice(vuln)
        
        return vulnerabilities
    
    def calculate_match_confidence(self, query, vuln):
        """Calculate a confidence score for the vulnerability match"""
        confidence = 0
        
        # Check if query terms appear in vulnerability description
        query_terms = query.lower().split()
        description = vuln.get('description', '').lower()
        
        for term in query_terms:
            if term in description:
                confidence += 20  # 20 points for each matching term
        
        # Add points based on vulnerability metadata
        if vuln.get('baseScore'):
            confidence += 10  # 10 points if it has a CVSS score
        
        if vuln.get('references'):
            confidence += 5  # 5 points if it has references
        
        # Normalize confidence score to 0-100 range
        return min(confidence, 100)
    
    def check_exploit_availability(self, cve_id):
        """Check if exploits are available for this CVE"""
        try:
            # Query exploit-db (this is a mock implementation)
            # In a real implementation, you would query exploit-db or other sources
            return {
                'available': False,
                'sources': [],
                'last_checked': datetime.now().isoformat()
            }
        except:
            return {
                'available': False,
                'sources': [],
                'last_checked': datetime.now().isoformat()
            }
    
    def generate_remediation_advice(self, vuln):
        """Generate remediation advice based on vulnerability type"""
        severity = vuln.get('severity', 'UNKNOWN').upper()
        description = vuln.get('description', '')
        
        remediation = {
            'priority': self.get_remediation_priority(severity),
            'general_advice': self.get_general_remediation_advice(severity),
            'specific_steps': []
        }
        
        # Add specific remediation steps based on vulnerability type
        if 'buffer overflow' in description.lower():
            remediation['specific_steps'].append('Update affected software to latest version')
            remediation['specific_steps'].append('Enable DEP/ASLR if available')
        elif 'sql injection' in description.lower():
            remediation['specific_steps'].append('Use prepared statements or stored procedures')
            remediation['specific_steps'].append('Implement input validation')
            remediation['specific_steps'].append('Update database access layer')
        elif 'cross-site scripting' in description.lower():
            remediation['specific_steps'].append('Implement output encoding')
            remediation['specific_steps'].append('Use Content Security Policy (CSP)')
            remediation['specific_steps'].append('Validate and sanitize user input')
        
        if not remediation['specific_steps']:
            remediation['specific_steps'].append('Update affected software to latest version')
            remediation['specific_steps'].append('Apply security patches if available')
            remediation['specific_steps'].append('Monitor vendor announcements for updates')
        
        return remediation
    
    def get_remediation_priority(self, severity):
        """Get remediation priority based on severity"""
        priority_map = {
            'CRITICAL': 'Immediate action required (24-48 hours)',
            'HIGH': 'Urgent action required (1 week)',
            'MEDIUM': 'Plan remediation within 1 month',
            'LOW': 'Fix during next maintenance window',
            'UNKNOWN': 'Evaluate risk and prioritize accordingly'
        }
        return priority_map.get(severity, priority_map['UNKNOWN'])
    
    def get_general_remediation_advice(self, severity):
        """Get general remediation advice based on severity"""
        advice_map = {
            'CRITICAL': 'Immediate patching required. Consider taking affected systems offline until patched.',
            'HIGH': 'Schedule emergency patch window. Implement temporary mitigations if patching is delayed.',
            'MEDIUM': 'Include in next patch cycle. Monitor for exploitation attempts.',
            'LOW': 'Fix during regular maintenance. Monitor for changes in severity.',
            'UNKNOWN': 'Further investigation required to determine appropriate action.'
        }
        return advice_map.get(severity, advice_map['UNKNOWN'])
    
    def get_severity_level(self, severity):
        severity_map = {
            'CRITICAL': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'UNKNOWN': 4
        }
        return severity_map.get(severity.upper(), 4)

def get_system_info():
    system_info = {
        'os': {
            'name': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'machine': platform.machine()
        },
        'python_version': sys.version.split()[0],
        'installed_software': [],
        'network_interfaces': get_network_interfaces()
    }
    
    # Get running processes
    processes = set()
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            proc_name = proc.info['name'].lower()
            if proc_name and not proc_name.startswith(('system', 'registry', 'memory')):
                processes.add(proc_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    system_info['installed_software'] = sorted(list(processes))
    return system_info

def query_nvd(search_term):
    params = {
        'keywordSearch': search_term,
        'resultsPerPage': 10
    }
    
    try:
        response = requests.get(NVD_API_BASE, params=params)
        if response.status_code == 200:
            data = response.json()
            results = []
            
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                vuln_data = {
                    'id': cve.get('id', ''),
                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                    'severity': 'N/A',
                    'published': cve.get('published', ''),
                    'lastModified': cve.get('lastModified', '')
                }
                
                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                if metrics:
                    cvss_data = metrics.get('cvssData', {})
                    vuln_data['severity'] = cvss_data.get('baseSeverity', 'N/A')
                    vuln_data['baseScore'] = cvss_data.get('baseScore', 'N/A')
                
                results.append(vuln_data)
            
            return results
    except Exception as e:
        print(f"Error querying NVD: {str(e)}")
        return []

scanner = NetworkScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/scan_network', methods=['POST'])
def scan_network():
    try:
        target = request.json.get('target', '')
        scan_type = request.json.get('scan_type', 'basic')
        
        if not target:
            return jsonify({'error': 'Target IP or range is required'}), 400
        
        results = scanner.scan_network(target, scan_type)
        return jsonify({
            'scan_results': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan_system', methods=['GET'])
def scan_system():
    try:
        system_info = get_system_info()
        vulnerabilities = scanner.match_vulnerabilities({
            'os': system_info['os'],
            'ports': [],
            'services': system_info['installed_software']
        })
        
        return jsonify({
            'system_info': system_info,
            'vulnerabilities': vulnerabilities
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search', methods=['POST'])
def search_vulnerabilities():
    search_term = request.json.get('search_term', '')
    vulnerabilities = query_nvd(search_term)
    
    if vulnerabilities:
        return jsonify({'vulnerabilities': vulnerabilities})
    else:
        return jsonify({'error': 'No vulnerabilities found'}), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
