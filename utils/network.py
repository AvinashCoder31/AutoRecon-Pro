"""
AutoRecon-Pro Network Utilities
Network-related functions for target validation, DNS resolution, and connectivity checks
"""

import socket
import ipaddress
import dns.resolver
import dns.reversename
import requests
import subprocess
import re
import time
import logging
from typing import List, Dict, Tuple, Optional, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

logger = logging.getLogger(__name__)

class NetworkUtils:
    """
    Network utility functions for AutoRecon-Pro
    """
    
    def __init__(self):
        """
        Initialize NetworkUtils with default configurations
        """
        self.dns_servers = [
            '8.8.8.8',      # Google
            '8.8.4.4',      # Google
            '1.1.1.1',      # Cloudflare
            '1.0.0.1',      # Cloudflare
            '208.67.222.222', # OpenDNS
            '208.67.220.220'  # OpenDNS
        ]
        self.timeout = 5
        self.max_threads = 50
        self._lock = threading.Lock()
    
    def resolve_hostname(self, hostname: str, record_type: str = 'A') -> List[str]:
        """
        Resolve hostname to IP addresses
        
        Args:
            hostname (str): Hostname to resolve
            record_type (str): DNS record type (A, AAAA, CNAME, MX, etc.)
            
        Returns:
            List[str]: List of resolved addresses
        """
        resolved_addresses = []
        
        try:
            # Configure DNS resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout * 2
            
            # Perform DNS query
            answers = resolver.resolve(hostname, record_type)
            
            for answer in answers:
                if record_type in ['A', 'AAAA']:
                    resolved_addresses.append(str(answer))
                elif record_type == 'CNAME':
                    resolved_addresses.append(str(answer.target))
                elif record_type == 'MX':
                    resolved_addresses.append(f"{answer.preference} {answer.exchange}")
                elif record_type == 'TXT':
                    resolved_addresses.append(str(answer))
                else:
                    resolved_addresses.append(str(answer))
            
            logger.debug(f"Resolved {hostname} ({record_type}): {resolved_addresses}")
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain not found: {hostname}")
        except dns.resolver.Timeout:
            logger.warning(f"DNS timeout for {hostname}")
        except Exception as e:
            logger.error(f"DNS resolution error for {hostname}: {str(e)}")
        
        return resolved_addresses
    
    def reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup
        
        Args:
            ip_address (str): IP address to lookup
            
        Returns:
            Optional[str]: Hostname if found, None otherwise
        """
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            # Perform reverse lookup
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            resolver.timeout = self.timeout
            
            reverse_name = dns.reversename.from_address(ip_address)
            answers = resolver.resolve(reverse_name, 'PTR')
            
            hostname = str(answers[0]).rstrip('.')
            logger.debug(f"Reverse DNS for {ip_address}: {hostname}")
            return hostname
            
        except Exception as e:
            logger.debug(f"Reverse DNS lookup failed for {ip_address}: {str(e)}")
            return None
    
    def is_host_alive(self, host: str, method: str = 'ping') -> bool:
        """
        Check if host is alive using various methods
        
        Args:
            host (str): Host to check
            method (str): Method to use ('ping', 'tcp', 'http')
            
        Returns:
            bool: True if host is alive, False otherwise
        """
        if method == 'ping':
            return self._ping_host(host)
        elif method == 'tcp':
            return self._tcp_connect(host, 80) or self._tcp_connect(host, 443)
        elif method == 'http':
            return self._http_check(host)
        else:
            # Try multiple methods
            return (self._ping_host(host) or 
                   self._tcp_connect(host, 80) or 
                   self._tcp_connect(host, 443))
    
    def _ping_host(self, host: str) -> bool:
        """
        Ping host to check connectivity
        
        Args:
            host (str): Host to ping
            
        Returns:
            bool: True if ping successful, False otherwise
        """
        try:
            # Determine ping command based on OS
            import platform
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', '3000', host]
            else:
                cmd = ['ping', '-c', '1', '-W', '3', host]
            
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=10
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _tcp_connect(self, host: str, port: int) -> bool:
        """
        Test TCP connection to host:port
        
        Args:
            host (str): Host to connect to
            port (int): Port to connect to
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    def _http_check(self, host: str) -> bool:
        """
        Check HTTP/HTTPS connectivity
        
        Args:
            host (str): Host to check
            
        Returns:
            bool: True if HTTP/HTTPS accessible, False otherwise
        """
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{host}"
                response = requests.head(
                    url, 
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                if response.status_code < 500:
                    return True
            except Exception:
                continue
        return False
    
    def expand_cidr(self, cidr: str) -> List[str]:
        """
        Expand CIDR notation to list of IP addresses
        
        Args:
            cidr (str): CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            List[str]: List of IP addresses
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Limit large networks for performance
            if network.num_addresses > 1024:
                logger.warning(f"Large network detected ({network.num_addresses} addresses). "
                             f"Consider using smaller subnets for better performance.")
                
                # For large networks, return only network and broadcast addresses as sample
                return [str(network.network_address), str(network.broadcast_address)]
            
            # Return all addresses except network and broadcast for /24 and smaller
            if network.prefixlen >= 24:
                return [str(ip) for ip in network.hosts()]
            else:
                # For larger networks, return all addresses
                return [str(ip) for ip in network]
                
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {cidr} - {str(e)}")
            return []
    
    def discover_live_hosts(self, targets: List[str], 
                           method: str = 'ping', 
                           max_threads: int = None) -> Dict[str, bool]:
        """
        Discover live hosts from target list
        
        Args:
            targets (List[str]): List of targets to check
            method (str): Discovery method ('ping', 'tcp', 'http', 'all')
            max_threads (int, optional): Maximum threads for concurrent checking
            
        Returns:
            Dict[str, bool]: Dictionary mapping targets to alive status
        """
        if not max_threads:
            max_threads = min(self.max_threads, len(targets))
        
        results = {}
        
        logger.info(f"Discovering live hosts among {len(targets)} targets using {method} method")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all tasks
            future_to_target = {
                executor.submit(self.is_host_alive, target, method): target
                for target in targets
            }
            
            # Collect results
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    is_alive = future.result(timeout=30)
                    results[target] = is_alive
                    
                    if is_alive:
                        logger.info(f"✓ {target} is alive")
                    else:
                        logger.debug(f"✗ {target} is not responding")
                        
                except Exception as e:
                    logger.warning(f"Error checking {target}: {str(e)}")
                    results[target] = False
        
        alive_count = sum(results.values())
        logger.info(f"Discovery complete: {alive_count}/{len(targets)} hosts are alive")
        
        return results
    
    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get local network interfaces and their configurations
        
        Returns:
            List[Dict[str, Any]]: List of network interface information
        """
        interfaces = []
        
        try:
            import netifaces
            
            for interface in netifaces.interfaces():
                interface_info = {
                    'name': interface,
                    'addresses': {}
                }
                
                # Get address families
                addrs = netifaces.ifaddresses(interface)
                
                # IPv4 addresses
                if netifaces.AF_INET in addrs:
                    interface_info['addresses']['ipv4'] = addrs[netifaces.AF_INET]
                
                # IPv6 addresses
                if netifaces.AF_INET6 in addrs:
                    interface_info['addresses']['ipv6'] = addrs[netifaces.AF_INET6]
                
                # MAC address
                if netifaces.AF_LINK in addrs:
                    interface_info['addresses']['mac'] = addrs[netifaces.AF_LINK]
                
                interfaces.append(interface_info)
                
        except ImportError:
            logger.warning("netifaces module not available, using basic interface detection")
            # Fallback method using socket
            interfaces = self._get_basic_interfaces()
        
        return interfaces
    
    def _get_basic_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get basic network interface information without netifaces
        
        Returns:
            List[Dict[str, Any]]: Basic interface information
        """
        interfaces = []
        
        try:
            # Get hostname and local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            interfaces.append({
                'name': 'local',
                'addresses': {
                    'ipv4': [{'addr': local_ip}],
                    'hostname': hostname
                }
            })
            
        except Exception as e:
            logger.warning(f"Could not get basic interface info: {str(e)}")
        
        return interfaces
    
    def detect_waf(self, url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall (WAF)
        
        Args:
            url (str): URL to test
            
        Returns:
            Dict[str, Any]: WAF detection results
        """
        waf_signatures = {
            'cloudflare': [
                'cloudflare',
                'cf-ray',
                '__cfduid',
                'cloudflare-nginx'
            ],
            'aws_waf': [
                'awselb',
                'awsalb',
                'x-amzn-requestid'
            ],
            'incapsula': [
                'incap_ses',
                'visid_incap',
                'x-iinfo'
            ],
            'akamai': [
                'akamai',
                'x-akamai',
                'ak_bmsc'
            ],
            'f5_big_ip': [
                'bigipserver',
                'f5-bigip',
                'bigip'
            ],
            'barracuda': [
                'barracuda',
                'barra'
            ],
            'sucuri': [
                'sucuri',
                'x-sucuri'
            ],
            'mod_security': [
                'mod_security',
                'modsecurity'
            ]
        }
        
        detected_wafs = []
        headers = {}
        status_code = None
        
        try:
            # Send test request
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; AutoRecon-Pro)'}
            )
            
            headers = dict(response.headers)
            status_code = response.status_code
            
            # Check headers for WAF signatures
            header_text = ' '.join([f"{k}: {v}" for k, v in headers.items()]).lower()
            
            for waf_name, signatures in waf_signatures.items():
                if any(sig.lower() in header_text for sig in signatures):
                    detected_wafs.append(waf_name)
            
            # Send malicious payload to trigger WAF
            test_payloads = [
                "' OR '1'='1",
                "<script>alert('xss')</script>",
                "../../../../etc/passwd",
                "SELECT * FROM users"
            ]
            
            for payload in test_payloads:
                try:
                    test_url = f"{url}?test={payload}"
                    test_response = requests.get(
                        test_url,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    # Check for WAF blocking responses
                    if test_response.status_code in [403, 406, 418, 429, 503]:
                        detected_wafs.append('generic_waf')
                        break
                        
                except Exception:
                    continue
            
        except Exception as e:
            logger.debug(f"WAF detection error for {url}: {str(e)}")
        
        return {
            'url': url,
            'detected_wafs': list(set(detected_wafs)),
            'headers': headers,
            'status_code': status_code,
            'protected': len(detected_wafs) > 0
        }
    
    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Check SSL certificate information
        
        Args:
            hostname (str): Hostname to check
            port (int): SSL port (default 443)
            
        Returns:
            Dict[str, Any]: SSL certificate information
        """
        import ssl
        from datetime import datetime
        
        cert_info = {
            'hostname': hostname,
            'port': port,
            'valid': False,
            'error': None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        cert_info.update({
                            'valid': True,
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                            'signature_algorithm': cert.get('signatureAlgorithm')
                        })
                        
                        # Check if certificate is expired
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        cert_info['expired'] = datetime.now() > not_after
                        cert_info['days_until_expiration'] = (not_after - datetime.now()).days
            
        except socket.timeout:
            cert_info['error'] = 'Connection timeout'
        except ssl.SSLError as e:
            cert_info['error'] = f'SSL error: {str(e)}'
        except Exception as e:
            cert_info['error'] = f'Certificate check failed: {str(e)}'
        
        return cert_info
    
    def traceroute(self, target: str, max_hops: int = 30) -> List[Dict[str, Any]]:
        """
        Perform traceroute to target
        
        Args:
            target (str): Target to trace route to
            max_hops (int): Maximum number of hops
            
        Returns:
            List[Dict[str, Any]]: Traceroute results
        """
        hops = []
        
        try:
            # Use system traceroute command
            import platform
            
            if platform.system().lower() == 'windows':
                cmd = ['tracert', '-h', str(max_hops), target]
            else:
                cmd = ['traceroute', '-m', str(max_hops), target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    # Parse traceroute output
                    if re.match(r'^\s*\d+', line):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            hop_num = int(parts[0])
                            
                            # Extract IP and hostname if present
                            ip_match = re.search(r'\(([^)]+)\)', line)
                            hostname_match = re.search(r'\s+([a-zA-Z0-9.-]+)\s+\(', line)
                            
                            hop_info = {
                                'hop': hop_num,
                                'ip': ip_match.group(1) if ip_match else None,
                                'hostname': hostname_match.group(1) if hostname_match else None,
                                'rtt': []
                            }
                            
                            # Extract RTT values
                            rtt_matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', line)
                            hop_info['rtt'] = [float(rtt) for rtt in rtt_matches]
                            
                            hops.append(hop_info)
            
        except Exception as e:
            logger.error(f"Traceroute failed for {target}: {str(e)}")
        
        return hops
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """
        Get WHOIS information for domain
        
        Args:
            domain (str): Domain to lookup
            
        Returns:
            Dict[str, Any]: WHOIS information
        """
        whois_info = {
            'domain': domain,
            'available': True,
            'error': None
        }
        
        try:
            import whois
            
            w = whois.whois(domain)
            
            if w:
                whois_info.update({
                    'available': False,
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'expiration_date': w.expiration_date,
                    'updated_date': w.updated_date,
                    'name_servers': w.name_servers,
                    'status': w.status,
                    'emails': w.emails,
                    'org': w.org,
                    'country': w.country
                })
            
        except ImportError:
            logger.warning("python-whois module not available")
            whois_info['error'] = 'WHOIS module not available'
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {str(e)}")
            whois_info['error'] = str(e)
        
        return whois_info
    
    def port_scan(self, host: str, ports: List[int], 
                  timeout: float = 1.0) -> Dict[int, bool]:
        """
        Simple port scanner
        
        Args:
            host (str): Host to scan
            ports (List[int]): List of ports to scan
            timeout (float): Connection timeout
            
        Returns:
            Dict[int, bool]: Dictionary mapping ports to open status
        """
        results = {}
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((host, port))
                    with self._lock:
                        results[port] = result == 0
            except Exception:
                with self._lock:
                    results[port] = False
        
        # Use threading for concurrent port scanning
        max_threads = min(100, len(ports))
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(scan_port, ports)
        
        return results
    
    def get_http_headers(self, url: str) -> Dict[str, Any]:
        """
        Get HTTP headers from URL
        
        Args:
            url (str): URL to request
            
        Returns:
            Dict[str, Any]: HTTP response information
        """
        result = {
            'url': url,
            'status_code': None,
            'headers': {},
            'server': None,
            'technologies': [],
            'error': None
        }
        
        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; AutoRecon-Pro)'}
            )
            
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['server'] = response.headers.get('Server', 'Unknown')
            
            # Detect technologies from headers
            header_text = ' '.join([f"{k}: {v}" for k, v in result['headers'].items()]).lower()
            
            tech_signatures = {
                'apache': ['apache'],
                'nginx': ['nginx'],
                'iis': ['microsoft-iis'],
                'php': ['php'],
                'asp.net': ['asp.net'],
                'jsp': ['jsp'],
                'tomcat': ['tomcat'],
                'cloudflare': ['cloudflare'],
                'wordpress': ['wp-', 'wordpress'],
                'drupal': ['drupal'],
                'joomla': ['joomla']
            }
            
            for tech, sigs in tech_signatures.items():
                if any(sig in header_text for sig in sigs):
                    result['technologies'].append(tech)
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
        
        return result
    
    def check_dns_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """
        Check for DNS zone transfer vulnerability
        
        Args:
            domain (str): Domain to test
            
        Returns:
            Dict[str, Any]: Zone transfer test results
        """
        result = {
            'domain': domain,
            'vulnerable': False,
            'name_servers': [],
            'transferred_records': [],
            'error': None
        }
        
        try:
            # Get name servers for domain
            resolver = dns.resolver.Resolver()
            ns_answers = resolver.resolve(domain, 'NS')
            name_servers = [str(ns) for ns in ns_answers]
            result['name_servers'] = name_servers
            
            # Test zone transfer on each name server
            for ns in name_servers:
                try:
                    # Resolve name server IP
                    ns_ip = str(resolver.resolve(ns, 'A')[0])
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
                    
                    if zone:
                        result['vulnerable'] = True
                        result['vulnerable_ns'] = ns
                        
                        # Extract records
                        records = []
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    records.append({
                                        'name': str(name),
                                        'type': dns.rdatatype.to_text(rdataset.rdtype),
                                        'value': str(rdata)
                                    })
                        
                        result['transferred_records'] = records
                        break
                        
                except Exception as e:
                    logger.debug(f"Zone transfer failed for {ns}: {str(e)}")
                    continue
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_public_ip(self) -> Optional[str]:
        """
        Get public IP address of current machine
        
        Returns:
            Optional[str]: Public IP address if available
        """
        services = [
            'https://api.ipify.org',
            'https://ipinfo.io/ip',
            'https://icanhazip.com',
            'https://ifconfig.me/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validate IP address
                    ipaddress.ip_address(ip)
                    return ip
            except Exception:
                continue
        
        return None
    
    def validate_target_list(self, targets: List[str]) -> Dict[str, List[str]]:
        """
        Validate and categorize list of targets
        
        Args:
            targets (List[str]): List of targets to validate
            
        Returns:
            Dict[str, List[str]]: Categorized targets
        """
        categorized = {
            'valid_ips': [],
            'valid_domains': [],
            'valid_cidrs': [],
            'valid_urls': [],
            'invalid': []
        }
        
        for target in targets:
            try:
                # Check if it's an IP address
                ipaddress.ip_address(target)
                categorized['valid_ips'].append(target)
                continue
            except ValueError:
                pass
            
            # Check if it's CIDR notation
            try:
                ipaddress.ip_network(target, strict=False)
                categorized['valid_cidrs'].append(target)
                continue
            except ValueError:
                pass
            
            # Check if it's a URL
            if target.startswith(('http://', 'https://')):
                categorized['valid_urls'].append(target)
                continue
            
            # Check if it's a domain name
            domain_pattern = re.compile(
                r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?
            )
            if domain_pattern.match(target):
                categorized['valid_domains'].append(target)
            else:
                categorized['invalid'].append(target)
        
        return categorized
    
    def get_network_range_info(self, ip: str) -> Dict[str, Any]:
        """
        Get network range information for an IP address
        
        Args:
            ip (str): IP address
            
        Returns:
            Dict[str, Any]: Network range information
        """
        info = {
            'ip': ip,
            'private': False,
            'loopback': False,
            'multicast': False,
            'network_class': None,
            'suggested_scan_range': None
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            info['private'] = ip_obj.is_private
            info['loopback'] = ip_obj.is_loopback
            info['multicast'] = ip_obj.is_multicast
            
            # Determine network class for IPv4
            if isinstance(ip_obj, ipaddress.IPv4Address):
                first_octet = int(ip.split('.')[0])
                if 1 <= first_octet <= 126:
                    info['network_class'] = 'A'
                    info['suggested_scan_range'] = f"{ip.split('.')[0]}.0.0.0/8"
                elif 128 <= first_octet <= 191:
                    info['network_class'] = 'B'
                    info['suggested_scan_range'] = f"{'.'.join(ip.split('.')[:2])}.0.0/16"
                elif 192 <= first_octet <= 223:
                    info['network_class'] = 'C'
                    info['suggested_scan_range'] = f"{'.'.join(ip.split('.')[:3])}.0/24"
                
                # For private networks, suggest smaller ranges
                if ip_obj.is_private:
                    if ip.startswith('192.168.'):
                        info['suggested_scan_range'] = f"{'.'.join(ip.split('.')[:3])}.0/24"
                    elif ip.startswith('10.'):
                        info['suggested_scan_range'] = f"{'.'.join(ip.split('.')[:2])}.0.0/16"
                    elif ip.startswith('172.'):
                        info['suggested_scan_range'] = f"{'.'.join(ip.split('.')[:2])}.0.0/16"
            
        except ValueError as e:
            info['error'] = str(e)
        
        return info