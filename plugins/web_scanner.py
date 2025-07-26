#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Web Application Scanner Plugin
"""

import asyncio
import aiohttp
import json
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional
from pathlib import Path
from core.plugin_manager import ServiceScanPlugin

class WebScanner(ServiceScanPlugin):
    """Comprehensive web application scanner"""
    
    @property
    def description(self) -> str:
        return "Comprehensive web application scanner with directory bruteforce, technology detection, and vulnerability assessment"
    
    @property
    def dependencies(self) -> List[str]:
        return ['gobuster', 'nikto', 'whatweb', 'httpx']
    
    @property
    def tags(self) -> List[str]:
        return ['default', 'web', 'http', 'https']
    
    @property
    def priority(self) -> int:
        return 30
    
    def should_run(self, target_info: Dict[str, Any]) -> bool:
        """Check if web services are present"""
        services = target_info.get('services', {})
        for port, service in services.items():
            service_name = service.get('name', '').lower()
            if 'http' in service_name or service.get('service', '').lower().startswith('http'):
                return True
        return False
    
    async def run(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive web application scan"""
        target = target_info['target']
        output_dir = target_info.get('output_dir', '/tmp')
        
        results = {
            'web_services': [],
            'directories': [],
            'technologies': [],
            'vulnerabilities': [],
            'screenshots': [],
            'headers_analysis': {},
            'ssl_analysis': {},
            'cms_detection': {},
            'errors': []
        }
        
        try:
            # Identify web services
            web_services = self._identify_web_services(target_info)
            results['web_services'] = web_services
            
            if not web_services:
                return results
            
            # Run scans for each web service
            for web_service in web_services:
                service_results = await self._scan_web_service(web_service, output_dir)
                
                # Merge results
                results['directories'].extend(service_results.get('directories', []))
                results['technologies'].extend(service_results.get('technologies', []))
                results['vulnerabilities'].extend(service_results.get('vulnerabilities', []))
                results['screenshots'].extend(service_results.get('screenshots', []))
                results['headers_analysis'].update(service_results.get('headers_analysis', {}))
                results['ssl_analysis'].update(service_results.get('ssl_analysis', {}))
                results['cms_detection'].update(service_results.get('cms_detection', {}))
            
            return results
            
        except Exception as e:
            self.logger.error(f"Web scanner failed for {target}: {e}")
            results['errors'].append(str(e))
            return results
    
    def _identify_web_services(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify web services from target information"""
        web_services = []
        services = target_info.get('services', {})
        target = target_info['target']
        
        for port, service_info in services.items():
            service_name = service_info.get('name', '').lower()
            port_num = port.split('/')[0]
            
            if 'http' in service_name or service_name in ['www', 'www-http']:
                # Determine protocol
                protocol = 'https' if 'ssl' in service_info.get('service', '').lower() or port_num == '443' else 'http'
                
                web_service = {
                    'target': target,
                    'port': port_num,
                    'protocol': protocol,
                    'url': f"{protocol}://{target}:{port_num}",
                    'service_info': service_info
                }
                web_services.append(web_service)
        
        return web_services
    
    async def _scan_web_service(self, web_service: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Scan a single web service"""
        url = web_service['url']
        self.logger.scan_start(url, "Web Service Scan")
        
        results = {
            'directories': [],
            'technologies': [],
            'vulnerabilities': [],
            'screenshots': [],
            'headers_analysis': {},
            'ssl_analysis': {},
            'cms_detection': {}
        }
        
        # Run concurrent web scans
        scan_tasks = [
            self._run_directory_bruteforce(web_service, output_dir),
            self._run_technology_detection(web_service, output_dir),
            self._run_vulnerability_scan(web_service, output_dir),
            self._analyze_headers(web_service),
            self._detect_cms(web_service)
        ]
        
        # Add SSL analysis for HTTPS
        if web_service['protocol'] == 'https':
            scan_tasks.append(self._analyze_ssl(web_service))
        
        # Add screenshot capture if enabled
        if self.config.get('features.screenshots', True):
            scan_tasks.append(self._capture_screenshot(web_service, output_dir))
        
        # Execute all scans concurrently
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(scan_results):
            if isinstance(result, Exception):
                self.logger.error(f"Web scan task failed: {result}")
                continue
            
            if i == 0:  # Directory bruteforce
                results['directories'] = result.get('directories', [])
            elif i == 1:  # Technology detection
                results['technologies'] = result.get('technologies', [])
            elif i == 2:  # Vulnerability scan
                results['vulnerabilities'] = result.get('vulnerabilities', [])
            elif i == 3:  # Headers analysis
                results['headers_analysis'] = result
            elif i == 4:  # CMS detection
                results['cms_detection'] = result
            elif i == 5 and web_service['protocol'] == 'https':  # SSL analysis
                results['ssl_analysis'] = result
            elif (i == 5 and web_service['protocol'] == 'http') or i == 6:  # Screenshot
                results['screenshots'] = result.get('screenshots', [])
        
        self.logger.scan_complete(url, "Web Service Scan", 0)
        return results
    
    async def _run_directory_bruteforce(self, web_service: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Run directory bruteforce using gobuster"""
        url = web_service['url']
        target = web_service['target']
        port = web_service['port']
        
        self.logger.info(f"Running directory bruteforce on {url}")
        
        # Determine wordlist
        wordlist_dir = self.config.get('wordlists.directory', '/usr/share/wordlists')
        wordlist_file = f"{wordlist_dir}/dirb/common.txt"
        
        if not Path(wordlist_file).exists():
            wordlist_file = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        
        # Output file
        output_file = f"{output_dir}/gobuster_{target}_{port}.txt"
        
        # Build gobuster command
        cmd_parts = [
            'gobuster', 'dir',
            f'-u {url}',
            f'-w {wordlist_file}',
            f'-o {output_file}',
            f'-t {self.config.get("tools.gobuster.threads", 50)}',
            '--quiet',
            '--no-error'
        ]
        
        # Add extensions
        extensions = self.config.get('tools.gobuster.extensions', 'php,html,txt,js,css,xml,json')
        if extensions:
            cmd_parts.append(f'-x {extensions}')
        
        # Add status codes
        cmd_parts.append('-s 200,204,301,302,307,401,403,405,500')
        
        command = ' '.join(cmd_parts)
        
        result = await self.execute_command(command)
        
        screenshots = []
        if result['exit_code'] == 0 and Path(screenshot_file).exists():
            screenshots.append({
                'url': url,
                'file': screenshot_file,
                'timestamp': asyncio.get_event_loop().time()
            })
            self.logger.success(f"Screenshot captured: {screenshot_file}")
        else:
            self.logger.error(f"Failed to capture screenshot for {url}")
        
        return {'screenshots': screenshots}
    
    async def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute command using scanner engine"""
        import subprocess
        import shlex
        
        try:
            cmd_args = shlex.split(command)
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                'command': command,
                'exit_code': process.returncode,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore')
            }
        except Exception as e:
            return {
                'command': command,
                'exit_code': -1,
                'stdout': '',
                'stderr': str(e),
                'error': str(e)
            }_command(command)
        
        directories = []
        if result['exit_code'] == 0:
            # Parse gobuster output
            directories = self._parse_gobuster_output(result['stdout'])
            
            # Also read from output file if it exists
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    file_dirs = self._parse_gobuster_output(f.read())
                    directories.extend(file_dirs)
            
            self.logger.success(f"Found {len(directories)} directories/files")
            
            # Log interesting findings
            for directory in directories:
                if any(keyword in directory['path'].lower() for keyword in ['admin', 'login', 'backup', 'config']):
                    self.logger.finding('Interesting Directory', url, directory['path'])
        
        return {'directories': directories}
    
    def _parse_gobuster_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse gobuster output"""
        directories = []
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('=') or 'Gobuster' in line:
                continue
            
            # Parse gobuster line format: /path (Status: 200) [Size: 1234]
            match = re.match(r'(/\S*)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]', line)
            if match:
                path, status, size = match.groups()
                directories.append({
                    'path': path,
                    'status': int(status),
                    'size': int(size),
                    'url': path
                })
        
        return directories
    
    async def _run_technology_detection(self, web_service: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Run technology detection using whatweb"""
        url = web_service['url']
        
        self.logger.info(f"Detecting technologies on {url}")
        
        # Output file
        output_file = f"{output_dir}/whatweb_{web_service['target']}_{web_service['port']}.json"
        
        # Build whatweb command
        cmd_parts = [
            'whatweb',
            f'--aggression={self.config.get("tools.whatweb.aggression", 3)}',
            '--log-json=' + output_file,
            url
        ]
        
        command = ' '.join(cmd_parts)
        
        result = await self.execute_command(command)
        
        technologies = []
        if result['exit_code'] == 0:
            # Parse whatweb output
            technologies = self._parse_whatweb_output(result['stdout'])
            
            # Also try to parse JSON output file
            if Path(output_file).exists():
                try:
                    with open(output_file, 'r') as f:
                        json_data = json.load(f)
                        json_techs = self._parse_whatweb_json(json_data)
                        technologies.extend(json_techs)
                except:
                    pass
            
            self.logger.success(f"Detected {len(technologies)} technologies")
        
        return {'technologies': technologies}
    
    def _parse_whatweb_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse whatweb output"""
        technologies = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if '[200 OK]' in line or '[301' in line or '[302' in line:
                # Extract technologies from line
                tech_matches = re.findall(r'(\w+)\[([^\]]*)\]', line)
                for tech_name, tech_info in tech_matches:
                    if tech_name not in ['Country', 'IP']:
                        technologies.append({
                            'name': tech_name,
                            'version': tech_info if tech_info else 'Unknown',
                            'confidence': 'High'
                        })
        
        return technologies
    
    def _parse_whatweb_json(self, json_data: List[Dict]) -> List[Dict[str, Any]]:
        """Parse whatweb JSON output"""
        technologies = []
        
        for entry in json_data:
            plugins = entry.get('plugins', {})
            for plugin_name, plugin_data in plugins.items():
                if isinstance(plugin_data, dict):
                    version = plugin_data.get('version', ['Unknown'])
                    if isinstance(version, list):
                        version = version[0] if version else 'Unknown'
                    
                    technologies.append({
                        'name': plugin_name,
                        'version': version,
                        'confidence': 'High'
                    })
        
        return technologies
    
    async def _run_vulnerability_scan(self, web_service: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Run vulnerability scan using nikto"""
        url = web_service['url']
        
        self.logger.info(f"Running vulnerability scan on {url}")
        
        # Output file
        output_file = f"{output_dir}/nikto_{web_service['target']}_{web_service['port']}.txt"
        
        # Build nikto command
        cmd_parts = [
            'nikto',
            f'-h {url}',
            f'-o {output_file}',
            '-Format txt',
            f'-timeout {self.config.get("tools.nikto.timeout", 600)}'
        ]
        
        command = ' '.join(cmd_parts)
        
        result = await self.execute_command(command)
        
        vulnerabilities = []
        if result['exit_code'] == 0:
            # Parse nikto output
            vulnerabilities = self._parse_nikto_output(result['stdout'])
            
            self.logger.success(f"Found {len(vulnerabilities)} potential vulnerabilities")
            
            # Log high-severity findings
            for vuln in vulnerabilities:
                if vuln.get('severity', '').upper() in ['HIGH', 'CRITICAL']:
                    self.logger.vulnerability('Web Vulnerability', url, vuln['severity'], vuln['description'])
        
        return {'vulnerabilities': vulnerabilities}
    
    def _parse_nikto_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nikto output"""
        vulnerabilities = []
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('+') and not line.startswith('+ Target'):
                # Remove the + prefix and parse
                vuln_text = line[1:].strip()
                
                # Determine severity based on keywords
                severity = 'INFO'
                if any(keyword in vuln_text.lower() for keyword in ['critical', 'high risk']):
                    severity = 'HIGH'
                elif any(keyword in vuln_text.lower() for keyword in ['medium', 'warning']):
                    severity = 'MEDIUM'
                elif any(keyword in vuln_text.lower() for keyword in ['low', 'info']):
                    severity = 'LOW'
                
                vulnerabilities.append({
                    'description': vuln_text,
                    'severity': severity,
                    'source': 'nikto'
                })
        
        return vulnerabilities
    
    async def _analyze_headers(self, web_service: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP headers for security issues"""
        url = web_service['url']
        
        self.logger.info(f"Analyzing HTTP headers for {url}")
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=False) as response:
                    headers = dict(response.headers)
                    
                    analysis = {
                        'headers': headers,
                        'security_headers': {},
                        'missing_headers': [],
                        'issues': []
                    }
                    
                    # Check for security headers
                    security_headers = [
                        'X-Frame-Options',
                        'X-Content-Type-Options',
                        'X-XSS-Protection',
                        'Strict-Transport-Security',
                        'Content-Security-Policy',
                        'Referrer-Policy'
                    ]
                    
                    for header in security_headers:
                        if header in headers:
                            analysis['security_headers'][header] = headers[header]
                        else:
                            analysis['missing_headers'].append(header)
                    
                    # Check for problematic headers
                    if 'Server' in headers:
                        analysis['issues'].append({
                            'type': 'Information Disclosure',
                            'description': f"Server header reveals: {headers['Server']}",
                            'severity': 'LOW'
                        })
                    
                    # Check for missing security headers
                    if analysis['missing_headers']:
                        analysis['issues'].append({
                            'type': 'Missing Security Headers',
                            'description': f"Missing headers: {', '.join(analysis['missing_headers'])}",
                            'severity': 'MEDIUM'
                        })
                    
                    return analysis
                    
        except Exception as e:
            self.logger.error(f"Failed to analyze headers for {url}: {e}")
            return {'error': str(e)}
    
    async def _analyze_ssl(self, web_service: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        url = web_service['url']
        target = web_service['target']
        port = web_service['port']
        
        self.logger.info(f"Analyzing SSL/TLS for {url}")
        
        # Use sslscan if available
        command = f"sslscan --no-colour {target}:{port}"
        
        result = await self.execute_command(command)
        
        if result['exit_code'] == 0:
            return self._parse_sslscan_output(result['stdout'])
        else:
            return {'error': 'SSL analysis failed'}
    
    def _parse_sslscan_output(self, output: str) -> Dict[str, Any]:
        """Parse sslscan output"""
        analysis = {
            'supported_protocols': [],
            'supported_ciphers': [],
            'certificate_info': {},
            'vulnerabilities': []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse supported protocols
            if 'Enabled' in line and any(proto in line for proto in ['SSLv2', 'SSLv3', 'TLSv1']):
                if 'SSLv2' in line or 'SSLv3' in line:
                    analysis['vulnerabilities'].append({
                        'type': 'Weak Protocol',
                        'description': f"Weak SSL/TLS protocol enabled: {line}",
                        'severity': 'HIGH'
                    })
                analysis['supported_protocols'].append(line)
            
            # Parse certificate information
            if 'Subject:' in line:
                analysis['certificate_info']['subject'] = line.split('Subject:')[1].strip()
            elif 'Issuer:' in line:
                analysis['certificate_info']['issuer'] = line.split('Issuer:')[1].strip()
        
        return analysis
    
    async def _detect_cms(self, web_service: Dict[str, Any]) -> Dict[str, Any]:
        """Detect Content Management System"""
        url = web_service['url']
        
        self.logger.info(f"Detecting CMS for {url}")
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    html = await response.text()
                    headers = dict(response.headers)
                    
                    cms_detection = {
                        'detected': False,
                        'cms_name': 'Unknown',
                        'version': 'Unknown',
                        'confidence': 0,
                        'indicators': []
                    }
                    
                    # WordPress detection
                    if self._detect_wordpress(html, headers):
                        cms_detection.update({
                            'detected': True,
                            'cms_name': 'WordPress',
                            'confidence': 90
                        })
                        cms_detection['indicators'].append('wp-content directory found')
                    
                    # Drupal detection
                    elif self._detect_drupal(html, headers):
                        cms_detection.update({
                            'detected': True,
                            'cms_name': 'Drupal',
                            'confidence': 85
                        })
                        cms_detection['indicators'].append('Drupal markers found')
                    
                    # Joomla detection
                    elif self._detect_joomla(html, headers):
                        cms_detection.update({
                            'detected': True,
                            'cms_name': 'Joomla',
                            'confidence': 85
                        })
                        cms_detection['indicators'].append('Joomla markers found')
                    
                    return cms_detection
                    
        except Exception as e:
            self.logger.error(f"CMS detection failed for {url}: {e}")
            return {'detected': False, 'error': str(e)}
    
    def _detect_wordpress(self, html: str, headers: Dict[str, str]) -> bool:
        """Detect WordPress"""
        wp_indicators = [
            'wp-content',
            'wp-includes',
            'wp-admin',
            'wordpress',
            '/wp-json/',
            'wp-embed.min.js'
        ]
        
        return any(indicator in html.lower() for indicator in wp_indicators)
    
    def _detect_drupal(self, html: str, headers: Dict[str, str]) -> bool:
        """Detect Drupal"""
        drupal_indicators = [
            'drupal',
            '/sites/default/',
            'drupal.js',
            'Drupal.settings',
            '/misc/drupal.js'
        ]
        
        return any(indicator in html.lower() for indicator in drupal_indicators)
    
    def _detect_joomla(self, html: str, headers: Dict[str, str]) -> bool:
        """Detect Joomla"""
        joomla_indicators = [
            '/components/',
            '/modules/',
            '/templates/',
            'joomla',
            'com_content'
        ]
        
        return any(indicator in html.lower() for indicator in joomla_indicators)
    
    async def _capture_screenshot(self, web_service: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Capture web screenshot"""
        url = web_service['url']
        target = web_service['target']
        port = web_service['port']
        
        self.logger.info(f"Capturing screenshot for {url}")
        
        # Screenshot filename
        screenshot_file = f"{output_dir}/screenshot_{target}_{port}.png"
        
        # Use headless Chrome via Python (requires additional implementation)
        # For now, we'll use a system command approach
        
        cmd_parts = [
            'timeout', '30',
            'google-chrome',
            '--headless',
            '--disable-gpu',
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--virtual-time-budget=10000',
            f'--window-size=1280,720',
            f'--screenshot={screenshot_file}',
            url
        ]
        
        command = ' '.join(cmd_parts)
        
        result = await self.execute