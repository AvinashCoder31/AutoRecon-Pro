"""
AutoRecon-Pro Web Scanner Plugin
Comprehensive web application scanning and enumeration
"""

import asyncio
import aiohttp
import requests
import subprocess
import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import time
from urllib.parse import urljoin, urlparse
import ssl
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class WebScanner:
    """
    Advanced web application scanner with multiple enumeration techniques
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize web scanner with configuration
        
        Args:
            config (Dict[str, Any], optional): Scanner configuration
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.max_redirects = self.config.get('max_redirects', 5)
        self.user_agent = self.config.get('user_agent', 'Mozilla/5.0 (compatible; AutoRecon-Pro)')
        self.threads = self.config.get('threads', 10)
        self.wordlist_dir = self.config.get('wordlist_dir', '/usr/share/wordlists')
        
        # Default wordlists
        self.default_wordlists = {
            'directories': [
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/wordlists/dirb/common.txt',
                'wordlists/directories.txt'
            ],
            'files': [
                '/usr/share/wordlists/dirbuster/directory-list-2.3-files.txt',
                'wordlists/files.txt'
            ],
            'extensions': ['php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'js', 'txt', 'xml', 'json']
        }
        
        # Common status codes to check
        self.interesting_status_codes = [200, 201, 204, 301, 302, 307, 401, 403, 500, 503]
        
    async def scan_target(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Main scanning method for web targets
        
        Args:
            target (str): Target URL or domain
            options (Dict[str, Any], optional): Scan options
            
        Returns:
            Dict[str, Any]: Comprehensive scan results
        """
        options = options or {}
        results = {
            'target': target,
            'timestamp': time.time(),
            'status': 'running',
            'findings': []
        }
        
        try:
            # Normalize target URL
            if not target.startswith(('http://', 'https://')):
                # Try HTTPS first, fallback to HTTP
                https_target = f"https://{target}"
                if await self._check_url_accessibility(https_target):
                    target = https_target
                else:
                    target = f"http://{target}"
            
            results['normalized_target'] = target
            logger.info(f"Starting web scan for {target}")
            
            # Perform various scans
            scan_tasks = []
            
            # Basic information gathering
            scan_tasks.append(self._gather_basic_info(target))
            
            # Technology detection
            scan_tasks.append(self._detect_technologies(target))
            
            # Directory enumeration
            if options.get('directory_enum', True):
                scan_tasks.append(self._enumerate_directories(target, options))
            
            # File enumeration
            if options.get('file_enum', True):
                scan_tasks.append(self._enumerate_files(target, options))
            
            # Vulnerability scanning
            if options.get('vuln_scan', True):
                scan_tasks.append(self._vulnerability_scan(target, options))
            
            # SSL/TLS analysis
            if target.startswith('https://'):
                scan_tasks.append(self._analyze_ssl(target))
            
            # Header analysis
            scan_tasks.append(self._analyze_headers(target))
            
            # Robots.txt and sitemap analysis
            scan_tasks.append(self._analyze_robots_sitemap(target))
            
            # Execute all scan tasks concurrently
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(scan_results):
                if isinstance(result, Exception):
                    logger.error(f"Scan task {i} failed: {str(result)}")
                    results['findings'].append({
                        'type': 'error',
                        'message': f"Scan task failed: {str(result)}"
                    })
                elif isinstance(result, dict) and 'findings' in result:
                    results['findings'].extend(result['findings'])
                elif isinstance(result, dict):
                    results.update(result)
            
            results['status'] = 'completed'
            results['duration'] = time.time() - results['timestamp']
            
            logger.info(f"Web scan completed for {target} in {results['duration']:.2f}s")
            
        except Exception as e:
            logger.error(f"Basic info gathering failed for {target}: {str(e)}")
            info['findings'].append({
                'type': 'error',
                'category': 'basic_info',
                'title': 'Basic Info Gathering Error',
                'data': {'error': str(e)}
            })
        
        return info
    
    async def _detect_technologies(self, target: str) -> Dict[str, Any]:
        """
        Detect web technologies using various methods
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: Detected technologies
        """
        tech_info = {'findings': []}
        detected_techs = set()
        
        try:
            # Use WhatWeb if available
            whatweb_result = await self._run_whatweb(target)
            if whatweb_result:
                detected_techs.update(whatweb_result)
            
            # Manual technology detection
            manual_techs = await self._manual_tech_detection(target)
            detected_techs.update(manual_techs)
            
            if detected_techs:
                tech_info['findings'].append({
                    'type': 'info',
                    'category': 'technology',
                    'title': 'Detected Technologies',
                    'data': {'technologies': list(detected_techs)}
                })
            
        except Exception as e:
            logger.error(f"Technology detection failed for {target}: {str(e)}")
            tech_info['findings'].append({
                'type': 'error',
                'category': 'technology',
                'title': 'Technology Detection Error',
                'data': {'error': str(e)}
            })
        
        return tech_info
    
    async def _run_whatweb(self, target: str) -> List[str]:
        """
        Run WhatWeb tool for technology detection
        
        Args:
            target (str): Target URL
            
        Returns:
            List[str]: Detected technologies
        """
        try:
            cmd = ['whatweb', '--log-brief', target]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            if result.returncode == 0:
                # Parse WhatWeb output
                technologies = []
                for line in result.stdout.split('\n'):
                    if target in line:
                        # Extract technology names
                        tech_matches = re.findall(r'(\w+)\[', line)
                        technologies.extend(tech_matches)
                
                return technologies
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("WhatWeb not available or timed out")
        except Exception as e:
            logger.debug(f"WhatWeb execution failed: {str(e)}")
        
        return []
    
    async def _manual_tech_detection(self, target: str) -> List[str]:
        """
        Manual technology detection based on headers and content
        
        Args:
            target (str): Target URL
            
        Returns:
            List[str]: Detected technologies
        """
        technologies = []
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                async with session.get(target, ssl=False) as response:
                    headers = dict(response.headers)
                    content = await response.text()
                    
                    # Header-based detection
                    header_techs = {
                        'Apache': ['Apache'],
                        'Nginx': ['nginx'],
                        'IIS': ['Microsoft-IIS'],
                        'PHP': ['PHP'],
                        'ASP.NET': ['ASP.NET'],
                        'Express': ['Express'],
                        'Cloudflare': ['cloudflare']
                    }
                    
                    for tech, signatures in header_techs.items():
                        for sig in signatures:
                            if any(sig.lower() in str(v).lower() for v in headers.values()):
                                technologies.append(tech)
                                break
                    
                    # Content-based detection
                    content_lower = content.lower()
                    content_techs = {
                        'WordPress': ['wp-content', 'wordpress', 'wp-includes'],
                        'Drupal': ['drupal', '/sites/all/', '/sites/default/'],
                        'Joomla': ['joomla', '/media/jui/', 'option=com_'],
                        'jQuery': ['jquery'],
                        'Bootstrap': ['bootstrap'],
                        'React': ['react', '__reactinternalinstance'],
                        'Angular': ['angular', 'ng-'],
                        'Vue.js': ['vue.js', '__vue__'],
                        'Django': ['csrfmiddlewaretoken', 'django'],
                        'Laravel': ['laravel_session', '_token'],
                        'Spring': ['spring', 'jsessionid']
                    }
                    
                    for tech, signatures in content_techs.items():
                        if any(sig in content_lower for sig in signatures):
                            technologies.append(tech)
                    
                    # Check for specific files/paths
                    common_files = {
                        'WordPress': ['/wp-admin/', '/wp-login.php'],
                        'Drupal': ['/user/login', '/admin/'],
                        'Joomla': ['/administrator/', '/index.php?option=com_'],
                        'phpMyAdmin': ['/phpmyadmin/', '/pma/']
                    }
                    
                    for tech, paths in common_files.items():
                        for path in paths:
                            test_url = urljoin(target, path)
                            try:
                                async with session.head(test_url, ssl=False) as test_response:
                                    if test_response.status == 200:
                                        technologies.append(tech)
                                        break
                            except Exception:
                                continue
        
        except Exception as e:
            logger.debug(f"Manual tech detection failed: {str(e)}")
        
        return list(set(technologies))
    
    async def _enumerate_directories(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enumerate directories using wordlists
        
        Args:
            target (str): Target URL
            options (Dict[str, Any]): Enumeration options
            
        Returns:
            Dict[str, Any]: Directory enumeration results
        """
        dir_info = {'findings': []}
        
        try:
            # Use Gobuster if available
            gobuster_results = await self._run_gobuster(target, 'directories', options)
            if gobuster_results:
                dir_info['findings'].extend(gobuster_results)
            
            # Manual directory enumeration
            manual_results = await self._manual_directory_enum(target, options)
            if manual_results:
                dir_info['findings'].extend(manual_results)
            
        except Exception as e:
            logger.error(f"Directory enumeration failed for {target}: {str(e)}")
            dir_info['findings'].append({
                'type': 'error',
                'category': 'directory_enum',
                'title': 'Directory Enumeration Error',
                'data': {'error': str(e)}
            })
        
        return dir_info
    
    async def _run_gobuster(self, target: str, scan_type: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run Gobuster for directory/file enumeration
        
        Args:
            target (str): Target URL
            scan_type (str): Type of scan ('directories' or 'files')
            options (Dict[str, Any]): Scan options
            
        Returns:
            List[Dict[str, Any]]: Gobuster results
        """
        results = []
        
        try:
            # Find appropriate wordlist
            wordlist = self._get_wordlist(scan_type, options)
            if not wordlist:
                return results
            
            # Build Gobuster command
            cmd = [
                'gobuster', 'dir',
                '-u', target,
                '-w', wordlist,
                '-t', str(options.get('threads', self.threads)),
                '-x', ','.join(self.default_wordlists['extensions']),
                '-s', '200,204,301,302,307,401,403',
                '--timeout', f"{self.timeout}s",
                '--useragent', self.user_agent
            ]
            
            # Add quiet mode
            cmd.extend(['-q'])
            
            # Execute Gobuster
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if process.returncode == 0:
                # Parse Gobuster output
                for line in process.stdout.split('\n'):
                    if line.strip() and not line.startswith('='):
                        # Parse line format: /path (Status: 200) [Size: 1234]
                        match = re.match(r'(/[^\s]*)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]', line)
                        if match:
                            path, status, size = match.groups()
                            results.append({
                                'type': 'finding',
                                'category': 'directory_enum',
                                'title': f'Directory/File Found: {path}',
                                'data': {
                                    'path': path,
                                    'url': urljoin(target, path),
                                    'status_code': int(status),
                                    'size': int(size),
                                    'method': 'gobuster'
                                },
                                'severity': 'info'
                            })
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Gobuster timed out for {target}")
        except FileNotFoundError:
            logger.debug("Gobuster not available")
        except Exception as e:
            logger.debug(f"Gobuster execution failed: {str(e)}")
        
        return results
    
    async def _manual_directory_enum(self, target: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Manual directory enumeration using common paths
        
        Args:
            target (str): Target URL
            options (Dict[str, Any]): Enumeration options
            
        Returns:
            List[Dict[str, Any]]: Manual enumeration results
        """
        results = []
        
        # Common directories to check
        common_dirs = [
            '/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/',
            '/backup/', '/backups/', '/config/', '/conf/', '/inc/',
            '/includes/', '/uploads/', '/images/', '/css/', '/js/',
            '/api/', '/v1/', '/v2/', '/test/', '/dev/', '/staging/',
            '/.git/', '/.svn/', '/.env', '/robots.txt', '/sitemap.xml'
        ]
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                # Check common directories
                for directory in common_dirs:
                    try:
                        test_url = urljoin(target, directory)
                        async with session.head(test_url, ssl=False) as response:
                            if response.status in self.interesting_status_codes:
                                results.append({
                                    'type': 'finding',
                                    'category': 'directory_enum',
                                    'title': f'Accessible Path: {directory}',
                                    'data': {
                                        'path': directory,
                                        'url': test_url,
                                        'status_code': response.status,
                                        'method': 'manual'
                                    },
                                    'severity': 'info' if response.status == 200 else 'low'
                                })
                    except Exception:
                        continue
        
        except Exception as e:
            logger.debug(f"Manual directory enumeration failed: {str(e)}")
        
        return results
    
    async def _enumerate_files(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enumerate files using various techniques
        
        Args:
            target (str): Target URL
            options (Dict[str, Any]): Enumeration options
            
        Returns:
            Dict[str, Any]: File enumeration results
        """
        file_info = {'findings': []}
        
        try:
            # Common file enumeration
            common_files = [
                'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
                'readme.txt', 'README.md', 'changelog.txt', 'license.txt',
                'backup.sql', 'database.sql', 'config.php', 'wp-config.php',
                '.env', '.git/config', 'crossdomain.xml', 'clientaccesspolicy.xml'
            ]
            
            found_files = await self._check_common_files(target, common_files)
            file_info['findings'].extend(found_files)
            
            # Backup file enumeration
            backup_files = await self._enumerate_backup_files(target)
            file_info['findings'].extend(backup_files)
            
        except Exception as e:
            logger.error(f"File enumeration failed for {target}: {str(e)}")
            file_info['findings'].append({
                'type': 'error',
                'category': 'file_enum',
                'title': 'File Enumeration Error',
                'data': {'error': str(e)}
            })
        
        return file_info
    
    async def _check_common_files(self, target: str, files: List[str]) -> List[Dict[str, Any]]:
        """
        Check for common files
        
        Args:
            target (str): Target URL
            files (List[str]): List of files to check
            
        Returns:
            List[Dict[str, Any]]: Found files
        """
        results = []
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                for file in files:
                    try:
                        test_url = urljoin(target, file)
                        async with session.get(test_url, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                results.append({
                                    'type': 'finding',
                                    'category': 'file_enum',
                                    'title': f'Accessible File: {file}',
                                    'data': {
                                        'file': file,
                                        'url': test_url,
                                        'status_code': response.status,
                                        'size': len(content),
                                        'content_preview': content[:500] if len(content) > 500 else content
                                    },
                                    'severity': 'medium' if file in ['.env', 'wp-config.php', 'config.php'] else 'info'
                                })
                    except Exception:
                        continue
        
        except Exception as e:
            logger.debug(f"Common file check failed: {str(e)}")
        
        return results
    
    async def _enumerate_backup_files(self, target: str) -> List[Dict[str, Any]]:
        """
        Enumerate potential backup files
        
        Args:
            target (str): Target URL
            
        Returns:
            List[Dict[str, Any]]: Found backup files
        """
        results = []
        
        # Parse target to get potential backup file names
        parsed_url = urlparse(target)
        domain = parsed_url.netloc.split('.')[0]
        
        backup_patterns = [
            f'{domain}.zip', f'{domain}.tar.gz', f'{domain}.backup',
            'backup.zip', 'backup.tar.gz', 'site.zip', 'www.zip',
            'backup.sql', 'database.sql', f'{domain}.sql'
        ]
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                for backup_file in backup_patterns:
                    try:
                        test_url = urljoin(target, backup_file)
                        async with session.head(test_url, ssl=False) as response:
                            if response.status == 200:
                                results.append({
                                    'type': 'finding',
                                    'category': 'file_enum',
                                    'title': f'Potential Backup File: {backup_file}',
                                    'data': {
                                        'file': backup_file,
                                        'url': test_url,
                                        'status_code': response.status,
                                        'content_type': response.headers.get('Content-Type', 'Unknown')
                                    },
                                    'severity': 'high'
                                })
                    except Exception:
                        continue
        
        except Exception as e:
            logger.debug(f"Backup file enumeration failed: {str(e)}")
        
        return results
    
    async def _vulnerability_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform vulnerability scanning
        
        Args:
            target (str): Target URL
            options (Dict[str, Any]): Scan options
            
        Returns:
            Dict[str, Any]: Vulnerability scan results
        """
        vuln_info = {'findings': []}
        
        try:
            # Run Nikto if available
            nikto_results = await self._run_nikto(target, options)
            if nikto_results:
                vuln_info['findings'].extend(nikto_results)
            
            # Manual vulnerability checks
            manual_vulns = await self._manual_vuln_checks(target)
            if manual_vulns:
                vuln_info['findings'].extend(manual_vulns)
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed for {target}: {str(e)}")
            vuln_info['findings'].append({
                'type': 'error',
                'category': 'vulnerability',
                'title': 'Vulnerability Scan Error',
                'data': {'error': str(e)}
            })
        
        return vuln_info
    
    async def _run_nikto(self, target: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run Nikto vulnerability scanner
        
        Args:
            target (str): Target URL
            options (Dict[str, Any]): Scan options
            
        Returns:
            List[Dict[str, Any]]: Nikto results
        """
        results = []
        
        try:
            cmd = [
                'nikto',
                '-h', target,
                '-Format', 'txt',
                '-timeout', str(self.timeout)
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if process.returncode == 0:
                # Parse Nikto output
                lines = process.stdout.split('\n')
                for line in lines:
                    if '+ ' in line and 'OSVDB' in line:
                        # Parse Nikto finding
                        results.append({
                            'type': 'finding',
                            'category': 'vulnerability',
                            'title': 'Nikto Finding',
                            'data': {
                                'description': line.strip(),
                                'tool': 'nikto'
                            },
                            'severity': 'medium'
                        })
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Nikto timed out for {target}")
        except FileNotFoundError:
            logger.debug("Nikto not available")
        except Exception as e:
            logger.debug(f"Nikto execution failed: {str(e)}")
        
        return results
    
    async def _manual_vuln_checks(self, target: str) -> List[Dict[str, Any]]:
        """
        Manual vulnerability checks
        
        Args:
            target (str): Target URL
            
        Returns:
            List[Dict[str, Any]]: Manual vulnerability findings
        """
        results = []
        
        try:
            # Check for common vulnerabilities
            vuln_checks = [
                self._check_clickjacking(target),
                self._check_cors_misconfiguration(target),
                self._check_security_headers(target),
                self._check_directory_listing(target)
            ]
            
            vuln_results = await asyncio.gather(*vuln_checks, return_exceptions=True)
            
            for result in vuln_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, dict):
                    results.append(result)
        
        except Exception as e:
            logger.debug(f"Manual vulnerability checks failed: {str(e)}")
        
        return results
    
    def _get_wordlist(self, scan_type: str, options: Dict[str, Any]) -> Optional[str]:
        """
        Get appropriate wordlist for scan type
        
        Args:
            scan_type (str): Type of scan
            options (Dict[str, Any]): Scan options
            
        Returns:
            Optional[str]: Path to wordlist file
        """
        # Check if custom wordlist is specified
        custom_wordlist = options.get('wordlist')
        if custom_wordlist and Path(custom_wordlist).exists():
            return custom_wordlist
        
        # Use default wordlists
        wordlists = self.default_wordlists.get(scan_type, [])
        
        for wordlist in wordlists:
            if Path(wordlist).exists():
                return wordlist
        
        logger.warning(f"No wordlist found for {scan_type}")
        return None
    
    async def _analyze_ssl(self, target: str) -> Dict[str, Any]:
        """
        Analyze SSL/TLS configuration
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: SSL analysis results
        """
        ssl_info = {'findings': []}
        
        try:
            from utils.network import NetworkUtils
            network_utils = NetworkUtils()
            
            # Extract hostname and port from URL
            from urllib.parse import urlparse
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Check SSL certificate
            cert_info = network_utils.check_ssl_certificate(hostname, port)
            
            if cert_info.get('valid'):
                ssl_info['findings'].append({
                    'type': 'info',
                    'category': 'ssl_analysis',
                    'title': 'SSL Certificate Information',
                    'data': cert_info,
                    'severity': 'info'
                })
                
                # Check for security issues
                if cert_info.get('expired'):
                    ssl_info['findings'].append({
                        'type': 'finding',
                        'category': 'ssl_analysis',
                        'title': 'Expired SSL Certificate',
                        'data': {'expiration_date': cert_info.get('not_after')},
                        'severity': 'high'
                    })
                
                days_until_expiration = cert_info.get('days_until_expiration', 0)
                if 0 < days_until_expiration < 30:
                    ssl_info['findings'].append({
                        'type': 'finding',
                        'category': 'ssl_analysis',
                        'title': 'SSL Certificate Expiring Soon',
                        'data': {'days_remaining': days_until_expiration},
                        'severity': 'medium'
                    })
            
            elif cert_info.get('error'):
                ssl_info['findings'].append({
                    'type': 'finding',
                    'category': 'ssl_analysis',
                    'title': 'SSL Certificate Error',
                    'data': {'error': cert_info['error']},
                    'severity': 'medium'
                })
        
        except Exception as e:
            logger.debug(f"SSL analysis failed: {str(e)}")
            ssl_info['findings'].append({
                'type': 'error',
                'category': 'ssl_analysis',
                'title': 'SSL Analysis Error',
                'data': {'error': str(e)}
            })
        
        return ssl_info
    
    async def _analyze_headers(self, target: str) -> Dict[str, Any]:
        """
        Analyze HTTP headers for security issues
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: Header analysis results
        """
        header_info = {'findings': []}
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                async with session.get(target, ssl=False) as response:
                    headers = dict(response.headers)
                    
                    # Security headers to check
                    security_headers = {
                        'X-Frame-Options': 'Clickjacking protection',
                        'X-Content-Type-Options': 'MIME type sniffing protection',
                        'X-XSS-Protection': 'XSS protection',
                        'Strict-Transport-Security': 'HTTPS enforcement',
                        'Content-Security-Policy': 'Content security policy',
                        'Referrer-Policy': 'Referrer policy',
                        'Permissions-Policy': 'Feature policy'
                    }
                    
                    missing_headers = []
                    for header, description in security_headers.items():
                        if header not in headers:
                            missing_headers.append({'header': header, 'description': description})
                    
                    if missing_headers:
                        header_info['findings'].append({
                            'type': 'finding',
                            'category': 'security_headers',
                            'title': 'Missing Security Headers',
                            'data': {'missing_headers': missing_headers},
                            'severity': 'medium'
                        })
                    
                    # Check for information disclosure in headers
                    disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                    disclosed_info = {}
                    
                    for header in disclosure_headers:
                        if header in headers:
                            disclosed_info[header] = headers[header]
                    
                    if disclosed_info:
                        header_info['findings'].append({
                            'type': 'finding',
                            'category': 'information_disclosure',
                            'title': 'Information Disclosure in Headers',
                            'data': {'disclosed_headers': disclosed_info},
                            'severity': 'low'
                        })
                    
                    # Store all headers for reference
                    header_info['findings'].append({
                        'type': 'info',
                        'category': 'headers',
                        'title': 'HTTP Response Headers',
                        'data': {'headers': headers},
                        'severity': 'info'
                    })
        
        except Exception as e:
            logger.debug(f"Header analysis failed: {str(e)}")
            header_info['findings'].append({
                'type': 'error',
                'category': 'headers',
                'title': 'Header Analysis Error',
                'data': {'error': str(e)}
            })
        
        return header_info
    
    async def _analyze_robots_sitemap(self, target: str) -> Dict[str, Any]:
        """
        Analyze robots.txt and sitemap.xml files
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: Robots/sitemap analysis results
        """
        analysis_info = {'findings': []}
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                # Check robots.txt
                robots_url = urljoin(target, '/robots.txt')
                try:
                    async with session.get(robots_url, ssl=False) as response:
                        if response.status == 200:
                            robots_content = await response.text()
                            
                            # Parse robots.txt for interesting paths
                            disallowed_paths = []
                            for line in robots_content.split('\n'):
                                if line.strip().startswith('Disallow:'):
                                    path = line.split(':', 1)[1].strip()
                                    if path and path != '/':
                                        disallowed_paths.append(path)
                            
                            analysis_info['findings'].append({
                                'type': 'info',
                                'category': 'robots_sitemap',
                                'title': 'Robots.txt Found',
                                'data': {
                                    'url': robots_url,
                                    'content': robots_content,
                                    'disallowed_paths': disallowed_paths
                                },
                                'severity': 'info'
                            })
                            
                            # Check if interesting paths are accessible
                            for path in disallowed_paths[:10]:  # Limit to first 10
                                try:
                                    test_url = urljoin(target, path)
                                    async with session.head(test_url, ssl=False) as test_response:
                                        if test_response.status == 200:
                                            analysis_info['findings'].append({
                                                'type': 'finding',  
                                                'category': 'robots_sitemap',
                                                'title': f'Accessible Disallowed Path: {path}',
                                                'data': {'path': path, 'url': test_url},
                                                'severity': 'low'
                                            })
                                except Exception:
                                    continue
                
                except Exception:
                    pass
                
                # Check sitemap.xml
                sitemap_url = urljoin(target, '/sitemap.xml')
                try:
                    async with session.get(sitemap_url, ssl=False) as response:
                        if response.status == 200:
                            sitemap_content = await response.text()
                            
                            # Extract URLs from sitemap
                            import xml.etree.ElementTree as ET
                            try:
                                root = ET.fromstring(sitemap_content)
                                urls = []
                                for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                                    loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                                    if loc_elem is not None:
                                        urls.append(loc_elem.text)
                                
                                analysis_info['findings'].append({
                                    'type': 'info',
                                    'category': 'robots_sitemap',
                                    'title': 'Sitemap.xml Found',
                                    'data': {
                                        'url': sitemap_url,
                                        'urls_found': len(urls),
                                        'sample_urls': urls[:20]  # First 20 URLs
                                    },
                                    'severity': 'info'
                                })
                                
                            except ET.ParseError:
                                analysis_info['findings'].append({
                                    'type': 'info',
                                    'category': 'robots_sitemap',
                                    'title': 'Sitemap.xml Found (Invalid XML)',
                                    'data': {'url': sitemap_url, 'content_preview': sitemap_content[:500]},
                                    'severity': 'info'
                                })
                
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"Robots/sitemap analysis failed: {str(e)}")
        
        return analysis_info
    
    async def _check_clickjacking(self, target: str) -> Dict[str, Any]:
        """
        Check for clickjacking vulnerability
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: Clickjacking check result
        """
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                async with session.get(target, ssl=False) as response:
                    headers = dict(response.headers)
                    
                    # Check for X-Frame-Options header
                    x_frame_options = headers.get('X-Frame-Options', '').lower()
                    csp = headers.get('Content-Security-Policy', '').lower()
                    
                    # Check if clickjacking protection is present
                    protected = (
                        x_frame_options in ['deny', 'sameorigin'] or
                        'frame-ancestors' in csp
                    )
                    
                    if not protected:
                        return {
                            'type': 'finding',
                            'category': 'vulnerability',
                            'title': 'Clickjacking Vulnerability',
                            'data': {
                                'description': 'Application may be vulnerable to clickjacking attacks',
                                'missing_protections': ['X-Frame-Options', 'Content-Security-Policy frame-ancestors']
                            },
                            'severity': 'medium'
                        }
        
        except Exception as e:
            logger.debug(f"Clickjacking check failed: {str(e)}")
        
        return {}
    
    async def _check_cors_misconfiguration(self, target: str) -> Dict[str, Any]:
        """
        Check for CORS misconfiguration
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: CORS check result
        """
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                
                # Test with malicious origin
                headers = {
                    'Origin': 'https://evil.com',
                    'User-Agent': self.user_agent
                }
                
                async with session.options(target, headers=headers, ssl=False) as response:
                    cors_headers = dict(response.headers)
                    
                    # Check if malicious origin is allowed
                    allowed_origin = cors_headers.get('Access-Control-Allow-Origin', '')
                    
                    if allowed_origin == '*' or 'evil.com' in allowed_origin:
                        return {
                            'type': 'finding',
                            'category': 'vulnerability',
                            'title': 'CORS Misconfiguration',
                            'data': {
                                'description': 'CORS policy allows requests from any origin',
                                'allowed_origin': allowed_origin
                            },
                            'severity': 'medium'
                        }
        
        except Exception as e:
            logger.debug(f"CORS check failed: {str(e)}")
        
        return {}
    
    async def _check_security_headers(self, target: str) -> List[Dict[str, Any]]:
        """
        Comprehensive security headers check
        
        Args:
            target (str): Target URL
            
        Returns:
            List[Dict[str, Any]]: Security header findings
        """
        findings = []
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                async with session.get(target, ssl=False) as response:
                    headers = dict(response.headers)
                    
                    # Critical security headers
                    critical_headers = {
                        'Strict-Transport-Security': {
                            'severity': 'high',
                            'description': 'HSTS header missing - HTTPS not enforced'
                        },
                        'Content-Security-Policy': {
                            'severity': 'medium',
                            'description': 'CSP header missing - XSS protection not implemented'
                        }
                    }
                    
                    for header, info in critical_headers.items():
                        if header not in headers and target.startswith('https://'):
                            findings.append({
                                'type': 'finding',
                                'category': 'security_headers',
                                'title': f'Missing {header} Header',
                                'data': {'description': info['description']},
                                'severity': info['severity']
                            })
        
        except Exception as e:
            logger.debug(f"Security headers check failed: {str(e)}")
        
        return findings
    
    async def _check_directory_listing(self, target: str) -> Dict[str, Any]:
        """
        Check for directory listing vulnerability
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: Directory listing check result
        """
        try:
            # Common directories that might have listing enabled
            test_dirs = ['/uploads/', '/images/', '/files/', '/backup/', '/temp/']
            
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                for directory in test_dirs:
                    try:
                        test_url = urljoin(target, directory)
                        async with session.get(test_url, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check for directory listing indicators
                                listing_indicators = [
                                    'Index of /',
                                    'Directory Listing',
                                    'Parent Directory',
                                    '<pre><a href="../">../</a>'
                                ]
                                
                                if any(indicator in content for indicator in listing_indicators):
                                    return {
                                        'type': 'finding',
                                        'category': 'vulnerability',
                                        'title': f'Directory Listing Enabled: {directory}',
                                        'data': {
                                            'url': test_url,
                                            'description': 'Directory listing is enabled, potentially exposing sensitive files'
                                        },
                                        'severity': 'medium'
                                    }
                    except Exception:
                        continue
        
        except Exception as e:
            logger.debug(f"Directory listing check failed: {str(e)}")
        
        return {}

# Plugin interface for AutoRecon-Pro
def run_plugin(target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Plugin entry point for AutoRecon-Pro
    
    Args:
        target (str): Target URL or domain
        options (Dict[str, Any], optional): Plugin options
        
    Returns:
        Dict[str, Any]: Plugin results
    """
    scanner = WebScanner(options)
    
    # Run the async scanner
    import asyncio
    
    try:
        if asyncio.get_running_loop():
            # If already in an async context, create a new loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, scanner.scan_target(target, options))
                return future.result()
        else:
            return asyncio.run(scanner.scan_target(target, options))
    except Exception as e:
        return {
            'target': target,
            'status': 'failed',
            'error': str(e),
            'findings': []
        }f"Web scan failed for {target}: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    async def _check_url_accessibility(self, url: str) -> bool:
        """
        Check if URL is accessible
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if accessible, False otherwise
        """
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.head(url, ssl=False) as response:
                    return response.status < 500
        except Exception:
            return False
    
    async def _gather_basic_info(self, target: str) -> Dict[str, Any]:
        """
        Gather basic information about the web application
        
        Args:
            target (str): Target URL
            
        Returns:
            Dict[str, Any]: Basic information
        """
        info = {'findings': []}
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                async with session.get(target, ssl=False) as response:
                    content = await response.text()
                    
                    # Basic response information
                    info['findings'].append({
                        'type': 'info',
                        'category': 'basic_info',
                        'title': 'HTTP Response Information',
                        'data': {
                            'status_code': response.status,
                            'content_length': len(content),
                            'content_type': response.headers.get('Content-Type', 'Unknown'),
                            'server': response.headers.get('Server', 'Unknown'),
                            'headers': dict(response.headers)
                        }
                    })
                    
                    # Extract title
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        info['findings'].append({
                            'type': 'info',
                            'category': 'basic_info',
                            'title': 'Page Title',
                            'data': {'title': title_match.group(1).strip()}
                        })
                    
                    # Extract meta information
                    meta_tags = re.findall(r'<meta[^>]+>', content, re.IGNORECASE)
                    meta_info = {}
                    for meta in meta_tags:
                        name_match = re.search(r'name=["\']([^"\']+)["\']', meta, re.IGNORECASE)
                        content_match = re.search(r'content=["\']([^"\']+)["\']', meta, re.IGNORECASE)
                        if name_match and content_match:
                            meta_info[name_match.group(1)] = content_match.group(1)
                    
                    if meta_info:
                        info['findings'].append({
                            'type': 'info',
                            'category': 'basic_info',
                            'title': 'Meta Information',
                            'data': meta_info
                        })
                    
                    # Extract forms
                    forms = re.findall(r'<form[^>]*>.*?</form>', content, re.IGNORECASE | re.DOTALL)
                    if forms:
                        form_data = []
                        for form in forms:
                            action = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                            method = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
                            inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
                            
                            form_info = {
                                'action': action.group(1) if action else '',
                                'method': method.group(1) if method else 'GET',
                                'inputs': len(inputs)
                            }
                            form_data.append(form_info)
                        
                        info['findings'].append({
                            'type': 'info',
                            'category': 'basic_info',
                            'title': 'Forms Detected',
                            'data': {'forms': form_data}
                        })
                    
                    # Extract links
                    links = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
                    external_links = [link for link in links if link.startswith(('http://', 'https://')) 
                                    and not link.startswith(target)]
                    
                    if external_links:
                        info['findings'].append({
                            'type': 'info',
                            'category': 'basic_info',
                            'title': 'External Links',
                            'data': {'external_links': external_links[:20]}  # Limit to first 20
                        })
                    
        except Exception as e:
            logger.error(