#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Advanced Nmap Scanner Plugin
"""

import asyncio
import xml.etree.ElementTree as ET
import re
from typing import Dict, List, Any
from core.plugin_manager import PortScanPlugin

class NmapScanner(PortScanPlugin):
    """Advanced Nmap scanning plugin with comprehensive port discovery"""
    
    @property
    def description(self) -> str:
        return "Advanced Nmap port scanner with service detection and OS fingerprinting"
    
    @property
    def dependencies(self) -> List[str]:
        return ['nmap']
    
    @property
    def tags(self) -> List[str]:
        return ['default', 'port_scan', 'service_detection', 'os_detection']
    
    @property
    def priority(self) -> int:
        return 10  # High priority for port scanning
    
    async def run(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive Nmap scan"""
        target = target_info['target']
        output_dir = target_info.get('output_dir', '/tmp')
        
        results = {
            'open_ports': {},
            'services': {},
            'os_detection': {},
            'script_results': {},
            'scan_stats': {},
            'errors': []
        }
        
        try:
            # Phase 1: Quick TCP SYN scan for port discovery
            tcp_results = await self._run_tcp_discovery(target, output_dir)
            results.update(tcp_results)
            
            # Phase 2: UDP scan on common ports (if not in quick mode)
            if not self.config.get('features.quick_mode', False):
                udp_results = await self._run_udp_scan(target, output_dir)
                results['udp_ports'] = udp_results.get('open_ports', {})
                results['services'].update(udp_results.get('services', {}))
            
            # Phase 3: Service version detection on discovered ports
            if results['open_ports']:
                service_results = await self._run_service_detection(target, results['open_ports'], output_dir)
                results['services'].update(service_results.get('services', {}))
                results['script_results'] = service_results.get('script_results', {})
            
            # Phase 4: OS detection (if enabled)
            if self.config.get('features.os_detection', True):
                os_results = await self._run_os_detection(target, output_dir)
                results['os_detection'] = os_results
            
            # Generate manual commands
            self._generate_manual_commands(target, results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Nmap scan failed for {target}: {e}")
            results['errors'].append(str(e))
            return results
    
    async def _run_tcp_discovery(self, target: str, output_dir: str) -> Dict[str, Any]:
        """Run TCP port discovery scan"""
        self.logger.scan_start(target, "TCP Discovery")
        
        # Determine port range
        ports = self.config.get('scanning.ports', '1-1000')
        
        # Build nmap command
        xml_output = f"{output_dir}/nmap_tcp_{target.replace('/', '_')}.xml"
        
        cmd_parts = [
            'nmap',
            '-sS',  # SYN scan
            '-Pn',  # Skip ping
            f'-p {ports}',
            '--min-rate=1000',
            '--max-retries=1',
            f'-oX {xml_output}',
            target
        ]
        
        # Add timing template based on config
        timing = self.config.get('scanning.timing', 'normal')
        timing_map = {
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }
        cmd_parts.insert(-1, timing_map.get(timing, '-T3'))
        
        command = ' '.join(cmd_parts)
        
        # Execute scan
        start_time = asyncio.get_event_loop().time()
        result = await self.execute_command(command)
        duration = asyncio.get_event_loop().time() - start_time
        
        if result['exit_code'] == 0:
            # Parse XML results
            parsed_results = self._parse_nmap_xml(xml_output)
            parsed_results['scan_duration'] = duration
            
            self.logger.scan_complete(target, "TCP Discovery", duration)
            self.logger.success(f"Found {len(parsed_results.get('open_ports', {}))} open TCP ports")
            
            return parsed_results
        else:
            error_msg = result.get('stderr', 'Unknown error')
            self.logger.scan_error(target, "TCP Discovery", error_msg)
            return {'open_ports': {}, 'services': {}, 'errors': [error_msg]}
    
    async def _run_udp_scan(self, target: str, output_dir: str) -> Dict[str, Any]:
        """Run UDP port scan on common ports"""
        self.logger.scan_start(target, "UDP Discovery")
        
        # Common UDP ports
        udp_ports = self.config.get('scanning.udp_ports', 'top-100')
        
        if udp_ports == 'top-100':
            udp_ports = '53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353'
        elif udp_ports == 'top-1000':
            udp_ports = '--top-ports 1000'
        
        xml_output = f"{output_dir}/nmap_udp_{target.replace('/', '_')}.xml"
        
        cmd_parts = [
            'nmap',
            '-sU',  # UDP scan
            '-Pn',
            f'-p {udp_ports}' if not udp_ports.startswith('--') else udp_ports,
            '--min-rate=500',
            f'-oX {xml_output}',
            target
        ]
        
        command = ' '.join(cmd_parts)
        
        start_time = asyncio.get_event_loop().time()
        result = await self.execute_command(command)
        duration = asyncio.get_event_loop().time() - start_time
        
        if result['exit_code'] == 0:
            parsed_results = self._parse_nmap_xml(xml_output)
            parsed_results['scan_duration'] = duration
            
            self.logger.scan_complete(target, "UDP Discovery", duration)
            self.logger.success(f"Found {len(parsed_results.get('open_ports', {}))} open UDP ports")
            
            return parsed_results
        else:
            error_msg = result.get('stderr', 'Unknown error')
            self.logger.scan_error(target, "UDP Discovery", error_msg)
            return {'open_ports': {}, 'services': {}}
    
    async def _run_service_detection(self, target: str, open_ports: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Run service version detection and default scripts"""
        self.logger.scan_start(target, "Service Detection")
        
        # Format ports for nmap
        tcp_ports = [p for p in open_ports.keys() if not p.endswith('/udp')]
        if not tcp_ports:
            return {'services': {}, 'script_results': {}}
        
        port_list = ','.join(tcp_ports)
        xml_output = f"{output_dir}/nmap_services_{target.replace('/', '_')}.xml"
        
        cmd_parts = [
            'nmap',
            '-sS',
            '-Pn',
            f'-p {port_list}',
            '-sV',  # Version detection
            '-sC',  # Default scripts
            '--version-intensity 5',
            f'-oX {xml_output}',
            target
        ]
        
        command = ' '.join(cmd_parts)
        
        start_time = asyncio.get_event_loop().time()
        result = await self.execute_command(command)
        duration = asyncio.get_event_loop().time() - start_time
        
        if result['exit_code'] == 0:
            parsed_results = self._parse_nmap_xml(xml_output, include_scripts=True)
            
            self.logger.scan_complete(target, "Service Detection", duration)
            self.logger.success(f"Detected services on {len(parsed_results.get('services', {}))} ports")
            
            return parsed_results
        else:
            error_msg = result.get('stderr', 'Unknown error')
            self.logger.scan_error(target, "Service Detection", error_msg)
            return {'services': {}, 'script_results': {}}
    
    async def _run_os_detection(self, target: str, output_dir: str) -> Dict[str, Any]:
        """Run OS detection scan"""
        self.logger.scan_start(target, "OS Detection")
        
        xml_output = f"{output_dir}/nmap_os_{target.replace('/', '_')}.xml"
        
        cmd_parts = [
            'nmap',
            '-Pn',
            '-O',  # OS detection
            '--osscan-guess',
            '--max-os-tries=2',
            f'-oX {xml_output}',
            target
        ]
        
        command = ' '.join(cmd_parts)
        
        start_time = asyncio.get_event_loop().time()
        result = await self.execute_command(command)
        duration = asyncio.get_event_loop().time() - start_time
        
        if result['exit_code'] == 0:
            os_info = self._parse_os_detection(xml_output)
            
            self.logger.scan_complete(target, "OS Detection", duration)
            if os_info.get('detected'):
                self.logger.success(f"OS detected: {os_info.get('os_family', 'Unknown')}")
            
            return os_info
        else:
            error_msg = result.get('stderr', 'OS detection failed')
            self.logger.scan_error(target, "OS Detection", error_msg)
            return {'detected': False, 'os_family': 'unknown', 'confidence': 0}
    
    def _parse_nmap_xml(self, xml_file: str, include_scripts: bool = False) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        results = {
            'open_ports': {},
            'services': {},
            'script_results': {},
            'scan_stats': {}
        }
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Parse scan statistics
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    results['scan_stats'] = {
                        'elapsed_time': finished.get('elapsed'),
                        'exit_status': finished.get('exit'),
                        'summary': finished.get('summary')
                    }
            
            # Parse host information
            for host in root.findall('host'):
                # Skip hosts that are down
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        port_key = f"{port_id}/{protocol}" if protocol == 'udp' else port_id
                        
                        state = port.find('state')
                        if state is not None and state.get('state') in ['open', 'open|filtered']:
                            results['open_ports'][port_key] = {
                                'port': port_id,
                                'protocol': protocol,
                                'state': state.get('state'),
                                'reason': state.get('reason')
                            }
                            
                            # Parse service information
                            service = port.find('service')
                            if service is not None:
                                service_info = {
                                    'name': service.get('name', 'unknown'),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'extrainfo': service.get('extrainfo', ''),
                                    'ostype': service.get('ostype', ''),
                                    'method': service.get('method', ''),
                                    'conf': service.get('conf', '')
                                }
                                
                                # Build service string
                                service_parts = [service_info['name']]
                                if service_info['product']:
                                    service_parts.append(service_info['product'])
                                if service_info['version']:
                                    service_parts.append(service_info['version'])
                                
                                service_info['service'] = ' '.join(service_parts)
                                results['services'][port_key] = service_info
                            
                            # Parse script results if requested
                            if include_scripts:
                                scripts = port.findall('script')
                                if scripts:
                                    results['script_results'][port_key] = []
                                    for script in scripts:
                                        script_info = {
                                            'id': script.get('id'),
                                            'output': script.get('output', ''),
                                        }
                                        
                                        # Parse script elements
                                        elements = script.findall('.//elem')
                                        if elements:
                                            script_info['elements'] = {}
                                            for elem in elements:
                                                key = elem.get('key')
                                                if key:
                                                    script_info['elements'][key] = elem.text
                                        
                                        results['script_results'][port_key].append(script_info)
                                        
                                        # Extract interesting information
                                        self._process_script_output(script_info, port_key)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to parse Nmap XML {xml_file}: {e}")
            return results
    
    def _parse_os_detection(self, xml_file: str) -> Dict[str, Any]:
        """Parse OS detection results from Nmap XML"""
        os_info = {'detected': False, 'os_family': 'unknown', 'confidence': 0}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                os_elem = host.find('os')
                if os_elem is not None:
                    # Find the best OS match
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        accuracy = int(osmatch.get('accuracy', 0))
                        if accuracy > os_info['confidence']:
                            os_info = {
                                'detected': True,
                                'os_family': osmatch.get('name', 'unknown'),
                                'confidence': accuracy,
                                'line': osmatch.get('line', ''),
                                'accuracy': accuracy
                            }
                            
                            # Extract OS class information
                            osclass = osmatch.find('osclass')
                            if osclass is not None:
                                os_info.update({
                                    'vendor': osclass.get('vendor', ''),
                                    'osfamily': osclass.get('osfamily', ''),
                                    'osgen': osclass.get('osgen', ''),
                                    'type': osclass.get('type', '')
                                })
            
            return os_info
            
        except Exception as e:
            self.logger.error(f"Failed to parse OS detection XML {xml_file}: {e}")
            return os_info
    
    def _process_script_output(self, script_info: Dict[str, Any], port_key: str):
        """Process Nmap script output for interesting findings"""
        script_id = script_info.get('id', '')
        output = script_info.get('output', '')
        
        # Check for common vulnerabilities
        if 'vuln' in script_id.lower():
            if 'VULNERABLE' in output or 'vulnerable' in output.lower():
                self.logger.vulnerability('Script Detection', port_key, 'MEDIUM', f"{script_id}: {output}")
        
        # Check for authentication bypasses
        if any(keyword in output.lower() for keyword in ['anonymous', 'null session', 'guest']):
            self.logger.finding('Authentication Bypass', port_key, f"{script_id}: Authentication not required")
        
        # Check for default credentials
        if any(keyword in output.lower() for keyword in ['default', 'password:', 'login:']):
            self.logger.finding('Default Credentials', port_key, f"{script_id}: Possible default credentials")
        
        # Check for SSL/TLS issues
        if 'ssl' in script_id.lower() or 'tls' in script_id.lower():
            if any(issue in output.lower() for issue in ['weak', 'insecure', 'deprecated']):
                self.logger.vulnerability('SSL/TLS Issue', port_key, 'MEDIUM', f"{script_id}: {output}")
        
        # Extract patterns
        patterns = self.extract_patterns(output)
        self.patterns.extend(patterns)
    
    def _generate_manual_commands(self, target: str, results: Dict[str, Any]):
        """Generate manual commands for further testing"""
        open_ports = results.get('open_ports', {})
        services = results.get('services', {})
        
        # Generate service-specific manual commands
        for port, service_info in services.items():
            service_name = service_info.get('name', '').lower()
            port_num = port.split('/')[0]
            
            if service_name == 'http' or service_name == 'https':
                self.add_manual_command(
                    f"gobuster dir -u {service_name}://{target}:{port_num} -w /usr/share/wordlists/dirb/common.txt",
                    f"Directory bruteforce on {service_name}://{target}:{port_num}"
                )
                self.add_manual_command(
                    f"nikto -h {service_name}://{target}:{port_num}",
                    f"Web vulnerability scan on {service_name}://{target}:{port_num}"
                )
            
            elif service_name == 'ssh':
                self.add_manual_command(
                    f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} -s {port_num} ssh",
                    f"SSH brute force on {target}:{port_num}"
                )
            
            elif service_name in ['smb', 'netbios-ssn', 'microsoft-ds']:
                self.add_manual_command(
                    f"enum4linux -a {target}",
                    f"SMB enumeration on {target}"
                )
                self.add_manual_command(
                    f"smbclient -L //{target} -N",
                    f"List SMB shares on {target}"
                )
            
            elif service_name == 'ftp':
                self.add_manual_command(
                    f"ftp {target} {port_num}",
                    f"Manual FTP connection to {target}:{port_num}"
                )
                self.add_manual_command(
                    f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} -s {port_num} ftp",
                    f"FTP brute force on {target}:{port_num}"
                )
            
            elif service_name in ['mysql', 'mssql', 'postgresql']:
                self.add_manual_command(
                    f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} -s {port_num} {service_name}",
                    f"Database brute force on {target}:{port_num}"
                )
            
            elif service_name == 'snmp':
                self.add_manual_command(
                    f"snmpwalk -c public -v1 {target}",
                    f"SNMP walk on {target}"
                )
                self.add_manual_command(
                    f"onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt {target}",
                    f"SNMP community string bruteforce on {target}"
                )
        
        # Vulnerability scanning commands
        if open_ports:
            port_list = ','.join([p.split('/')[0] for p in open_ports.keys() if '/' not in p or '/tcp' in p])
            self.add_manual_command(
                f"nmap --script vuln -p {port_list} {target}",
                f"Vulnerability scan on discovered ports"
            )
    
    async def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute command using scanner engine"""
        # This would use the scanner engine's execute_command method
        # For now, we'll implement a basic version
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
            }