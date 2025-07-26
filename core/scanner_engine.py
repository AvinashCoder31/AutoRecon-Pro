#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Advanced Scanner Engine
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import subprocess
import shlex
from concurrent.futures import ThreadPoolExecutor
import aiofiles
import signal

class ScannerEngine:
    """Advanced scanning engine with intelligent workflow management"""
    
    def __init__(self, config, logger, plugin_manager):
        self.config = config
        self.logger = logger
        self.plugin_manager = plugin_manager
        self.active_scans = {}
        self.scan_results = {}
        self.scan_queue = asyncio.Queue()
        self.executor = ThreadPoolExecutor(max_workers=config.threads)
        self.stop_event = asyncio.Event()
        
    async def scan_target(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive scan for a single target"""
        target = target_info['target']
        self.logger.info(f"Starting comprehensive scan for {target}")
        
        scan_start_time = time.time()
        results = {
            'target': target,
            'target_info': target_info,
            'scan_phases': {},
            'timeline': [],
            'summary': {},
            'manual_commands': [],
            'patterns_found': [],
            'errors': []
        }
        
        try:
            # Phase 1: Discovery and Port Scanning
            discovery_results = await self._run_discovery_phase(target_info)
            results['scan_phases']['discovery'] = discovery_results
            results['timeline'].append({
                'phase': 'discovery',
                'timestamp': time.time(),
                'duration': discovery_results.get('duration', 0)
            })
            
            # Update target info with discovered services
            target_info.update(discovery_results.get('enhanced_target_info', {}))
            
            # Phase 2: Service Enumeration
            if discovery_results.get('open_ports'):
                service_results = await self._run_service_enumeration_phase(target_info)
                results['scan_phases']['service_enumeration'] = service_results
                results['timeline'].append({
                    'phase': 'service_enumeration',
                    'timestamp': time.time(),
                    'duration': service_results.get('duration', 0)
                })
            
            # Phase 3: Vulnerability Assessment
            if self.config.get('features.vulnerability_scan', True):
                vuln_results = await self._run_vulnerability_phase(target_info)
                results['scan_phases']['vulnerability_assessment'] = vuln_results
                results['timeline'].append({
                    'phase': 'vulnerability_assessment',
                    'timestamp': time.time(),
                    'duration': vuln_results.get('duration', 0)
                })
            
            # Phase 4: Web Application Testing (if web services found)
            web_services = self._extract_web_services(results)
            if web_services:
                web_results = await self._run_web_testing_phase(target_info, web_services)
                results['scan_phases']['web_testing'] = web_results
                results['timeline'].append({
                    'phase': 'web_testing',
                    'timestamp': time.time(),
                    'duration': web_results.get('duration', 0)
                })
            
            # Generate comprehensive summary
            results['summary'] = self._generate_target_summary(results)
            results['total_duration'] = time.time() - scan_start_time
            
            self.logger.success(f"Completed comprehensive scan for {target}")
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed for {target}: {e}")
            results['errors'].append({
                'phase': 'scan_engine',
                'error': str(e),
                'timestamp': time.time()
            })
            return results
    
    async def _run_discovery_phase(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Run discovery and port scanning phase"""
        self.logger.info("Phase 1: Discovery and Port Scanning")
        phase_start = time.time()
        
        # Get port scanning plugins
        port_scan_plugins = self.plugin_manager.get_plugins_by_type('port_scan')
        
        # Run port scanning plugins
        port_results = await self.plugin_manager.run_plugins_parallel(
            port_scan_plugins, 
            target_info,
            max_concurrent=2  # Limit concurrent port scans
        )
        
        # Aggregate port scan results
        open_ports = {}
        services = {}
        
        for result in port_results:
            if 'error' not in result:
                ports_found = result.get('open_ports', {})
                services_found = result.get('services', {})
                
                open_ports.update(ports_found)
                services.update(services_found)
        
        # Enhanced target info for next phases
        enhanced_target_info = {
            'open_ports': open_ports,
            'services': services,
            'os_info': self._extract_os_info(port_results)
        }
        
        phase_duration = time.time() - phase_start
        
        return {
            'plugin_results': port_results,
            'open_ports': open_ports,
            'services': services,
            'enhanced_target_info': enhanced_target_info,
            'duration': phase_duration,
            'ports_found': len(open_ports),
            'services_identified': len(services)
        }
    
    async def _run_service_enumeration_phase(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Run service-specific enumeration phase"""
        self.logger.info("Phase 2: Service Enumeration")
        phase_start = time.time()
        
        # Get service scanning plugins
        service_plugins = self.plugin_manager.get_plugins_by_type('service_scan')
        
        # Filter plugins based on discovered services
        relevant_plugins = []
        for plugin in service_plugins:
            if plugin.should_run(target_info):
                relevant_plugins.append(plugin)
        
        # Run service enumeration plugins
        service_results = await self.plugin_manager.run_plugins_parallel(
            relevant_plugins,
            target_info,
            max_concurrent=self.config.get('performance.max_scans', 10)
        )
        
        # Process service enumeration results
        enumeration_data = {}
        credentials_found = []
        shares_found = []
        interesting_files = []
        
        for result in service_results:
            if 'error' not in result:
                service_name = result.get('service_name', 'unknown')
                enumeration_data[service_name] = result
                
                # Extract interesting findings
                if 'credentials' in result:
                    credentials_found.extend(result['credentials'])
                if 'shares' in result:
                    shares_found.extend(result['shares'])
                if 'interesting_files' in result:
                    interesting_files.extend(result['interesting_files'])
        
        phase_duration = time.time() - phase_start
        
        return {
            'plugin_results': service_results,
            'enumeration_data': enumeration_data,
            'credentials_found': credentials_found,
            'shares_found': shares_found,
            'interesting_files': interesting_files,
            'duration': phase_duration,
            'services_enumerated': len(enumeration_data)
        }
    
    async def _run_vulnerability_phase(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Run vulnerability assessment phase"""
        self.logger.info("Phase 3: Vulnerability Assessment")
        phase_start = time.time()
        
        # Get vulnerability scanning plugins
        vuln_plugins = self.plugin_manager.get_plugins_by_type('vuln_scan')
        
        # Filter plugins based on discovered services
        relevant_plugins = []
        for plugin in vuln_plugins:
            if plugin.should_run(target_info):
                relevant_plugins.append(plugin)
        
        # Run vulnerability scanning plugins
        vuln_results = await self.plugin_manager.run_plugins_parallel(
            relevant_plugins,
            target_info,
            max_concurrent=3  # Limit concurrent vuln scans
        )
        
        # Process vulnerability results
        vulnerabilities = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in vuln_results:
            if 'error' not in result and 'vulnerabilities' in result:
                for vuln in result['vulnerabilities']:
                    vulnerabilities.append(vuln)
                    severity = vuln.get('severity', 'info').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
        
        phase_duration = time.time() - phase_start
        
        return {
            'plugin_results': vuln_results,
            'vulnerabilities': vulnerabilities,
            'severity_counts': severity_counts,
            'duration': phase_duration,
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    async def _run_web_testing_phase(self, target_info: Dict[str, Any], web_services: List[Dict]) -> Dict[str, Any]:
        """Run web application testing phase"""
        self.logger.info("Phase 4: Web Application Testing")
        phase_start = time.time()
        
        # Get web-specific plugins
        web_plugins = self.plugin_manager.get_plugins_by_type('web_scan')
        
        web_results = []
        
        # Test each web service
        for web_service in web_services:
            # Update target info with current web service
            web_target_info = target_info.copy()
            web_target_info.update(web_service)
            
            # Run web plugins for this service
            service_results = await self.plugin_manager.run_plugins_parallel(
                web_plugins,
                web_target_info,
                max_concurrent=5
            )
            
            web_results.extend(service_results)
        
        # Process web testing results
        directories_found = []
        technologies_detected = []
        web_vulnerabilities = []
        screenshots = []
        
        for result in web_results:
            if 'error' not in result:
                if 'directories' in result:
                    directories_found.extend(result['directories'])
                if 'technologies' in result:
                    technologies_detected.extend(result['technologies'])
                if 'vulnerabilities' in result:
                    web_vulnerabilities.extend(result['vulnerabilities'])
                if 'screenshots' in result:
                    screenshots.extend(result['screenshots'])
        
        phase_duration = time.time() - phase_start
        
        return {
            'plugin_results': web_results,
            'directories_found': directories_found,
            'technologies_detected': technologies_detected,
            'web_vulnerabilities': web_vulnerabilities,
            'screenshots': screenshots,
            'duration': phase_duration,
            'web_services_tested': len(web_services)
        }
    
    def _extract_web_services(self, results: Dict[str, Any]) -> List[Dict]:
        """Extract web services from discovery results"""
        web_services = []
        discovery = results.get('scan_phases', {}).get('discovery', {})
        services = discovery.get('services', {})
        
        web_ports = ['80', '443', '8080', '8443', '3000', '5000', '8000', '9000']
        
        for port, service_info in services.items():
            if any(web_port in str(port) for web_port in web_ports) or \
               'http' in service_info.get('service', '').lower():
                
                # Determine protocol
                protocol = 'https' if 'ssl' in service_info.get('service', '').lower() or port == '443' else 'http'
                
                web_services.append({
                    'port': port,
                    'protocol': protocol,
                    'service_info': service_info,
                    'url': f"{protocol}://{results['target']}:{port}"
                })
        
        return web_services
    
    def _extract_os_info(self, port_results: List[Dict]) -> Dict[str, Any]:
        """Extract OS information from port scan results"""
        os_info = {'detected': False, 'os_family': 'unknown', 'confidence': 0}
        
        for result in port_results:
            if 'os_detection' in result:
                os_data = result['os_detection']
                if os_data.get('confidence', 0) > os_info['confidence']:
                    os_info.update(os_data)
        
        return os_info
    
    def _generate_target_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive target summary"""
        summary = {
            'target': results['target'],
            'scan_completion_time': time.time(),
            'total_duration': results.get('total_duration', 0),
            'phases_completed': len(results.get('scan_phases', {})),
            'statistics': {}
        }
        
        # Port statistics
        discovery = results.get('scan_phases', {}).get('discovery', {})
        summary['statistics']['ports_found'] = discovery.get('ports_found', 0)
        summary['statistics']['services_identified'] = discovery.get('services_identified', 0)
        
        # Service enumeration statistics
        service_enum = results.get('scan_phases', {}).get('service_enumeration', {})
        summary['statistics']['services_enumerated'] = service_enum.get('services_enumerated', 0)
        summary['statistics']['credentials_found'] = len(service_enum.get('credentials_found', []))
        summary['statistics']['shares_found'] = len(service_enum.get('shares_found', []))
        
        # Vulnerability statistics
        vuln_assess = results.get('scan_phases', {}).get('vulnerability_assessment', {})
        summary['statistics']['vulnerabilities_found'] = vuln_assess.get('total_vulnerabilities', 0)
        summary['statistics']['severity_breakdown'] = vuln_assess.get('severity_counts', {})
        
        # Web testing statistics
        web_testing = results.get('scan_phases', {}).get('web_testing', {})
        summary['statistics']['web_services_tested'] = web_testing.get('web_services_tested', 0)
        summary['statistics']['directories_found'] = len(web_testing.get('directories_found', []))
        summary['statistics']['technologies_detected'] = len(web_testing.get('technologies_detected', []))
        
        # Risk assessment
        total_vulns = summary['statistics']['vulnerabilities_found']
        critical_vulns = summary['statistics']['severity_breakdown'].get('critical', 0)
        high_vulns = summary['statistics']['severity_breakdown'].get('high', 0)
        
        if critical_vulns > 0:
            summary['risk_level'] = 'CRITICAL'
        elif high_vulns > 0:
            summary['risk_level'] = 'HIGH'
        elif total_vulns > 0:
            summary['risk_level'] = 'MEDIUM'
        else:
            summary['risk_level'] = 'LOW'
        
        return summary
    
    async def execute_command(self, command: str, cwd: str = None, timeout: int = None) -> Dict[str, Any]:
        """Execute system command asynchronously"""
        if timeout is None:
            timeout = self.config.get('performance.timeout', 300)
        
        start_time = time.time()
        
        try:
            # Split command safely
            cmd_args = shlex.split(command)
            
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
                
                duration = time.time() - start_time
                
                result = {
                    'command': command,
                    'exit_code': process.returncode,
                    'stdout': stdout.decode('utf-8', errors='ignore'),
                    'stderr': stderr.decode('utf-8', errors='ignore'),
                    'duration': duration,
                    'timeout': False
                }
                
                # Log command execution
                self.logger.command_executed(command, process.returncode, duration)
                
                return result
                
            except asyncio.TimeoutError:
                # Kill the process
                process.kill()
                await process.wait()
                
                return {
                    'command': command,
                    'exit_code': -1,
                    'stdout': '',
                    'stderr': f'Command timed out after {timeout} seconds',
                    'duration': timeout,
                    'timeout': True
                }
                
        except Exception as e:
            duration = time.time() - start_time
            return {
                'command': command,
                'exit_code': -1,
                'stdout': '',
                'stderr': str(e),
                'duration': duration,
                'timeout': False,
                'error': str(e)
            }
    
    async def execute_commands_parallel(self, commands: List[str], max_concurrent: int = 5) -> List[Dict[str, Any]]:
        """Execute multiple commands in parallel"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(cmd):
            async with semaphore:
                return await self.execute_command(cmd)
        
        tasks = [execute_with_semaphore(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Command execution error: {result}")
                valid_results.append({
                    'error': str(result),
                    'exit_code': -1,
                    'stdout': '',
                    'stderr': str(result)
                })
            else:
                valid_results.append(result)
        
        return valid_results
    
    async def save_scan_state(self, target: str, results: Dict[str, Any], output_dir: str):
        """Save scan state for resumption"""
        state_file = Path(output_dir) / f"{target}_scan_state.json"
        
        try:
            async with aiofiles.open(state_file, 'w') as f:
                await f.write(json.dumps(results, indent=2, default=str))
            
            self.logger.debug(f"Scan state saved to {state_file}")
        except Exception as e:
            self.logger.error(f"Failed to save scan state: {e}")
    
    async def load_scan_state(self, target: str, output_dir: str) -> Optional[Dict[str, Any]]:
        """Load previous scan state"""
        state_file = Path(output_dir) / f"{target}_scan_state.json"
        
        if not state_file.exists():
            return None
        
        try:
            async with aiofiles.open(state_file, 'r') as f:
                content = await f.read()
                return json.loads(content)
        except Exception as e:
            self.logger.error(f"Failed to load scan state: {e}")
            return None
    
    def stop_all_scans(self):
        """Stop all active scans"""
        self.logger.warning("Stopping all active scans...")
        self.stop_event.set()
        
        # Cancel active scans
        for scan_id, task in self.active_scans.items():
            if not task.done():
                task.cancel()
                self.logger.debug(f"Cancelled scan: {scan_id}")
    
    async def get_scan_progress(self, target: str) -> Dict[str, Any]:
        """Get scan progress for a target"""
        if target not in self.active_scans:
            return {'status': 'not_running'}
        
        # This would be implemented with more detailed progress tracking
        return {
            'status': 'running',
            'target': target,
            'start_time': self.active_scans[target].get('start_time'),
            'current_phase': self.active_scans[target].get('current_phase'),
            'progress_percentage': self.active_scans[target].get('progress', 0)
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_all_scans()
        self.executor.shutdown(wait=True)