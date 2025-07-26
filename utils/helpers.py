"""
AutoRecon-Pro Helper Utilities
Common utility functions and dependency validation
"""

import os
import sys
import shutil
import subprocess
import platform
import logging
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import importlib.util
import re
import time

logger = logging.getLogger(__name__)

def validate_dependencies() -> Dict[str, bool]:
    """
    Validate required system dependencies and tools
    
    Returns:
        Dict[str, bool]: Dictionary mapping tool names to availability status
    """
    required_tools = {
        'nmap': ['nmap', '--version'],
        'masscan': ['masscan', '--version'],
        'gobuster': ['gobuster', 'version'],
        'nikto': ['nikto', '-Version'],
        'whatweb': ['whatweb', '--version'],
        'hydra': ['hydra', '-h'],
        'enum4linux': ['enum4linux'],
        'smbclient': ['smbclient', '--version'],
        'snmpwalk': ['snmpwalk', '-V'],
        'curl': ['curl', '--version'],
        'wget': ['wget', '--version'],
        'dig': ['dig', '-v'],
        'nslookup': ['nslookup', '-version'],
        'python3': ['python3', '--version'],
        'pip3': ['pip3', '--version']
    }
    
    optional_tools = {
        'httpx': ['httpx', '-version'],
        'subfinder': ['subfinder', '-version'],
        'nuclei': ['nuclei', '-version'],
        'amass': ['amass', '-version'],
        'ffuf': ['ffuf', '-V'],
        'dirsearch': ['dirsearch', '-h'],
        'chromium': ['chromium', '--version'],
        'firefox': ['firefox', '--version']
    }
    
    results = {}
    
    logger.info("Validating required dependencies...")
    
    # Check required tools
    for tool, command in required_tools.items():
        results[tool] = check_tool_availability(command)
        status = "✓" if results[tool] else "✗"
        logger.info(f"{status} {tool}: {'Available' if results[tool] else 'Missing'}")
    
    # Check optional tools
    logger.info("Checking optional tools...")
    for tool, command in optional_tools.items():
        results[f"{tool}_optional"] = check_tool_availability(command)
        status = "✓" if results[f"{tool}_optional"] else "○"
        logger.info(f"{status} {tool}: {'Available' if results[f'{tool}_optional'] else 'Not installed (optional)'}")
    
    # Validate Python packages
    python_packages = [
        'requests', 'beautifulsoup4', 'lxml', 'colorama', 
        'termcolor', 'tqdm', 'pyyaml', 'jinja2', 'asyncio'
    ]
    
    logger.info("Validating Python packages...")
    for package in python_packages:
        results[f"python_{package}"] = check_python_package(package)
        status = "✓" if results[f"python_{package}"] else "✗"
        logger.info(f"{status} {package}: {'Available' if results[f'python_{package}'] else 'Missing'}")
    
    return results

def check_tool_availability(command: List[str]) -> bool:
    """
    Check if a system tool is available
    
    Args:
        command (List[str]): Command to execute for checking
        
    Returns:
        bool: True if tool is available, False otherwise
    """
    try:
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=10
        )
        return result.returncode == 0 or result.returncode is None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

def check_python_package(package_name: str) -> bool:
    """
    Check if a Python package is installed
    
    Args:
        package_name (str): Package name to check
        
    Returns:
        bool: True if package is available, False otherwise
    """
    try:
        importlib.import_module(package_name)
        return True
    except ImportError:
        return False

def setup_directories(base_path: str = "results") -> Dict[str, str]:
    """
    Set up directory structure for AutoRecon-Pro
    
    Args:
        base_path (str): Base directory path
        
    Returns:
        Dict[str, str]: Dictionary mapping directory types to paths
    """
    base_dir = Path(base_path)
    
    directories = {
        'base': str(base_dir),
        'scans': str(base_dir / 'scans'),
        'reports': str(base_dir / 'reports'),
        'screenshots': str(base_dir / 'screenshots'),
        'logs': str(base_dir / 'logs'),
        'temp': str(base_dir / 'temp'),
        'wordlists': str(base_dir / 'wordlists'),
        'configs': str(base_dir / 'configs'),
        'plugins': str(base_dir / 'plugins')
    }
    
    logger.info(f"Setting up directory structure in {base_path}")
    
    for dir_type, dir_path in directories.items():
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created directory: {dir_path}")
    
    # Create subdirectories for different scan types
    scan_subdirs = ['nmap', 'web', 'services', 'enumeration', 'vulnerabilities']
    for subdir in scan_subdirs:
        Path(directories['scans'] / subdir).mkdir(parents=True, exist_ok=True)
    
    # Create log subdirectories
    log_subdirs = ['debug', 'error', 'scan']
    for subdir in log_subdirs:
        Path(directories['logs'] / subdir).mkdir(parents=True, exist_ok=True)
    
    logger.info("Directory structure created successfully")
    return directories

def get_system_info() -> Dict[str, Any]:
    """
    Get system information for compatibility checking
    
    Returns:
        Dict[str, Any]: System information
    """
    return {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'python_implementation': platform.python_implementation(),
        'cpu_count': os.cpu_count(),
        'user': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
        'home_directory': str(Path.home()),
        'current_directory': str(Path.cwd()),
        'path_separator': os.pathsep,
        'environment_variables': dict(os.environ)
    }

def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format
    
    Args:
        seconds (float): Duration in seconds
        
    Returns:
        str: Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.2f}s"

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format
    
    Args:
        size_bytes (int): Size in bytes
        
    Returns:
        str: Formatted size string
    """
    if size_bytes == 0:
        return "0B"
    
    size_names = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f}{size_names[i]}"

def validate_target(target: str) -> Tuple[bool, str, str]:
    """
    Validate and categorize target input
    
    Args:
        target (str): Target string (IP, domain, CIDR, etc.)
        
    Returns:
        Tuple[bool, str, str]: (is_valid, target_type, normalized_target)
    """
    # Remove whitespace
    target = target.strip()
    
    if not target:
        return False, "empty", ""
    
    # Check for CIDR notation
    cidr_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
    if cidr_pattern.match(target):
        # Validate CIDR
        try:
            ip, prefix = target.split('/')
            prefix = int(prefix)
            if 0 <= prefix <= 32 and all(0 <= int(octet) <= 255 for octet in ip.split('.')):
                return True, "cidr", target
        except ValueError:
            pass
        return False, "invalid_cidr", target
    
    # Check for IP address
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(target):
        # Validate IP address
        try:
            if all(0 <= int(octet) <= 255 for octet in target.split('.')):
                return True, "ipv4", target
        except ValueError:
            pass
        return False, "invalid_ip", target
    
    # Check for IPv6 address
    ipv6_pattern = re.compile(r'^([0-9a-fA-F:]+)$')
    if ':' in target and ipv6_pattern.match(target):
        return True, "ipv6", target.lower()
    
    # Check for domain name
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    if domain_pattern.match(target):
        return True, "domain", target.lower()
    
    # Check for URL
    url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    if url_pattern.match(target):
        return True, "url", target.lower()
    
    return False, "unknown", target

def parse_port_range(port_range: str) -> List[int]:
    """
    Parse port range string into list of ports
    
    Args:
        port_range (str): Port range (e.g., "80,443,8000-8100")
        
    Returns:
        List[int]: List of port numbers
    """
    ports = []
    
    for part in port_range.split(','):
        part = part.strip()
        
        if '-' in part:
            # Handle range (e.g., "8000-8100")
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.extend(range(start, end + 1))
            except ValueError:
                logger.warning(f"Invalid port range: {part}")
        else:
            # Handle single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                logger.warning(f"Invalid port: {part}")
    
    return sorted(list(set(ports)))

def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Check if a port is open on a host
    
    Args:
        host (str): Target host
        port (int): Port number
        timeout (float): Connection timeout
        
    Returns:
        bool: True if port is open, False otherwise
    """
    import socket
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except (socket.gaierror, socket.timeout, OSError):
        return False

def generate_random_string(length: int = 8, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
    """
    Generate random string for temporary files, IDs, etc.
    
    Args:
        length (int): Length of string
        charset (str): Character set to use
        
    Returns:
        str: Random string
    """
    import random
    return ''.join(random.choice(charset) for _ in range(length))

def safe_filename(filename: str) -> str:
    """
    Convert string to safe filename by removing/replacing invalid characters
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Safe filename
    """
    # Replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    # Limit length
    filename = filename[:200]
    
    # Remove leading/trailing periods and spaces
    filename = filename.strip('. ')
    
    # Ensure not empty
    if not filename:
        filename = f"unnamed_{generate_random_string(6)}"
    
    return filename

def execute_command(command: List[str], timeout: int = 300, 
                   capture_output: bool = True, cwd: str = None) -> Dict[str, Any]:
    """
    Execute system command with enhanced error handling and logging
    
    Args:
        command (List[str]): Command and arguments
        timeout (int): Command timeout in seconds
        capture_output (bool): Whether to capture stdout/stderr
        cwd (str, optional): Working directory
        
    Returns:
        Dict[str, Any]: Execution results
    """
    start_time = time.time()
    
    try:
        logger.debug(f"Executing command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            cwd=cwd,
            env=os.environ.copy()
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        execution_result = {
            'success': result.returncode == 0,
            'returncode': result.returncode,
            'stdout': result.stdout if capture_output else None,
            'stderr': result.stderr if capture_output else None,
            'duration': duration,
            'command': ' '.join(command),
            'timeout': False
        }
        
        if result.returncode == 0:
            logger.debug(f"Command completed successfully in {format_duration(duration)}")
        else:
            logger.warning(f"Command failed with return code {result.returncode}")
        
        return execution_result
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return {
            'success': False,
            'returncode': -1,
            'stdout': None,
            'stderr': f"Command timed out after {timeout} seconds",
            'duration': timeout,
            'command': ' '.join(command),
            'timeout': True
        }
        
    except FileNotFoundError:
        logger.error(f"Command not found: {command[0]}")
        return {
            'success': False,
            'returncode': -1,
            'stdout': None,
            'stderr': f"Command not found: {command[0]}",
            'duration': 0,
            'command': ' '.join(command),
            'timeout': False
        }
        
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return {
            'success': False,
            'returncode': -1,
            'stdout': None,
            'stderr': str(e),
            'duration': time.time() - start_time,
            'command': ' '.join(command),
            'timeout': False
        }

def read_wordlist(wordlist_path: str, max_entries: int = None) -> List[str]:
    """
    Read wordlist file and return entries
    
    Args:
        wordlist_path (str): Path to wordlist file
        max_entries (int, optional): Maximum number of entries to read
        
    Returns:
        List[str]: Wordlist entries
    """
    try:
        wordlist_file = Path(wordlist_path)
        if not wordlist_file.exists():
            logger.error(f"Wordlist file not found: {wordlist_path}")
            return []
        
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            entries = [line.strip() for line in f if line.strip()]
        
        if max_entries and len(entries) > max_entries:
            entries = entries[:max_entries]
            logger.info(f"Limited wordlist to {max_entries} entries")
        
        logger.info(f"Loaded {len(entries)} entries from {wordlist_path}")
        return entries
        
    except Exception as e:
        logger.error(f"Error reading wordlist {wordlist_path}: {str(e)}")
        return []

def merge_wordlists(wordlist_paths: List[str], output_path: str = None, 
                   deduplicate: bool = True) -> List[str]:
    """
    Merge multiple wordlists into one
    
    Args:
        wordlist_paths (List[str]): List of wordlist file paths
        output_path (str, optional): Output file path
        deduplicate (bool): Remove duplicates
        
    Returns:
        List[str]: Merged wordlist entries
    """
    all_entries = []
    
    for wordlist_path in wordlist_paths:
        entries = read_wordlist(wordlist_path)
        all_entries.extend(entries)
    
    if deduplicate:
        # Preserve order while removing duplicates
        seen = set()
        unique_entries = []
        for entry in all_entries:
            if entry not in seen:
                seen.add(entry)
                unique_entries.append(entry)
        all_entries = unique_entries
    
    logger.info(f"Merged {len(all_entries)} unique entries from {len(wordlist_paths)} wordlists")
    
    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_entries))
            logger.info(f"Merged wordlist saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving merged wordlist: {str(e)}")
    
    return all_entries

def clean_temp_files(temp_directory: str, max_age_hours: int = 24) -> int:
    """
    Clean temporary files older than specified age
    
    Args:
        temp_directory (str): Temporary directory path
        max_age_hours (int): Maximum file age in hours
        
    Returns:
        int: Number of files cleaned
    """
    temp_dir = Path(temp_directory)
    if not temp_dir.exists():
        return 0
    
    current_time = time.time()
    max_age_seconds = max_age_hours * 3600
    cleaned_count = 0
    
    try:
        for file_path in temp_dir.rglob('*'):
            if file_path.is_file():
                file_age = current_time - file_path.stat().st_mtime
                if file_age > max_age_seconds:
                    try:
                        file_path.unlink()
                        cleaned_count += 1
                        logger.debug(f"Cleaned temp file: {file_path}")
                    except Exception as e:
                        logger.warning(f"Could not clean temp file {file_path}: {str(e)}")
        
        logger.info(f"Cleaned {cleaned_count} temporary files")
        return cleaned_count
        
    except Exception as e:
        logger.error(f"Error cleaning temp files: {str(e)}")
        return 0

def get_available_wordlists() -> Dict[str, List[str]]:
    """
    Discover available wordlists on the system
    
    Returns:
        Dict[str, List[str]]: Dictionary mapping categories to wordlist paths
    """
    wordlist_locations = [
        '/usr/share/wordlists',
        '/usr/share/dirbuster/wordlists',
        '/usr/share/dirb/wordlists',
        '/usr/share/seclists',
        '/opt/SecLists',
        str(Path.home() / 'wordlists'),
        'wordlists'
    ]
    
    wordlists = {
        'directories': [],
        'files': [],
        'subdomains': [],
        'usernames': [],
        'passwords': [],
        'dns': [],
        'fuzzing': [],
        'other': []
    }
    
    # Category patterns
    category_patterns = {
        'directories': ['dir', 'directory', 'common', 'big'],
        'files': ['file', 'extension', 'backup'],
        'subdomains': ['subdomain', 'dns', 'domain'],
        'usernames': ['user', 'username', 'name'],
        'passwords': ['password', 'pass', 'rockyou'],
        'dns': ['dns', 'resolver'],
        'fuzzing': ['fuzz', 'payload', 'xss', 'sqli']
    }
    
    for location in wordlist_locations:
        location_path = Path(location)
        if location_path.exists() and location_path.is_dir():
            for wordlist_file in location_path.rglob('*.txt'):
                filename_lower = wordlist_file.name.lower()
                categorized = False
                
                for category, patterns in category_patterns.items():
                    if any(pattern in filename_lower for pattern in patterns):
                        wordlists[category].append(str(wordlist_file))
                        categorized = True
                        break
                
                if not categorized:
                    wordlists['other'].append(str(wordlist_file))
    
    # Remove duplicates and sort
    for category in wordlists:
        wordlists[category] = sorted(list(set(wordlists[category])))
    
    total_wordlists = sum(len(paths) for paths in wordlists.values())
    logger.info(f"Found {total_wordlists} wordlists across {len(wordlist_locations)} locations")
    
    return wordlists

def create_scan_id() -> str:
    """
    Create unique scan ID based on timestamp and random string
    
    Returns:
        str: Unique scan ID
    """
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_suffix = generate_random_string(6)
    return f"scan_{timestamp}_{random_suffix}"

def parse_nmap_ports(port_string: str) -> str:
    """
    Parse and validate Nmap port specification
    
    Args:
        port_string (str): Port specification
        
    Returns:
        str: Validated port specification
    """
    if not port_string:
        return "1-65535"
    
    # Handle common port aliases
    port_aliases = {
        'top-ports': 'top-ports',
        'fast': '1-1000',
        'full': '1-65535',
        'web': '80,443,8080,8443,8000,8888',
        'common': '21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6379'
    }
    
    if port_string.lower() in port_aliases:
        return port_aliases[port_string.lower()]
    
    # Validate port specification format
    if re.match(r'^[\d,\-]+, port_string):
        return port_string
    
    logger.warning(f"Invalid port specification: {port_string}, using default")
    return "1-65535"

def estimate_scan_time(targets: List[str], ports: str, plugins: List[str]) -> Dict[str, Any]:
    """
    Estimate scan duration based on targets, ports, and plugins
    
    Args:
        targets (List[str]): List of targets
        ports (str): Port specification
        plugins (List[str]): List of plugins to run
        
    Returns:
        Dict[str, Any]: Time estimation details
    """
    # Base time estimates (in seconds)
    base_times = {
        'nmap_scan': 30,  # per target
        'web_scanner': 120,  # per web service
        'service_enum': 60,  # per service
        'vuln_scan': 180,  # per target
        'screenshot': 10   # per web service
    }
    
    # Port count estimation
    if 'top-ports' in ports:
        port_count = 1000
    elif '1-65535' in ports or 'full' in ports:
        port_count = 65535
    elif '1-1000' in ports:
        port_count = 1000
    else:
        # Count individual ports and ranges
        port_list = parse_port_range(ports)
        port_count = len(port_list)
    
    # Estimate total time
    target_count = len(targets)
    total_seconds = 0
    
    # Base scan time (increases with port count)
    port_multiplier = min(port_count / 1000, 10)  # Cap at 10x
    base_scan_time = base_times['nmap_scan'] * port_multiplier * target_count
    total_seconds += base_scan_time
    
    # Plugin time estimation
    for plugin in plugins:
        if plugin in base_times:
            total_seconds += base_times[plugin] * target_count
        else:
            total_seconds += 60 * target_count  # Default 1 minute per target
    
    # Add overhead (20%)
    total_seconds *= 1.2
    
    return {
        'estimated_seconds': int(total_seconds),
        'estimated_duration': format_duration(total_seconds),
        'target_count': target_count,
        'estimated_port_count': port_count,
        'plugin_count': len(plugins),
        'breakdown': {
            'base_scan': format_duration(base_scan_time),
            'plugins': format_duration(total_seconds - base_scan_time),
            'overhead': '20%'
        }
    }

def get_default_wordlists() -> Dict[str, str]:
    """
    Get default wordlist paths for different scan types
    
    Returns:
        Dict[str, str]: Default wordlist paths
    """
    # Try to find common wordlists
    possible_locations = [
        '/usr/share/wordlists',
        '/usr/share/dirbuster/wordlists',
        '/usr/share/dirb/wordlists',
        '/opt/SecLists'
    ]
    
    defaults = {
        'directories': None,
        'files': None,
        'subdomains': None,
        'usernames': None,
        'passwords': None
    }
    
    # Directory wordlists
    dir_wordlists = [
        'dirbuster/directory-list-2.3-medium.txt',
        'dirb/common.txt',
        'Discovery/Web-Content/common.txt',
        'common.txt'
    ]
    
    for location in possible_locations:
        for wordlist in dir_wordlists:
            full_path = Path(location) / wordlist
            if full_path.exists():
                defaults['directories'] = str(full_path)
                break
        if defaults['directories']:
            break
    
    # Similar logic for other wordlist types...
    # (Implementation shortened for brevity)
    
    return defaults

def print_scan_banner(scan_info: Dict[str, Any]) -> None:
    """
    Print formatted scan banner with information
    
    Args:
        scan_info (Dict[str, Any]): Scan information
    """
    from utils.banner import print_banner
    
    print_banner()
    
    print(f"\n{'='*60}")
    print(f"SCAN CONFIGURATION")
    print(f"{'='*60}")
    print(f"Scan ID: {scan_info.get('scan_id', 'unknown')}")
    print(f"Targets: {len(scan_info.get('targets', []))}")
    print(f"Plugins: {', '.join(scan_info.get('plugins', []))}")
    print(f"Estimated Duration: {scan_info.get('estimated_duration', 'unknown')}")
    print(f"Output Directory: {scan_info.get('output_dir', 'unknown')}")
    print(f"{'='*60}\n")

def load_scan_profile(profile_name: str, config_dir: str = "configs") -> Dict[str, Any]:
    """
    Load scan profile configuration
    
    Args:
        profile_name (str): Profile name
        config_dir (str): Configuration directory
        
    Returns:
        Dict[str, Any]: Profile configuration
    """
    import yaml
    
    profile_file = Path(config_dir) / f"{profile_name}.yaml"
    
    if not profile_file.exists():
        logger.warning(f"Profile file not found: {profile_file}")
        return {}
    
    try:
        with open(profile_file, 'r', encoding='utf-8') as f:
            profile_config = yaml.safe_load(f)
        
        logger.info(f"Loaded scan profile: {profile_name}")
        return profile_config
        
    except Exception as e:
        logger.error(f"Error loading profile {profile_name}: {str(e)}")
        return {}

def setup_logging(log_level: str = "INFO", log_file: str = None) -> logging.Logger:
    """
    Set up logging configuration
    
    Args:
        log_level (str): Logging level
        log_file (str, optional): Log file path
        
    Returns:
        logging.Logger: Configured logger
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not set up file logging: {e}")
    
    return root_logger