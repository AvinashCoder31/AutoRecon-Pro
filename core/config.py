#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Configuration Management
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import ipaddress

class Config:
    """Configuration management class"""
    
    def __init__(self, config_file: str, args: Any):
        self.config_file = config_file
        self.args = args
        self.config_data = {}
        self.load_config()
        self.merge_args()
        
    def load_config(self):
        """Load configuration from file"""
        default_config = self.get_default_config()
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = yaml.safe_load(f) or {}
                self.config_data = self.merge_configs(default_config, user_config)
            except Exception as e:
                print(f"Warning: Failed to load config file {self.config_file}: {e}")
                self.config_data = default_config
        else:
            self.config_data = default_config
            self.create_default_config()
    
    def merge_args(self):
        """Merge command line arguments with config"""
        # Override config with command line args
        if self.args.ports:
            self.config_data['scanning']['ports'] = self.args.ports
        if self.args.threads:
            self.config_data['performance']['threads'] = self.args.threads
        if self.args.timeout:
            self.config_data['performance']['timeout'] = self.args.timeout
        if self.args.max_targets:
            self.config_data['performance']['max_targets'] = self.args.max_targets
        if self.args.max_scans:
            self.config_data['performance']['max_scans'] = self.args.max_scans
        if self.args.output:
            self.config_data['output']['directory'] = self.args.output
        if self.args.wordlist_dir:
            self.config_data['wordlists']['directory'] = self.args.wordlist_dir
        if self.args.proxy:
            self.config_data['network']['proxy'] = self.args.proxy
        if self.args.user_agent:
            self.config_data['network']['user_agent'] = self.args.user_agent
        
        # Set profile-specific settings
        if self.args.profile:
            self.apply_profile(self.args.profile)
        
        # Feature toggles
        self.config_data['features']['screenshots'] = not self.args.no_screenshots
        self.config_data['features']['bruteforce'] = not self.args.no_bruteforce
        self.config_data['features']['ping_scan'] = not self.args.no_ping
        self.config_data['features']['aggressive'] = self.args.aggressive
        self.config_data['features']['quick_mode'] = self.args.quick
    
    def apply_profile(self, profile_name: str):
        """Apply scanning profile"""
        profiles = self.get_profiles()
        if profile_name in profiles:
            profile = profiles[profile_name]
            
            # Apply profile settings
            for key, value in profile.get('settings', {}).items():
                if '.' in key:
                    section, option = key.split('.', 1)
                    if section not in self.config_data:
                        self.config_data[section] = {}
                    self.config_data[section][option] = value
                else:
                    self.config_data[key] = value
    
    def get_profiles(self) -> Dict[str, Dict]:
        """Get available scanning profiles"""
        return {
            'quick': {
                'description': 'Quick scan with top ports only',
                'plugins': ['port_scan', 'service_detection', 'web_enum'],
                'settings': {
                    'scanning.ports': '1-1000',
                    'performance.threads': 50,
                    'features.screenshots': True,
                    'features.bruteforce': False
                }
            },
            'thorough': {
                'description': 'Comprehensive scan of all ports and services',
                'plugins': ['port_scan', 'service_detection', 'web_enum', 'smb_enum', 
                          'dns_enum', 'ftp_enum', 'ssh_enum', 'vuln_scan'],
                'settings': {
                    'scanning.ports': '1-65535',
                    'scanning.udp_ports': 'top-1000',
                    'performance.threads': 20,
                    'features.screenshots': True,
                    'features.bruteforce': True
                }
            },
            'stealth': {
                'description': 'Stealthy scan to avoid detection',
                'plugins': ['port_scan', 'service_detection', 'web_enum'],
                'settings': {
                    'scanning.timing': 'sneaky',
                    'scanning.fragment_packets': True,
                    'performance.threads': 5,
                    'features.aggressive': False
                }
            },
            'oscp': {
                'description': 'OSCP exam compliant scanning',
                'plugins': ['port_scan', 'service_detection', 'web_enum', 'smb_enum', 
                          'dns_enum', 'ftp_enum', 'ssh_enum'],
                'settings': {
                    'scanning.ports': '1-65535',
                    'features.screenshots': True,
                    'features.bruteforce': False,
                    'features.exploits': False
                }
            },
            'web-only': {
                'description': 'Web application focused scanning',
                'plugins': ['subdomain_enum', 'web_enum', 'web_screenshot', 'tech_detect'],
                'settings': {
                    'scanning.ports': '80,443,8080,8443,3000,5000,8000,9000',
                    'features.screenshots': True,
                    'features.bruteforce': True
                }
            }
        }
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'version': '2.0',
            'scanning': {
                'ports': '1-1000',
                'udp_ports': 'top-100',
                'timing': 'normal',
                'fragment_packets': False,
                'scan_delay': 0,
                'max_retries': 3
            },
            'performance': {
                'max_targets': 10,
                'max_scans': 50,
                'threads': 20,
                'timeout': 300,
                'scan_timeout': 600,
                'memory_limit': '2GB'
            },
            'network': {
                'proxy': None,
                'user_agent': 'AutoRecon-Pro/2.0',
                'max_redirects': 5,
                'verify_ssl': False,
                'connect_timeout': 10,
                'read_timeout': 30
            },
            'features': {
                'screenshots': True,
                'bruteforce': True,
                'ping_scan': True,
                'service_detection': True,
                'vulnerability_scan': True,
                'exploits': False,
                'aggressive': False,
                'quick_mode': False
            },
            'output': {
                'directory': 'results',
                'formats': ['json', 'txt', 'html'],
                'compression': True,
                'cleanup_empty': True
            },
            'wordlists': {
                'directory': '/usr/share/wordlists',
                'subdomain_list': 'subdomains-top1million-110000.txt',
                'directory_list': 'directory-list-2.3-medium.txt',
                'username_list': 'usernames.txt',
                'password_list': 'passwords.txt'
            },
            'tools': {
                'nmap': {
                    'path': 'nmap',
                    'extra_args': '-sV -sC --version-intensity 5'
                },
                'masscan': {
                    'path': 'masscan',
                    'rate': 1000
                },
                'gobuster': {
                    'path': 'gobuster',
                    'threads': 50,
                    'extensions': 'php,html,txt,js,css,xml,json'
                },
                'nikto': {
                    'path': 'nikto',
                    'timeout': 600
                },
                'whatweb': {
                    'path': 'whatweb',
                    'aggression': 3
                },
                'subfinder': {
                    'path': 'subfinder',
                    'threads': 100
                },
                'httpx': {
                    'path': 'httpx',
                    'threads': 50
                }
            },
            'patterns': {
                'credentials': [
                    r'(?i)(password|passwd|pwd)\s*[:=]\s*([^\s\n]+)',
                    r'(?i)(username|user|login)\s*[:=]\s*([^\s\n]+)',
                    r'(?i)(api[_-]?key|token)\s*[:=]\s*([^\s\n]+)'
                ],
                'vulnerabilities': [
                    r'(?i)(sql\s+injection|sqli)',
                    r'(?i)(cross[_-]?site\s+scripting|xss)',
                    r'(?i)(command\s+injection|rce)',
                    r'(?i)(directory\s+traversal|path\s+traversal)'
                ],
                'interesting_files': [
                    r'(?i)(\.git|\.svn|\.env|\.config)',
                    r'(?i)(backup|\.bak|\.old|\.tmp)',
                    r'(?i)(admin|panel|dashboard|login)'
                ]
            },
            'plugins': {
                'enabled': ['all'],
                'disabled': [],
                'custom_path': None,
                'timeout': 300
            },
            'logging': {
                'level': 'INFO',
                'file': 'autorecon.log',
                'max_size': '100MB',
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        }
    
    def create_default_config(self):
        """Create default configuration file"""
        try:
            config_dir = os.path.dirname(self.config_file)
            os.makedirs(config_dir, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Warning: Could not create config file: {e}")
    
    def merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Recursively merge configuration dictionaries"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key: str, default=None):
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    @property
    def output_dir(self) -> str:
        return self.get('output.directory', 'results')
    
    @property
    def max_targets(self) -> int:
        return self.get('performance.max_targets', 10)
    
    @property
    def max_scans(self) -> int:
        return self.get('performance.max_scans', 50)
    
    @property
    def threads(self) -> int:
        return self.get('performance.threads', 20)
    
    @property
    def timeout(self) -> int:
        return self.get('performance.timeout', 300)
    
    @property
    def ports(self) -> str:
        return self.get('scanning.ports', '1-1000')
    
    @property
    def wordlist_dir(self) -> str:
        return self.get('wordlists.directory', '/usr/share/wordlists')
    
    def save(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config file: {e}")