#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Advanced Logging System
"""

import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import colorama
from colorama import Fore, Back, Style

# Initialize colorama
colorama.init()

class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'SUCCESS': Fore.GREEN + Style.BRIGHT,
    }
    
    def __init__(self, fmt=None, datefmt=None, no_color=False):
        super().__init__(fmt, datefmt)
        self.no_color = no_color
    
    def format(self, record):
        if not self.no_color and record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

class Logger:
    """Advanced logging system for AutoRecon-Py Pro"""
    
    def __init__(self, level: int = 0, output_dir: str = None, no_color: bool = False):
        self.verbosity = level
        self.output_dir = output_dir
        self.no_color = no_color
        self.setup_logging()
        
        # Add success level
        logging.addLevelName(25, 'SUCCESS')
        self.logger = logging.getLogger('AutoRecon-Pro')
    
    def setup_logging(self):
        """Setup logging configuration"""
        # Determine log level based on verbosity
        if self.verbosity == 0:
            level = logging.WARNING
        elif self.verbosity == 1:
            level = logging.INFO
        elif self.verbosity == 2:
            level = logging.DEBUG
        else:  # verbosity >= 3
            level = logging.DEBUG
        
        # Create logger
        logger = logging.getLogger('AutoRecon-Pro')
        logger.setLevel(level)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_format = ColoredFormatter(
            fmt='[%(asctime)s] %(levelname)s - %(message)s',
            datefmt='%H:%M:%S',
            no_color=self.no_color
        )
        console_handler.setFormatter(console_format)
        console_handler.setLevel(level)
        logger.addHandler(console_handler)
        
        # File handler (if output directory specified)
        if self.output_dir:
            try:
                os.makedirs(self.output_dir, exist_ok=True)
                log_file = os.path.join(self.output_dir, 'autorecon.log')
                
                file_handler = logging.FileHandler(log_file)
                file_format = logging.Formatter(
                    fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(file_format)
                file_handler.setLevel(logging.DEBUG)  # Always log everything to file
                logger.addHandler(file_handler)
                
            except Exception as e:
                print(f"Warning: Could not setup file logging: {e}")
    
    def _log_with_prefix(self, level, message, prefix="", color=""):
        """Log message with custom prefix and color"""
        if not self.no_color and color:
            formatted_message = f"{color}{prefix}{message}{Style.RESET_ALL}"
        else:
            formatted_message = f"{prefix}{message}"
        
        self.logger.log(level, formatted_message)
    
    def debug(self, message: str):
        """Log debug message"""
        self._log_with_prefix(logging.DEBUG, message, "[DEBUG] ", Fore.CYAN)
    
    def info(self, message: str):
        """Log info message"""
        self._log_with_prefix(logging.INFO, message, "[*] ", Fore.BLUE)
    
    def success(self, message: str):
        """Log success message"""
        self._log_with_prefix(25, message, "[+] ", Fore.GREEN + Style.BRIGHT)
    
    def warning(self, message: str):
        """Log warning message"""
        self._log_with_prefix(logging.WARNING, message, "[!] ", Fore.YELLOW)
    
    def error(self, message: str):
        """Log error message"""
        self._log_with_prefix(logging.ERROR, message, "[-] ", Fore.RED)
    
    def critical(self, message: str):
        """Log critical message"""
        self._log_with_prefix(logging.CRITICAL, message, "[CRITICAL] ", Fore.RED + Style.BRIGHT)
    
    def scan_start(self, target: str, scan_type: str):
        """Log scan start"""
        message = f"Starting {scan_type} scan for {target}"
        self._log_with_prefix(logging.INFO, message, "[SCAN] ", Fore.MAGENTA)
    
    def scan_complete(self, target: str, scan_type: str, duration: float):
        """Log scan completion"""
        message = f"Completed {scan_type} scan for {target} in {duration:.2f}s"
        self._log_with_prefix(25, message, "[SCAN] ", Fore.GREEN)
    
    def scan_error(self, target: str, scan_type: str, error: str):
        """Log scan error"""
        message = f"Failed {scan_type} scan for {target}: {error}"
        self._log_with_prefix(logging.ERROR, message, "[SCAN] ", Fore.RED)
    
    def plugin_start(self, plugin_name: str, target: str):
        """Log plugin start"""
        message = f"Running plugin '{plugin_name}' on {target}"
        self._log_with_prefix(logging.INFO, message, "[PLUGIN] ", Fore.CYAN)
    
    def plugin_complete(self, plugin_name: str, target: str, results_count: int):
        """Log plugin completion"""
        message = f"Plugin '{plugin_name}' completed for {target} ({results_count} results)"
        self._log_with_prefix(25, message, "[PLUGIN] ", Fore.GREEN)
    
    def finding(self, finding_type: str, target: str, details: str):
        """Log security finding"""
        message = f"{finding_type} found on {target}: {details}"
        self._log_with_prefix(logging.WARNING, message, "[FINDING] ", Fore.YELLOW + Style.BRIGHT)
    
    def vulnerability(self, vuln_type: str, target: str, severity: str, details: str):
        """Log vulnerability"""
        color = Fore.RED + Style.BRIGHT if severity.upper() in ['HIGH', 'CRITICAL'] else Fore.YELLOW
        message = f"{severity.upper()} {vuln_type} on {target}: {details}"
        self._log_with_prefix(logging.WARNING, message, "[VULN] ", color)
    
    def credential(self, service: str, target: str, username: str, password: str = None):
        """Log credential finding"""
        if password:
            message = f"Credential found for {service} on {target}: {username}:{password}"
        else:
            message = f"Username found for {service} on {target}: {username}"
        self._log_with_prefix(logging.WARNING, message, "[CRED] ", Fore.YELLOW + Style.BRIGHT)
    
    def progress(self, current: int, total: int, operation: str):
        """Log progress information"""
        percentage = (current / total) * 100
        message = f"{operation}: {current}/{total} ({percentage:.1f}%)"
        self._log_with_prefix(logging.INFO, message, "[PROGRESS] ", Fore.BLUE)
    
    def command_executed(self, command: str, exit_code: int, duration: float):
        """Log executed command"""
        if self.verbosity >= 2:  # Only show commands in verbose mode
            status = "SUCCESS" if exit_code == 0 else "FAILED"
            color = Fore.GREEN if exit_code == 0 else Fore.RED
            message = f"Command {status} ({duration:.2f}s): {command}"
            self._log_with_prefix(logging.DEBUG, message, "[CMD] ", color)
    
    def pattern_match(self, pattern_type: str, target: str, match: str):
        """Log pattern match"""
        message = f"{pattern_type} pattern matched on {target}: {match}"
        self._log_with_prefix(logging.INFO, message, "[PATTERN] ", Fore.MAGENTA)
    
    def rate_limit(self, service: str, delay: int):
        """Log rate limiting"""
        message = f"Rate limiting {service} requests (delay: {delay}s)"
        self._log_with_prefix(logging.WARNING, message, "[RATE] ", Fore.YELLOW)
    
    def report_generated(self, report_type: str, file_path: str):
        """Log report generation"""
        message = f"{report_type} report generated: {file_path}"
        self._log_with_prefix(25, message, "[REPORT] ", Fore.GREEN)
    
    def target_summary(self, target: str, ports_found: int, services_found: int, 
                      vulnerabilities_found: int, duration: float):
        """Log target scanning summary"""
        message = (f"Target {target} summary: {ports_found} ports, "
                  f"{services_found} services, {vulnerabilities_found} vulnerabilities "
                  f"(scanned in {duration:.2f}s)")
        self._log_with_prefix(25, message, "[SUMMARY] ", Fore.GREEN + Style.BRIGHT)
    
    def banner(self, text: str):
        """Log banner text"""
        if not self.no_color:
            print(f"{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
        else:
            print(text)
    
    def separator(self, char="=", length=80):
        """Print separator line"""
        separator = char * length
        if not self.no_color:
            print(f"{Fore.BLUE}{separator}{Style.RESET_ALL}")
        else:
            print(separator)
    
    def table_header(self, headers: list):
        """Print table header"""
        header_str = " | ".join(f"{h:^15}" for h in headers)
        separator_str = "-" * len(header_str)
        
        if not self.no_color:
            print(f"{Fore.CYAN + Style.BRIGHT}{header_str}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{separator_str}{Style.RESET_ALL}")
        else:
            print(header_str)
            print(separator_str)
    
    def table_row(self, values: list):
        """Print table row"""
        row_str = " | ".join(f"{str(v):^15}" for v in values)
        print(row_str)
    
    def status_update(self, status: str, details: str = ""):
        """Print status update"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if details:
            message = f"[{timestamp}] {status}: {details}"
        else:
            message = f"[{timestamp}] {status}"
        
        if not self.no_color:
            print(f"{Fore.BLUE}{message}{Style.RESET_ALL}")
        else:
            print(message)
    
    def interactive_prompt(self, message: str, default: str = None) -> str:
        """Display interactive prompt"""
        if default:
            prompt = f"{message} [{default}]: "
        else:
            prompt = f"{message}: "
        
        if not self.no_color:
            prompt = f"{Fore.YELLOW}{prompt}{Style.RESET_ALL}"
        
        try:
            response = input(prompt).strip()
            return response if response else default
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return None
    
    def close(self):
        """Close all log handlers"""
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)