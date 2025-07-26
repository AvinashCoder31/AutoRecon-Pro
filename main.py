#!/usr/bin/env python3
"""
AutoRecon-Py Pro v2.0
Advanced Multi-Target Network Reconnaissance Framework

Author: Enhanced by AI Assistant
License: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import ipaddress
import concurrent.futures
from datetime import datetime
import signal
import yaml

# Core imports
from core.config import Config
from core.logger import Logger
from core.nmap_scanner import TargetManager
from core.plugin_manager import PluginManager
from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from core.pattern_matcher import PatternMatcher
from utils.banner import print_banner
from utils.helpers import validate_dependencies, setup_directories
from utils.network import NetworkUtils

class AutoReconPro:
    """
    Main AutoRecon-Py Pro application class
    """
    
    def __init__(self):
        self.config = None
        self.logger = None
        self.target_manager = None
        self.plugin_manager = None
        self.scanner_engine = None
        self.report_generator = None
        self.pattern_matcher = None
        self.start_time = time.time()
        self.interrupted = False
        
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.warning("Interrupt received. Gracefully shutting down...")
            self.interrupted = True
            if self.scanner_engine:
                self.scanner_engine.stop_all_scans()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="AutoRecon-Py Pro - Advanced Network Reconnaissance Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s 192.168.1.1                    # Single IP scan
  %(prog)s 192.168.1.0/24                 # CIDR range scan
  %(prog)s example.com subdomain.com      # Multiple domains
  %(prog)s -t targets.txt                 # Target file
  %(prog)s 10.0.0.1 --profile oscp        # OSCP exam profile
  %(prog)s 192.168.1.1 --plugins web,smb  # Specific plugins only
  %(prog)s example.com --quick --no-screenshots # Quick web scan
            """
        )
        
        # Target specification
        parser.add_argument('targets', nargs='*', 
                          help='IP addresses, CIDR ranges, or hostnames to scan')
        parser.add_argument('-t', '--target-file', 
                          help='File containing targets (one per line)')
        
        # Scanning options
        parser.add_argument('-p', '--ports', 
                          help='Port specification (e.g., 1-1000, 80,443, T:80,U:53)')
        parser.add_argument('--profile', choices=['quick', 'thorough', 'stealth', 'oscp', 'web-only'],
                          default='quick', help='Scanning profile to use')
        parser.add_argument('--plugins', 
                          help='Comma-separated list of plugins to run')
        parser.add_argument('--exclude-plugins',
                          help='Comma-separated list of plugins to exclude')
        
        # Performance options
        parser.add_argument('--max-targets', type=int, default=10,
                          help='Maximum concurrent targets to scan')
        parser.add_argument('--max-scans', type=int, default=50,
                          help='Maximum concurrent scans per target')
        parser.add_argument('--threads', type=int, default=20,
                          help='Number of threads for multi-threaded operations')
        parser.add_argument('--timeout', type=int, default=300,
                          help='Global timeout in seconds')
        
        # Output options
        parser.add_argument('-o', '--output', default='results',
                          help='Output directory for results')
        parser.add_argument('--format', choices=['json', 'xml', 'html', 'txt', 'all'],
                          default='all', help='Report format(s)')
        parser.add_argument('--no-color', action='store_true',
                          help='Disable colored output')
        
        # Feature toggles
        parser.add_argument('--quick', action='store_true',
                          help='Quick scan mode (faster, less comprehensive)')
        parser.add_argument('--no-ping', action='store_true',
                          help='Skip host discovery (assume hosts are up)')
        parser.add_argument('--no-screenshots', action='store_true',
                          help='Skip web screenshot capture')
        parser.add_argument('--no-bruteforce', action='store_true',
                          help='Skip brute force attacks')
        parser.add_argument('--aggressive', action='store_true',
                          help='Enable aggressive scanning (may be detected)')
        
        # Advanced options
        parser.add_argument('--wordlist-dir', 
                          help='Custom wordlist directory')
        parser.add_argument('--config', 
                          help='Custom configuration file')
        parser.add_argument('--resume', 
                          help='Resume from previous scan session')
        parser.add_argument('--user-agent', 
                          help='Custom User-Agent for web requests')
        parser.add_argument('--proxy', 
                          help='Proxy URL (http://proxy:port)')
        
        # Information options
        parser.add_argument('--list-plugins', action='store_true',
                          help='List available plugins and exit')
        parser.add_argument('--list-profiles', action='store_true',
                          help='List available profiles and exit')
        parser.add_argument('-v', '--verbose', action='count', default=0,
                          help='Increase verbosity (use -v, -vv, -vvv)')
        parser.add_argument('--version', action='version', version='AutoRecon-Py Pro v2.0')
        
        return parser.parse_args()
    
    def initialize_components(self, args):
        """Initialize all core components"""
        try:
            # Initialize configuration
            config_file = args.config or os.path.expanduser('~/.config/autorecon-pro/config.yaml')
            self.config = Config(config_file, args)
            
            # Initialize logger
            self.logger = Logger(
                level=args.verbose,
                output_dir=args.output,
                no_color=args.no_color
            )
            
            # Initialize other components
            self.target_manager = TargetManager(self.config, self.logger)
            self.plugin_manager = PluginManager(self.config, self.logger)
            self.scanner_engine = ScannerEngine(self.config, self.logger, self.plugin_manager)
            self.report_generator = ReportGenerator(self.config, self.logger)
            self.pattern_matcher = PatternMatcher(self.config, self.logger)
            
        except Exception as e:
            print(f"[!] Failed to initialize components: {e}")
            sys.exit(1)
    
    def validate_environment(self):
        """Validate system dependencies and environment"""
        self.logger.info("Validating system dependencies...")
        
        missing_deps = validate_dependencies()
        if missing_deps:
            self.logger.error(f"Missing dependencies: {', '.join(missing_deps)}")
            self.logger.info("Please install missing dependencies and try again")
            return False
        
        # Check permissions
        if os.geteuid() != 0:
            self.logger.warning("Running without root privileges. Some scans may be limited.")
        
        return True
    
    def list_information(self, args):
        """Handle information listing requests"""
        if args.list_plugins:
            print("\n=== Available Plugins ===")
            plugins = self.plugin_manager.get_available_plugins()
            for category, plugin_list in plugins.items():
                print(f"\n{category.upper()}:")
                for plugin in plugin_list:
                    print(f"  {plugin['name']} - {plugin['description']}")
            return True
            
        if args.list_profiles:
            print("\n=== Available Profiles ===")
            profiles = self.config.get_profiles()
            for name, profile in profiles.items():
                print(f"\n{name}: {profile['description']}")
                print(f"  Plugins: {', '.join(profile['plugins'])}")
            return True
            
        return False
    
    async def run_reconnaissance(self, targets: List[str]):
        """Main reconnaissance execution"""
        self.logger.info(f"Starting reconnaissance on {len(targets)} target(s)")
        
        # Create semaphore for concurrent target limiting
        target_semaphore = asyncio.Semaphore(self.config.max_targets)
        
        # Process targets concurrently
        tasks = []
        for target in targets:
            task = asyncio.create_task(
                self.process_single_target(target, target_semaphore)
            )
            tasks.append(task)
        
        # Wait for all targets to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_scans = []
        failed_scans = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed_scans.append((targets[i], str(result)))
            else:
                successful_scans.append((targets[i], result))
        
        return successful_scans, failed_scans
    
    async def process_single_target(self, target: str, semaphore: asyncio.Semaphore):
        """Process a single target"""
        async with semaphore:
            try:
                self.logger.info(f"Processing target: {target}")
                
                # Prepare target
                target_info = await self.target_manager.prepare_target(target)
                if not target_info:
                    raise Exception(f"Failed to prepare target: {target}")
                
                # Create output directory
                output_dir = setup_directories(target, self.config.output_dir)
                target_info['output_dir'] = output_dir
                
                # Run scans
                scan_results = await self.scanner_engine.scan_target(target_info)
                
                # Process patterns
                patterns = self.pattern_matcher.analyze_results(scan_results)
                
                # Generate reports
                await self.report_generator.generate_reports(
                    target_info, scan_results, patterns, output_dir
                )
                
                self.logger.success(f"Completed reconnaissance for: {target}")
                return scan_results
                
            except Exception as e:
                self.logger.error(f"Failed to process target {target}: {e}")
                raise
    
    def print_summary(self, successful_scans, failed_scans, elapsed_time):
        """Print final summary"""
        print("\n" + "="*80)
        print("RECONNAISSANCE SUMMARY")
        print("="*80)
        
        print(f"Total targets processed: {len(successful_scans) + len(failed_scans)}")
        print(f"Successful scans: {len(successful_scans)}")
        print(f"Failed scans: {len(failed_scans)}")
        print(f"Total execution time: {elapsed_time:.2f} seconds")
        
        if failed_scans:
            print(f"\nFailed targets:")
            for target, error in failed_scans:
                print(f"  {target}: {error}")
        
        print(f"\nResults saved to: {self.config.output_dir}")
        print("="*80)
    
    async def main(self):
        """Main application entry point"""
        try:
            # Parse arguments
            args = self.parse_arguments()
            
            # Print banner
            print_banner()
            
            # Setup signal handlers
            self.setup_signal_handlers()
            
            # Initialize components
            self.initialize_components(args)
            
            # Handle information requests
            if self.list_information(args):
                return
            
            # Validate environment
            if not self.validate_environment():
                return
            
            # Prepare targets
            targets = []
            
            # Add command line targets
            if args.targets:
                targets.extend(args.targets)
            
            # Add targets from file
            if args.target_file:
                file_targets = self.target_manager.load_targets_from_file(args.target_file)
                targets.extend(file_targets)
            
            if not targets:
                self.logger.error("No targets specified. Use --help for usage information.")
                return
            
            # Expand targets (handle CIDR, etc.)
            expanded_targets = self.target_manager.expand_targets(targets)
            
            self.logger.info(f"Loaded {len(expanded_targets)} target(s) for reconnaissance")
            
            # Run reconnaissance
            successful_scans, failed_scans = await self.run_reconnaissance(expanded_targets)
            
            # Calculate elapsed time
            elapsed_time = time.time() - self.start_time
            
            # Print summary
            self.print_summary(successful_scans, failed_scans, elapsed_time)
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            if args.verbose >= 2:
                import traceback
                traceback.print_exc()
            sys.exit(1)

def main():
    """Entry point"""
    app = AutoReconPro()
    asyncio.run(app.main())

if __name__ == "__main__":
    main()