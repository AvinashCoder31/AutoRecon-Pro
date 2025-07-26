#!/usr/bin/env python3
"""
AutoRecon-Pro v2.0 - Advanced Network Reconnaissance Framework
Main entry point for the application
"""

import sys
import os
import asyncio
import argparse
import time
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Core imports
from core.config import Config
from core.logger import Logger
  # Fixed import path
from core.plugin_manager import PluginManager
from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from core.pattern_matcher import PatternMatcher
from utils.banner import print_banner
from utils.helpers import validate_dependencies, setup_directories
from utils.network import NetworkUtils

def parse_arguments():
    """
    Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='AutoRecon-Pro v2.0 - Advanced Network Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100                    # Single IP scan
  %(prog)s example.com                      # Domain scan  
  %(prog)s 192.168.1.0/24                   # CIDR range scan
  %(prog)s -p 80,443,8080 example.com       # Custom ports
  %(prog)s --profile quick example.com      # Quick scan profile
  %(prog)s --plugins web_scanner example.com # Specific plugin
        """
    )
    
    # Target arguments
    parser.add_argument(
        'targets',
        nargs='+',
        help='Target IP addresses, domains, or CIDR ranges'
    )
    
    # Scan options
    parser.add_argument(
        '-p', '--ports',
        default='1-65535',
        help='Port specification (default: 1-65535)'
    )
    
    parser.add_argument(
        '-P', '--profile',
        choices=['quick', 'thorough', 'web-only', 'oscp', 'stealth', 'corporate', 'bounty'],
        default='thorough',
        help='Scanning profile (default: thorough)'
    )
    
    parser.add_argument(
        '--plugins',
        help='Comma-separated list of plugins to run'
    )
    
    parser.add_argument(
        '--exclude-plugins',
        help='Comma-separated list of plugins to exclude'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    
    parser.add_argument(
        '-T', '--timing',
        choices=['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
        default='T3',
        help='Nmap timing template (default: T3)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Command timeout in seconds (default: 300)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output-dir',
        default='results',
        help='Output directory (default: results)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['html', 'json', 'xml', 'pdf', 'txt'],
        nargs='+',
        default=['html', 'json'],
        help='Report format(s) (default: html json)'
    )
    
    # Feature flags
    parser.add_argument(
        '--screenshots',
        action='store_true',
        help='Capture web page screenshots'
    )
    
    parser.add_argument(
        '--manual-commands',
        action='store_true',
        help='Generate manual testing commands'
    )
    
    parser.add_argument(
        '--resume',
        help='Resume interrupted scan by scan ID'
    )
    
    # Configuration
    parser.add_argument(
        '--config',
        help='Custom configuration file'
    )
    
    parser.add_argument(
        '--wordlist',
        help='Custom wordlist file'
    )
    
    # Network options
    parser.add_argument(
        '--proxy',
        help='HTTP/SOCKS proxy (http://proxy:8080)'
    )
    
    parser.add_argument(
        '--user-agent',
        default='Mozilla/5.0 (compatible; AutoRecon-Pro)',
        help='Custom User-Agent string'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=0,
        help='Delay between requests in seconds'
    )
    
    parser.add_argument(
        '--rate-limit',
        type=int,
        help='Rate limit (requests per second)'
    )
    
    # Logging options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Debug mode'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode'
    )
    
    # Version
    parser.add_argument(
        '--version',
        action='version',
        version='AutoRecon-Pro v2.0.0'
    )
    
    return parser.parse_args()

async def main():
    """
    Main application entry point
    """
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Print banner
        print_banner()
        
        # Set up logging
        log_level = 'DEBUG' if args.debug else 'INFO' if args.verbose else 'WARNING' if args.quiet else 'INFO'
        logger = Logger(level=log_level, log_file=f"{args.output_dir}/logs/autorecon.log")
        
        # Load configuration
        config = Config(config_file=args.config)
        
        # Set up directories
        directories = setup_directories(args.output_dir)
        logger.info(f"Output directories created: {directories['base']}")
        
        # Validate dependencies
        logger.info("Validating system dependencies...")
        deps = validate_dependencies()
        missing_deps = [dep for dep, available in deps.items() if not available and not dep.endswith('_optional')]
        
        if missing_deps:
            logger.error(f"Missing required dependencies: {', '.join(missing_deps)}")
            logger.error("Please install missing dependencies and try again")
            sys.exit(1)
        
        logger.info("✓ All required dependencies are available")
        
        # Initialize core components
        network_utils = NetworkUtils()
        target_manager = TargetManager()
        plugin_manager = PluginManager()
        pattern_matcher = PatternMatcher()
        report_generator = ReportGenerator(args.output_dir)
        
        # Process targets
        logger.info(f"Processing {len(args.targets)} targets...")
        processed_targets = []
        
        for target in args.targets:
            # Validate and expand targets
            from utils.helpers import validate_target
            is_valid, target_type, normalized_target = validate_target(target)
            
            if not is_valid:
                logger.warning(f"Invalid target: {target}")
                continue
            
            if target_type == 'cidr':
                # Expand CIDR range
                expanded_targets = network_utils.expand_cidr(normalized_target)
                processed_targets.extend(expanded_targets)
                logger.info(f"Expanded CIDR {normalized_target} to {len(expanded_targets)} targets")
            else:
                processed_targets.append(normalized_target)
        
        if not processed_targets:
            logger.error("No valid targets provided")
            sys.exit(1)
        
        logger.info(f"Total targets to scan: {len(processed_targets)}")
        
        # Host discovery (if more than 1 target)
        if len(processed_targets) > 1:
            logger.info("Performing host discovery...")
            alive_hosts = network_utils.discover_live_hosts(processed_targets, method='ping')
            live_targets = [host for host, alive in alive_hosts.items() if alive]
            
            if not live_targets:
                logger.warning("No live hosts found")
                live_targets = processed_targets  # Continue with all targets anyway
            else:
                logger.info(f"Found {len(live_targets)} live hosts")
                processed_targets = live_targets
        
        # Initialize scanner engine
        scanner_engine = ScannerEngine(
            config=config,
            plugin_manager=plugin_manager,
            report_generator=report_generator,
            pattern_matcher=pattern_matcher
        )
        
        # Configure scan options
        scan_options = {
            'ports': args.ports,
            'profile': args.profile,
            'threads': args.threads,
            'timing': args.timing,
            'timeout': args.timeout,
            'screenshots': args.screenshots,
            'manual_commands': args.manual_commands,
            'wordlist': args.wordlist,
            'proxy': args.proxy,
            'user_agent': args.user_agent,
            'delay': args.delay,
            'rate_limit': args.rate_limit,
            'output_dir': args.output_dir,
            'report_formats': args.format
        }
        
        # Set up plugins
        if args.plugins:
            enabled_plugins = [p.strip() for p in args.plugins.split(',')]
            plugin_manager.set_enabled_plugins(enabled_plugins)
        
        if args.exclude_plugins:
            excluded_plugins = [p.strip() for p in args.exclude_plugins.split(',')]
            plugin_manager.set_disabled_plugins(excluded_plugins)
        
        # Load plugins
        plugin_manager.load_plugins()
        available_plugins = plugin_manager.get_available_plugins()
        logger.info(f"Loaded {len(available_plugins)} plugins: {', '.join(available_plugins)}")
        
        # Generate scan ID
        from utils.helpers import create_scan_id
        scan_id = create_scan_id()
        
        # Estimate scan time
        from utils.helpers import estimate_scan_time
        enabled_plugins = plugin_manager.get_enabled_plugins()
        time_estimate = estimate_scan_time(processed_targets, args.ports, enabled_plugins)
        
        # Print scan information
        scan_info = {
            'scan_id': scan_id,
            'targets': processed_targets,
            'plugins': enabled_plugins,
            'estimated_duration': time_estimate['estimated_duration'],
            'output_dir': args.output_dir
        }
        
        from utils.helpers import print_scan_banner
        print_scan_banner(scan_info)
        
        # Set scan metadata
        scan_metadata = {
            'scan_id': scan_id,
            'start_time': time.time(),
            'targets': processed_targets,
            'plugins_used': enabled_plugins,
            'version': '2.0.0',
            'command_line': ' '.join(sys.argv)
        }
        
        report_generator.set_scan_metadata(scan_metadata)
        
        # Execute scan
        logger.info("Starting reconnaissance scan...")
        start_time = time.time()
        
        try:
            # Run the main scan
            scan_results = await scanner_engine.scan_targets(
                targets=processed_targets,
                options=scan_options
            )
            
            # Calculate total duration
            end_time = time.time()
            total_duration = end_time - start_time
            
            # Update metadata with end time
            scan_metadata['end_time'] = end_time
            scan_metadata['total_duration'] = total_duration
            report_generator.set_scan_metadata(scan_metadata)
            
            logger.info(f"Scan completed in {total_duration:.2f} seconds")
            
            # Process results with pattern matcher
            logger.info("Analyzing results for patterns...")
            for target, target_results in scan_results.items():
                for plugin, plugin_results in target_results.items():
                    if 'output' in plugin_results:
                        # Analyze plugin output for patterns
                        pattern_analysis = pattern_matcher.analyze_text(
                            plugin_results['output'], 
                            target
                        )
                        
                        # Add pattern analysis to results
                        plugin_results['pattern_analysis'] = pattern_analysis
                        
                        # Generate risk score
                        risk_score = pattern_matcher.generate_risk_score(pattern_analysis)
                        plugin_results['risk_score'] = risk_score
            
            # Generate reports
            logger.info("Generating reports...")
            generated_reports = {}
            
            for report_format in args.format:
                try:
                    if report_format == 'html':
                        report_path = report_generator.generate_html_report()
                    elif report_format == 'json':
                        report_path = report_generator.generate_json_report()
                    elif report_format == 'xml':
                        report_path = report_generator.generate_xml_report()
                    elif report_format == 'txt':
                        report_path = report_generator.generate_txt_report()
                    else:
                        logger.warning(f"Unsupported report format: {report_format}")
                        continue
                    
                    generated_reports[report_format] = report_path
                    logger.info(f"✓ {report_format.upper()} report: {report_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to generate {report_format} report: {str(e)}")
            
            # Print summary
            print(f"\n{'='*60}")
            print("SCAN SUMMARY")
            print(f"{'='*60}")
            print(f"Scan ID: {scan_id}")
            print(f"Targets Scanned: {len(processed_targets)}")
            print(f"Plugins Executed: {len(enabled_plugins)}")
            print(f"Total Duration: {total_duration:.2f} seconds")
            print(f"Output Directory: {args.output_dir}")
            print(f"\nGenerated Reports:")
            for fmt, path in generated_reports.items():
                print(f"  {fmt.upper()}: {path}")
            print(f"{'='*60}")
            
            # Calculate overall statistics
            total_findings = 0
            critical_findings = 0
            high_findings = 0
            
            for target_results in scan_results.values():
                for plugin_results in target_results.values():
                    if 'pattern_analysis' in plugin_results:
                        analysis = plugin_results['pattern_analysis']
                        for category in ['vulnerabilities', 'credentials']:
                            findings = analysis.get(category, [])
                            total_findings += len(findings)
                            for finding in findings:
                                if finding.get('severity') == 'critical':
                                    critical_findings += 1
                                elif finding.get('severity') == 'high':
                                    high_findings += 1
            
            print(f"\nFindings Summary:")
            print(f"  Total Findings: {total_findings}")
            print(f"  Critical: {critical_findings}")
            print(f"  High: {high_findings}")
            
            # Success exit
            logger.info("AutoRecon-Pro scan completed successfully")
            return 0
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            print("\n⚠️  Scan interrupted by user")
            return 130
        
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            print(f"\n❌ Scan failed: {str(e)}")
            return 1
    
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1

def run_autorecon():
    """
    Entry point wrapper for the application
    """
    try:
        # Check Python version
        if sys.version_info < (3, 7):
            print("❌ AutoRecon-Pro requires Python 3.7 or higher")
            sys.exit(1)
        
        # Run the main application
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️  Application interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    run_autorecon()