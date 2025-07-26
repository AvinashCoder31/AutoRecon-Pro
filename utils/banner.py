#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Banner and Branding Utilities
"""

import random
from colorama import Fore, Style, init

# Initialize colorama
init()

def print_banner():
    """Print the main application banner"""
    banners = [
        get_banner_1(),
        get_banner_2(),
        get_banner_3()
    ]
    
    # Select random banner
    banner = random.choice(banners)
    print(banner)
    
    # Print info
    print_info()

def get_banner_1():
    """ASCII Art Banner 1"""
    return f"""{Fore.CYAN}{Style.BRIGHT}
    ██████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
   ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
   ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
{Style.RESET_ALL}"""

def get_banner_2():
    """ASCII Art Banner 2"""
    return f"""{Fore.RED}{Style.BRIGHT}
    ▄▄▄       █    ██ ▄▄▄█████▓ ▒█████   ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █     ██▓███   ██▀███   ▒█████  
   ▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █    ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒
   ▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒   ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒
   ░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒   ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░
    ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░
    ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒    ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ 
     ▒   ▒▒ ░░░▒░ ░ ░     ░      ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ 
     ░   ▒    ░░░ ░ ░   ░      ░ ░ ░ ▒    ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░    ░░         ░░   ░ ░ ░ ░ ▒  
         ░  ░   ░                  ░ ░     ░        ░  ░░ ░          ░ ░           ░                 ░         ░ ░  
{Style.RESET_ALL}"""

def get_banner_3():
    """ASCII Art Banner 3"""
    return f"""{Fore.GREEN}{Style.BRIGHT}
   █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
  ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
  ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
{Style.RESET_ALL}"""

def print_info():
    """Print application information"""
    info = f"""
{Fore.YELLOW}{Style.BRIGHT}    ╔══════════════════════════════════════════════════════════════════════════════════════╗
    ║                           AutoRecon-Py Pro v2.0                                     ║
    ║                     Advanced Network Reconnaissance Framework                        ║
    ║                                                                                      ║
    ║  🎯 Multi-Target Scanning      🔍 Service Enumeration     🌐 Web App Testing       ║
    ║  🛡️  Vulnerability Assessment  📊 Advanced Reporting     🔧 Extensible Plugins     ║
    ║  🚀 Async Performance         💾 Resume Capability       🎨 Beautiful Output       ║
    ║                                                                                      ║
    ║  Created by: Enhanced AI Assistant    License: MIT                                  ║
    ║  GitHub: https://github.com/AvinashCoder31/AutoRecon-Py                             ║
    ╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(info)

def print_scan_header(target: str, profile: str, plugins: int):
    """Print scan header information"""
    header = f"""
{Fore.BLUE}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                 SCAN CONFIGURATION                                   ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  Target: {target:<70} ║
║  Profile: {profile:<69} ║
║  Plugins: {plugins:<69} ║
║  Started: {get_current_time():<67} ║
╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(header)

def print_scan_phase(phase_name: str, description: str):
    """Print scan phase header"""
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*80}")
    print(f"PHASE: {phase_name.upper()}")
    print(f"Description: {description}")
    print(f"{'='*80}{Style.RESET_ALL}")

def print_plugin_start(plugin_name: str, target: str):
    """Print plugin start message"""
    print(f"{Fore.CYAN}[PLUGIN] {plugin_name} → {target}{Style.RESET_ALL}")

def print_target_summary(target: str, stats: dict):
    """Print target scan summary"""
    summary = f"""
{Fore.GREEN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                TARGET SUMMARY: {target:<40} ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  📊 Ports Found: {stats.get('ports_found', 0):<20} 🔍 Services Identified: {stats.get('services_identified', 0):<20} ║
║  🌐 Web Services: {stats.get('web_services', 0):<19} 📁 Directories Found: {stats.get('directories_found', 0):<20} ║
║  🛡️  Vulnerabilities: {stats.get('vulnerabilities_found', 0):<17} 📋 Technologies: {stats.get('technologies_detected', 0):<23} ║
║  🔑 Credentials: {stats.get('credentials_found', 0):<20} ⏱️  Duration: {stats.get('duration', '0s'):<25} ║
║  🎯 Risk Level: {stats.get('risk_level', 'LOW'):<21} 📈 Success Rate: {stats.get('success_rate', '100%'):<20} ║
╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(summary)

def print_findings_table(findings: list):
    """Print findings in table format"""
    if not findings:
        return
    
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════════════════════╗")
    print(f"║                                    KEY FINDINGS                                      ║")
    print(f"╠══════════════════════════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
    
    for finding in findings[:10]:  # Show top 10 findings
        severity_color = get_severity_color(finding.get('severity', 'INFO'))
        print(f"║ {severity_color}●{Style.RESET_ALL} {finding.get('type', 'Unknown'):<20} │ {finding.get('description', '')[:50]:<50} ║")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

def get_severity_color(severity: str) -> str:
    """Get color based on severity level"""
    colors = {
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.BLUE,
        'INFO': Fore.GREEN
    }
    return colors.get(severity.upper(), Fore.WHITE)

def print_progress_bar(current: int, total: int, prefix: str = "", length: int = 50):
    """Print progress bar"""
    if total == 0:
        return
    
    percent = (current / total) * 100
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '░' * (length - filled_length)
    
    print(f"\r{Fore.BLUE}{prefix} |{bar}| {percent:.1f}% ({current}/{total}){Style.RESET_ALL}", end='', flush=True)

def print_error_box(error_message: str):
    """Print error in a box"""
    lines = error_message.split('\n')
    max_length = max(len(line) for line in lines) + 4
    
    print(f"\n{Fore.RED}{Style.BRIGHT}╔{'═' * max_length}╗")
    print(f"║{' ' * ((max_length - 5) // 2)}ERROR{' ' * ((max_length - 5) // 2)}║")
    print(f"╠{'═' * max_length}╣")
    
    for line in lines:
        padding = max_length - len(line) - 2
        print(f"║ {line}{' ' * padding}║")
    
    print(f"╚{'═' * max_length}╝{Style.RESET_ALL}")

def print_success_box(success_message: str):
    """Print success in a box"""
    lines = success_message.split('\n')
    max_length = max(len(line) for line in lines) + 4
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}╔{'═' * max_length}╗")
    print(f"║{' ' * ((max_length - 7) // 2)}SUCCESS{' ' * ((max_length - 7) // 2)}║")
    print(f"╠{'═' * max_length}╣")
    
    for line in lines:
        padding = max_length - len(line) - 2
        print(f"║ {line}{' ' * padding}║")
    
    print(f"╚{'═' * max_length}╝{Style.RESET_ALL}")

def print_warning_box(warning_message: str):
    """Print warning in a box"""
    lines = warning_message.split('\n')
    max_length = max(len(line) for line in lines) + 4
    
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}╔{'═' * max_length}╗")
    print(f"║{' ' * ((max_length - 7) // 2)}WARNING{' ' * ((max_length - 7) // 2)}║")
    print(f"╠{'═' * max_length}╣")
    
    for line in lines:
        padding = max_length - len(line) - 2
        print(f"║ {line}{' ' * padding}║")
    
    print(f"╚{'═' * max_length}╝{Style.RESET_ALL}")

def get_current_time() -> str:
    """Get current time formatted"""
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_manual_commands(commands: list):
    """Print manual commands box"""
    if not commands:
        return
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════════════════════╗")
    print(f"║                                MANUAL COMMANDS                                       ║")
    print(f"║                        (Commands for further manual testing)                        ║")
    print(f"╠══════════════════════════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
    
    for i, cmd in enumerate(commands[:10], 1):  # Show top 10 commands
        description = cmd.get('description', 'Manual command')
        command = cmd.get('command', '')
        
        print(f"{Fore.CYAN}║ {i:2d}. {description:<75} ║{Style.RESET_ALL}")
        print(f"║     {Fore.WHITE}{command[:75]:<75}{Style.RESET_ALL} ║")
        if i < len(commands[:10]):
            print(f"{Fore.CYAN}╠──────────────────────────────────────────────────────────────────────────────────────╣{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{Style.BRIGHT}╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

def print_final_summary(total_targets: int, successful: int, failed: int, duration: float):
    """Print final scan summary"""
    success_rate = (successful / total_targets * 100) if total_targets > 0 else 0
    
    summary = f"""
{Fore.GREEN if successful > failed else Fore.YELLOW}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                  SCAN COMPLETE                                       ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  📊 Total Targets: {total_targets:<20} ✅ Successful: {successful:<25} ║
║  ❌ Failed: {failed:<25} 📈 Success Rate: {success_rate:.1f}%{' ' * 18} ║
║  ⏱️  Total Duration: {format_duration(duration):<65} ║
║  📁 Results saved to output directory                                                ║
╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(summary)

def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        seconds = seconds % 60
        return f"{minutes}m {seconds:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = seconds % 60
        return f"{hours}h {minutes}m {seconds:.0f}s"

def print_ascii_art_small():
    """Print small ASCII art for status updates"""
    art = f"""{Fore.BLUE}
    ╔═══════════════════════════════════════╗
    ║          AutoRecon-Py Pro             ║
    ║     Advanced Network Reconnaissance   ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """
    return art