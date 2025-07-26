#!/bin/bash

# AutoRecon-Py Pro v2.0 - Installation and Setup Script
# This script automates the installation of AutoRecon-Py Pro and its dependencies

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                           AutoRecon-Py Pro v2.0 Setup                               ║"
    echo "║                     Advanced Network Reconnaissance Framework                        ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. Some operations may require non-root privileges."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            OS="debian"
            PKG_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            OS="redhat"
            PKG_MANAGER="yum"
        elif command -v pacman &> /dev/null; then
            OS="arch"
            PKG_MANAGER="pacman"
        else
            OS="linux"
            PKG_MANAGER="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    else
        OS="unknown"
        PKG_MANAGER="unknown"
    fi
    
    log_info "Detected OS: $OS"
}

# Update package manager
update_packages() {
    log_step "Updating package manager..."
    
    case $PKG_MANAGER in
        "apt")
            sudo apt update && sudo apt upgrade -y
            ;;
        "yum")
            sudo yum update -y
            ;;
        "pacman")
            sudo pacman -Syu --noconfirm
            ;;
        "brew")
            brew update && brew upgrade
            ;;
        *)
            log_warning "Unknown package manager. Please update manually."
            ;;
    esac
    
    log_success "Package manager updated"
}

# Install Python 3.8+
install_python() {
    log_step "Installing Python 3.8+..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
        if (( $(echo "$PYTHON_VERSION >= 3.8" | bc -l) )); then
            log_success "Python $PYTHON_VERSION is already installed"
            return
        fi
    fi
    
    case $PKG_MANAGER in
        "apt")
            sudo apt install -y python3 python3-pip python3-venv python3-dev
            ;;
        "yum")
            sudo yum install -y python3 python3-pip python3-devel
            ;;
        "pacman")
            sudo pacman -S --noconfirm python python-pip
            ;;
        "brew")
            brew install python@3.11
            ;;
        *)
            log_error "Cannot install Python automatically. Please install Python 3.8+ manually."
            exit 1
            ;;
    esac
    
    log_success "Python installed"
}

# Install system dependencies
install_system_deps() {
    log_step "Installing system dependencies..."
    
    case $PKG_MANAGER in
        "apt")
            sudo apt install -y \
                nmap masscan \
                gobuster feroxbuster dirb dirbuster \
                nikto whatweb httpx \
                hydra john hashcat \
                enum4linux smbclient smbmap rpcclient \
                snmp snmp-mibs-downloader onesixtyone \
                ftp telnet openssh-client netcat-openbsd \
                curl wget dnsutils whois iputils-ping traceroute \
                tcpdump tshark wireshark-common \
                aircrack-ng hashid \
                libimage-exiftool-perl binwalk binutils xxd \
                git build-essential libssl-dev libffi-dev \
                chromium-browser chromium-chromedriver \
                sqlite3 redis-server \
                bc jq
            ;;
        "yum")
            sudo yum install -y \
                nmap masscan \
                gobuster nikto \
                hydra john \
                smbclient \
                net-snmp-utils \
                ftp telnet openssh-clients nc \
                curl wget bind-utils whois iputils traceroute \
                tcpdump wireshark \
                hashcat \
                exiftool binutils \
                git gcc openssl-devel libffi-devel \
                sqlite redis \
                bc jq
            ;;
        "pacman")
            sudo pacman -S --noconfirm \
                nmap masscan \
                gobuster nikto \
                hydra john \
                smbclient \
                net-snmp \
                curl wget bind whois iputils traceroute \
                tcpdump wireshark-cli \
                hashcat \
                perl-image-exiftool binutils \
                git base-devel openssl libffi \
                sqlite redis \
                bc jq
            ;;
        "brew")
            brew install \
                nmap masscan \
                gobuster nikto \
                hydra john \
                smbclient \
                net-snmp \
                curl wget bind whois \
                tcpdump wireshark \
                hashcat \
                exiftool binutils \
                git openssl libffi \
                sqlite redis \
                bc jq
            ;;
        *)
            log_warning "Cannot install system dependencies automatically."
            log_info "Please install the following tools manually:"
            echo "nmap, masscan, gobuster, nikto, hydra, smbclient, curl, wget, etc."
            ;;
    esac
    
    log_success "System dependencies installed"
}

# Install Go tools
install_go_tools() {
    log_step "Installing Go-based tools..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_info "Installing Go..."
        case $PKG_MANAGER in
            "apt")
                sudo apt install -y golang-go
                ;;
            "yum")
                sudo yum install -y golang
                ;;
            "pacman")
                sudo pacman -S --noconfirm go
                ;;
            "brew")
                brew install go
                ;;
            *)
                log_warning "Please install Go manually from https://golang.org/dl/"
                return
                ;;
        esac
    fi
    
    # Install Go tools
    log_info "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    log_info "Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    log_info "Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    log_info "Installing amass..."
    go install -v github.com/owasp-amass/amass/v4/...@master
    
    # Add Go bin to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:$HOME/go/bin
        log_info "Added $HOME/go/bin to PATH"
    fi
    
    log_success "Go tools installed"
}

# Create project structure
create_project_structure() {
    log_step "Creating project structure..."
    
    # Create main directories
    mkdir -p autorecon-pro/{core,plugins,utils,wordlists,templates,docs,tests}
    mkdir -p autorecon-pro/plugins/{port_scan,service_scan,web_scan,vuln_scan,report}
    mkdir -p autorecon-pro/output
    mkdir -p ~/.config/autorecon-pro
    
    log_success "Project structure created"
}

# Setup Python virtual environment
setup_virtual_env() {
    log_step "Setting up Python virtual environment..."
    
    cd autorecon-pro
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    log_success "Virtual environment created"
}

# Install Python dependencies
install_python_deps() {
    log_step "Installing Python dependencies..."
    
    # Install from requirements.txt if it exists, otherwise install manually
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        # Core dependencies
        pip install \
            aiohttp aiofiles asyncio-throttle \
            requests urllib3 httpx selenium beautifulsoup4 lxml \
            python-nmap scapy cryptography pyOpenSSL paramiko \
            pyyaml toml xmltodict python-dateutil \
            jinja2 markdown reportlab xlsxwriter \
            pillow colorama rich click \
            dnspython python-whois \
            loguru psutil \
            pytest pytest-asyncio
    fi
    
    log_success "Python dependencies installed"
}

# Download wordlists
download_wordlists() {
    log_step "Downloading wordlists..."
    
    # Create wordlists directory
    mkdir -p wordlists
    cd wordlists
    
    # Download SecLists if not already present
    if [ ! -d "SecLists" ]; then
        log_info "Downloading SecLists..."
        git clone https://github.com/danielmiessler/SecLists.git
    fi
    
    # Download other useful wordlists
    if [ ! -f "rockyou.txt" ]; then
        log_info "Downloading rockyou.txt..."
        if command -v wget &> /dev/null; then
            wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        elif command -v curl &> /dev/null; then
            curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        fi
    fi
    
    cd ..
    log_success "Wordlists downloaded"
}

# Create configuration files
create_config_files() {
    log_step "Creating configuration files..."
    
    # Create main config file
    cat > ~/.config/autorecon-pro/config.yaml << EOF
# AutoRecon-Py Pro Configuration File
version: '2.0'

scanning:
  ports: '1-65535'
  udp_ports: 'top-1000'
  timing: 'normal'
  max_retries: 3

performance:
  max_targets: 10
  max_scans: 50
  threads: 20
  timeout: 300

features:
  screenshots: true
  bruteforce: false
  vulnerability_scan: true
  os_detection: true

output:
  directory: 'results'
  formats: ['json', 'txt', 'html']
  compression: true

wordlists:
  directory: './wordlists'
  subdomain_list: 'SecLists/Discovery/DNS/subdomains-top1million-110000.txt'
  directory_list: 'SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt'

tools:
  nmap:
    path: 'nmap'
    extra_args: '-sV -sC --version-intensity 5'
  gobuster:
    path: 'gobuster'
    threads: 50
    extensions: 'php,html,txt,js,css,xml,json'

logging:
  level: 'INFO'
  file: 'autorecon.log'
EOF

    log_success "Configuration files created"
}

# Set up desktop shortcut (Linux only)
create_desktop_shortcut() {
    if [[ "$OS" == "debian" || "$OS" == "redhat" || "$OS" == "arch" ]]; then
        log_step "Creating desktop shortcut..."
        
        cat > ~/Desktop/AutoRecon-Pro.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=AutoRecon-Py Pro
Comment=Advanced Network Reconnaissance Framework
Exec=$PWD/venv/bin/python $PWD/main.py
Icon=utilities-terminal
Path=$PWD
Terminal=true
Categories=Security;Network;
EOF
        
        chmod +x ~/Desktop/AutoRecon-Pro.desktop
        log_success "Desktop shortcut created"
    fi
}

# Install browser drivers
install_browser_drivers() {
    log_step "Installing browser drivers..."
    
    # Install chromedriver
    if command -v google-chrome &> /dev/null || command -v chromium-browser &> /dev/null; then
        pip install chromedriver-binary
        log_success "Chrome driver installed"
    fi
    
    # Install geckodriver for Firefox
    if command -v firefox &> /dev/null; then
        pip install geckodriver-autoinstaller
        log_success "Gecko driver installed"
    fi
}

# Verify installation
verify_installation() {
    log_step "Verifying installation..."
    
    # Check Python dependencies
    python -c "import aiohttp, requests, nmap, yaml; print('Python dependencies OK')"
    
    # Check system tools
    local tools=("nmap" "gobuster" "nikto" "hydra" "curl" "wget")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -eq 0 ]; then
        log_success "All system tools are available"
    else
        log_warning "Missing tools: ${missing_tools[*]}"
        log_info "Some features may not work properly"
    fi
    
    # Check wordlists
    if [ -d "wordlists/SecLists" ]; then
        log_success "Wordlists are available"
    else
        log_warning "Wordlists not found. Some features may be limited."
    fi
    
    log_success "Installation verification completed"
}

# Create startup script
create_startup_script() {
    log_step "Creating startup script..."
    
    cat > autorecon-pro.sh << 'EOF'
#!/bin/bash

# AutoRecon-Py Pro Startup Script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
source venv/bin/activate

# Run AutoRecon-Py Pro
python main.py "$@"
EOF
    
    chmod +x autorecon-pro.sh
    
    # Create symlink for global access
    if [ -w "/usr/local/bin" ]; then
        sudo ln -sf "$PWD/autorecon-pro.sh" /usr/local/bin/autorecon-pro
        log_success "Global command 'autorecon-pro' created"
    else
        log_info "Add $PWD to your PATH to use 'autorecon-pro' globally"
    fi
    
    log_success "Startup script created"
}

# Print usage instructions
print_usage_instructions() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                              INSTALLATION COMPLETE                                   ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                                      ║"
    echo "║  AutoRecon-Py Pro has been successfully installed!                                   ║"
    echo "║                                                                                      ║"
    echo "║  Usage:                                                                              ║"
    echo "║    ./autorecon-pro.sh <target>                    # Basic scan                      ║"
    echo "║    ./autorecon-pro.sh 192.168.1.0/24             # Network scan                    ║"
    echo "║    ./autorecon-pro.sh --profile thorough <target> # Comprehensive scan              ║"
    echo "║    ./autorecon-pro.sh --help                      # Show all options                ║"
    echo "║                                                                                      ║"
    echo "║  Configuration: ~/.config/autorecon-pro/config.yaml                                 ║"
    echo "║  Results: ./results/                                                                ║"
    echo "║                                                                                      ║"
    echo "║  For updates: git pull && ./setup.sh --update                                       ║"
    echo "║                                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Update function
update_installation() {
    log_step "Updating AutoRecon-Py Pro..."
    
    # Pull latest changes
    git pull origin main
    
    # Update Python dependencies
    source venv/bin/activate
    pip install --upgrade -r requirements.txt
    
    # Update Go tools
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    log_success "AutoRecon-Py Pro updated successfully"
}

# Main installation function
main() {
    print_banner
    
    # Parse command line arguments
    case "${1:-}" in
        --update)
            update_installation
            exit 0
            ;;
        --help)
            echo "Usage: $0 [--update|--help]"
            echo "  --update  Update existing installation"
            echo "  --help    Show this help message"
            exit 0
            ;;
    esac
    
    check_root
    detect_os
    
    log_info "Starting AutoRecon-Py Pro installation..."
    
    # Installation steps
    update_packages
    install_python
    install_system_deps
    install_go_tools
    create_project_structure
    setup_virtual_env
    install_python_deps
    install_browser_drivers
    download_wordlists
    create_config_files
    create_desktop_shortcut
    create_startup_script
    verify_installation
    
    print_usage_instructions
    
    log_success "Installation completed successfully!"
}

# Run main function
main "$@"