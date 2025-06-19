#!/bin/bash

# MantaGuard Project Initialization Script
# This script sets up the project with uv for dependency management

set -e  # Exit on any error

echo "🛡️  MantaGuard Project Initialization"
echo "====================================="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ Error: MantaGuard requires Linux operating system"
    echo "   Reason: Zeek Network Security Monitor (core dependency) only runs on Linux"
    echo "   Supported: Ubuntu 20.04+, Debian 12+, and compatible distributions"
    echo "   Current OS: $OSTYPE"
    exit 1
fi

echo "✅ Linux system detected: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown distribution")"

# Function to install uv
install_uv() {
    echo "📦 Starting uv installation..."
    
    # Check if we can write to ~/.cargo/bin or ~/.local/bin
    if [[ -w "$HOME/.cargo/bin" ]] || [[ -w "$HOME/.local/bin" ]] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
        echo "   Installing uv using the official installer..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        
        # Source the environment to make uv available immediately
        if [[ -f "$HOME/.cargo/env" ]]; then
            source "$HOME/.cargo/env"
        fi
        
        # Add to PATH if needed
        if [[ -f "$HOME/.cargo/bin/uv" ]] && [[ ":$PATH:" != *":$HOME/.cargo/bin:"* ]]; then
            export PATH="$HOME/.cargo/bin:$PATH"
        elif [[ -f "$HOME/.local/bin/uv" ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            export PATH="$HOME/.local/bin:$PATH"
        fi
        
        # Verify installation
        if command -v uv &> /dev/null; then
            echo "✅ uv installation successful: $(uv --version)"
            return 0
        else
            echo "❌ uv installation failed. Please install manually."
            return 1
        fi
    else
        echo "❌ Cannot install uv automatically (no write permissions)"
        echo "   Please install uv manually: https://docs.astral.sh/uv/getting-started/installation/"
        return 1
    fi
}

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ uv is not installed"
    echo "   uv is required for Python dependency management in MantaGuard"
    echo ""
    
    # Check if user wants automatic installation
    while true; do
        read -p "Would you like MantaGuard to install uv automatically? (y/n): " yn
        case $yn in
            [Yy]* ) 
                echo "🚀 Installing uv automatically..."
                if install_uv; then
                    echo "✅ uv installation completed successfully!"
                    break
                else
                    echo "❌ Automatic installation failed."
                    echo "   Please install uv manually: https://docs.astral.sh/uv/getting-started/installation/"
                    echo "   Quick install: curl -LsSf https://astral.sh/uv/install.sh | sh"
                    exit 1
                fi
                ;;
            [Nn]* ) 
                echo "📖 Manual installation required:"
                echo "   - https://docs.astral.sh/uv/getting-started/installation/"
                echo "   - Quick install: curl -LsSf https://astral.sh/uv/install.sh | sh"
                echo ""
                echo "After installing uv, run this script again."
                exit 1
                ;;
            * ) 
                echo "Please answer yes (y) or no (n)."
                ;;
        esac
    done
fi

echo "✅ Found uv: $(uv --version)"

# Function to check and install system dependencies
check_system_dependencies() {
    echo "🔍 Checking system dependencies..."
    local missing_deps=()
    
    # Check for essential tools
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    if ! command -v git &> /dev/null; then
        missing_deps+=("git")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check for build essentials (needed for some Python packages)
    if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
        if [[ -f /etc/arch-release ]]; then
            missing_deps+=("base-devel")
        else
            missing_deps+=("build-essential")
        fi
    fi
    
    # Check for Python development headers
    if ! python3 -c "import distutils.util" 2>/dev/null && ! python3 -c "import sysconfig" 2>/dev/null; then
        if [[ -f /etc/arch-release ]]; then
            # On Arch, python headers are included in python package
            missing_deps+=("python-dev-tools")
        else
            missing_deps+=("python3-dev")
        fi
    fi
    
    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        echo "✅ All system dependencies are available"
        return 0
    fi
    
    echo "❌ Missing system dependencies: ${missing_deps[*]}"
    echo "   These dependencies are required for MantaGuard to function properly"
    echo ""
    
    # Ask user if they want to install missing dependencies
    while true; do
        read -p "Would you like to install missing system dependencies? (y/n): " yn
        case $yn in
            [Yy]* ) 
                echo "🚀 Installing system dependencies..."
                if install_system_dependencies "${missing_deps[@]}"; then
                    echo "✅ System dependencies installed successfully!"
                    return 0
                else
                    echo "❌ Failed to install some dependencies. Please install manually:"
                    echo "   ${missing_deps[*]}"
                    return 1
                fi
                ;;
            [Nn]* ) 
                echo "⚠️  Warning: Some features may not work without these dependencies:"
                echo "   ${missing_deps[*]}"
                echo "   You can install them manually later if needed."
                return 0
                ;;
            * ) 
                echo "Please answer yes (y) or no (n)."
                ;;
        esac
    done
}

# Function to install system dependencies
install_system_dependencies() {
    local deps=("$@")
    
    # Detect distribution for package installation
    if command -v lsb_release &> /dev/null; then
        DISTRO=$(lsb_release -si)
    elif [[ -f /etc/arch-release ]]; then
        DISTRO="Arch"
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="Debian"
    else
        DISTRO="Unknown"
    fi
    
    case $DISTRO in
        "Ubuntu"|"Debian")
            echo "   Updating package list..."
            sudo apt update
            for dep in "${deps[@]}"; do
                echo "   Installing $dep..."
                sudo apt install -y "$dep" || echo "   Warning: Failed to install $dep"
            done
            ;;
            
        "Arch"|"Manjaro"|"EndeavourOS"|"ArcoLinux")
            echo "   Updating package database..."
            sudo pacman -Sy
            for dep in "${deps[@]}"; do
                echo "   Installing $dep..."
                # Map some package names for Arch
                case $dep in
                    "build-essential") dep="base-devel" ;;
                    "python3-dev") dep="python" ;;  # Headers included in python package
                    "python-dev-tools") dep="python" ;;
                esac
                sudo pacman -S --noconfirm "$dep" || echo "   Warning: Failed to install $dep"
            done
            ;;
            
        *)
            echo "   ❌ Unsupported distribution for automatic dependency installation: $DISTRO"
            echo "   Please install these packages manually: ${deps[*]}"
            return 1
            ;;
    esac
    
    return 0
}

# Check system dependencies
check_system_dependencies

# Function to check if Zeek is installed
check_zeek() {
    if command -v zeek &> /dev/null && command -v zeekctl &> /dev/null; then
        echo "✅ Zeek is installed: $(zeek --version 2>/dev/null | head -n1 || echo "version unknown")"
        return 0
    elif [[ -x "/opt/zeek/bin/zeek" ]] && [[ -x "/opt/zeek/bin/zeekctl" ]]; then
        echo "✅ Zeek found in /opt/zeek/bin/"
        echo "   Note: You may need to add /opt/zeek/bin to your PATH"
        echo "   Run: export PATH=\"/opt/zeek/bin:\$PATH\""
        return 0
    else
        return 1
    fi
}

# Function to install Zeek automatically
install_zeek() {
    echo "📦 Starting Zeek installation..."
    
    # Check if we have sudo privileges
    if ! sudo -n true 2>/dev/null; then
        echo "   This installation requires sudo privileges."
        echo "   You may be prompted for your password."
    fi
    
    # Detect distribution
    if command -v lsb_release &> /dev/null; then
        DISTRO=$(lsb_release -si)
        VERSION=$(lsb_release -sr)
        echo "   Detected: $DISTRO $VERSION"
    else
        echo "   Warning: Cannot detect distribution, assuming Ubuntu"
        DISTRO="Ubuntu"
        VERSION="22.04"
    fi
    
    # Install based on distribution
    case $DISTRO in
        "Ubuntu")
            echo "   Installing Zeek for Ubuntu..."
            
            # Add GPG key
            echo "   Adding Zeek repository GPG key..."
            curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${VERSION}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
            
            # Add repository
            echo "   Adding Zeek repository..."
            echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
            
            # Update and install
            echo "   Updating package list..."
            sudo apt update
            echo "   Installing Zeek..."
            sudo apt install -y zeek
            ;;
            
        "Debian")
            echo "   Installing Zeek for Debian..."
            
            # Add GPG key
            echo "   Adding Zeek repository GPG key..."
            curl -fsSL "https://download.opensuse.org/repositories/security:zeek/Debian_${VERSION}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
            
            # Add repository
            echo "   Adding Zeek repository..."
            echo "deb http://download.opensuse.org/repositories/security:/zeek/Debian_${VERSION}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
            
            # Update and install
            echo "   Updating package list..."
            sudo apt update
            echo "   Installing Zeek..."
            sudo apt install -y zeek
            ;;
            
        "Arch"|"Manjaro"|"EndeavourOS"|"ArcoLinux")
            echo "   Installing Zeek for Arch Linux..."
            
            # Check if yay is available (preferred AUR helper)
            if command -v yay &> /dev/null; then
                echo "   Using yay to install Zeek from AUR..."
                yay -S --noconfirm zeek
            elif command -v paru &> /dev/null; then
                echo "   Using paru to install Zeek from AUR..."
                paru -S --noconfirm zeek
            else
                echo "   No AUR helper found. Installing using pacman from official repos..."
                sudo pacman -Sy --noconfirm zeek 2>/dev/null || {
                    echo "   Zeek not available in official repos. Installing yay first..."
                    # Install base-devel and git if not present
                    sudo pacman -S --needed --noconfirm base-devel git
                    
                    # Clone and install yay
                    cd /tmp
                    git clone https://aur.archlinux.org/yay.git
                    cd yay
                    makepkg -si --noconfirm
                    cd - > /dev/null
                    
                    echo "   Installing Zeek using yay..."
                    yay -S --noconfirm zeek
                }
            fi
            ;;
            
        *)
            echo "   ❌ Unsupported distribution: $DISTRO"
            echo "   Supported distributions:"
            echo "   - Ubuntu 20.04+"
            echo "   - Debian 12+"
            echo "   - Arch Linux (and derivatives like Manjaro, EndeavourOS)"
            echo "   Please install Zeek manually. See README.md for instructions."
            return 1
            ;;
    esac
    
    # Verify installation
    echo "   Verifying Zeek installation..."
    if check_zeek; then
        echo "✅ Zeek installation successful!"
        
        # Add to PATH if needed
        if ! command -v zeek &> /dev/null && [[ -x "/opt/zeek/bin/zeek" ]]; then
            echo "   Adding Zeek to PATH for current session..."
            export PATH="/opt/zeek/bin:$PATH"
            echo "   Note: Add 'export PATH=\"/opt/zeek/bin:\$PATH\"' to your ~/.bashrc for permanent access"
        fi
    else
        echo "❌ Zeek installation failed. Please install manually."
        echo "   See README.md for manual installation instructions."
        return 1
    fi
}

# Check for Zeek installation
echo "🔍 Checking for Zeek Network Security Monitor..."
if ! check_zeek; then
    echo "❌ Zeek is required but not found"
    echo "   Zeek is essential for network packet analysis in MantaGuard"
    echo ""
    
    # Check if user wants automatic installation
    while true; do
        read -p "Would you like MantaGuard to install Zeek automatically? (y/n): " yn
        case $yn in
            [Yy]* ) 
                echo "🚀 Installing Zeek automatically..."
                # Call the Zeek installation function
                if install_zeek; then
                    echo "✅ Zeek installation completed successfully!"
                    break
                else
                    echo "❌ Automatic installation failed. Please install manually."
                    exit 1
                fi
                ;;
            [Nn]* ) 
                echo "📖 Manual installation required. Please see the documentation:"
                echo "   - README.md: Zeek Installation Guide section"
                echo "   - https://docs.zeek.org/en/stable/install/index.html"
                echo ""
                echo "After installing Zeek, run this script again."
                exit 1
                ;;
            * ) 
                echo "Please answer yes (y) or no (n)."
                ;;
        esac
    done
fi

# Check if we're in the right directory
if [[ ! -f "app.py" ]] || [[ ! -f "pyproject.toml" ]]; then
    echo "❌ Error: Please run this script from the MantaGuard project root directory"
    exit 1
fi

echo "📁 Setting up virtual environment..."
# Create virtual environment if it doesn't exist
if [[ ! -d ".venv" ]]; then
    uv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

echo "📦 Installing dependencies..."
# Install dependencies using pyproject.toml
uv sync
echo "✅ Dependencies installed"

echo "📂 Ensuring data directory structure..."
# Create necessary directories (they should exist but ensure they're there)
mkdir -p data/{pcaps,logs,models,analysis,forensics,output/analysis_results,labeling/extracted_pcaps,AttackData}

# Ensure .gitkeep files exist to maintain directory structure
touch data/pcaps/.gitkeep 2>/dev/null || true
touch data/logs/.gitkeep 2>/dev/null || true
touch data/models/.gitkeep 2>/dev/null || true
touch data/analysis/.gitkeep 2>/dev/null || true
touch data/forensics/.gitkeep 2>/dev/null || true
touch data/output/analysis_results/.gitkeep 2>/dev/null || true
touch data/labeling/extracted_pcaps/.gitkeep 2>/dev/null || true
touch data/AttackData/.gitkeep 2>/dev/null || true

echo "✅ Directory structure verified"

echo "🎯 Initialization complete!"
echo ""
echo "Next steps:"
echo "1. Run './start.sh' to launch the application"
echo "2. Or manually activate the environment: source .venv/bin/activate"
echo "3. Then run: uv run python app.py"
echo ""
echo "The application will be available at: http://127.0.0.1:5000"
echo "The training database (training_repository.db) will be created automatically on first run."