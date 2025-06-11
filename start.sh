#!/bin/bash

# MantaGuard Application Launcher
# This script starts the MantaGuard application and opens it in the browser

set -e  # Exit on any error

echo "🛡️  Starting MantaGuard..."
echo "========================="

# Check if we're in the right directory
if [[ ! -f "app.py" ]] || [[ ! -f "pyproject.toml" ]]; then
    echo "❌ Error: Please run this script from the MantaGuard project root directory"
    exit 1
fi

# Check if virtual environment exists
if [[ ! -d ".venv" ]]; then
    echo "❌ Error: Virtual environment not found"
    echo "Please run './init.sh' first to initialize the project"
    exit 1
fi

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ Error: uv is not installed"
    echo "Please install uv first: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

echo "🚀 Launching MantaGuard application..."

# Function to open browser (cross-platform)
open_browser() {
    local url="http://127.0.0.1:5000"
    
    # Wait a moment for the server to start
    sleep 3
    
    # Detect platform and open browser
    if command -v xdg-open &> /dev/null; then
        # Linux
        xdg-open "$url" 2>/dev/null &
    elif command -v open &> /dev/null; then
        # macOS
        open "$url" 2>/dev/null &
    elif command -v start &> /dev/null; then
        # Windows (if running in WSL or Git Bash)
        start "$url" 2>/dev/null &
    else
        echo "📖 Please open your browser and navigate to: $url"
        return
    fi
    
    echo "🌐 Opening browser at: $url"
}

# Start browser opener in background
open_browser &

echo "🎯 Starting Flask application..."
echo "   - Application URL: http://127.0.0.1:5000"
echo "   - Press Ctrl+C to stop the application"
echo ""

# Start the application with uv
uv run python app.py