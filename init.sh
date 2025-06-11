#!/bin/bash

# MantaGuard Project Initialization Script
# This script sets up the project with uv for dependency management

set -e  # Exit on any error

echo "🛡️  MantaGuard Project Initialization"
echo "====================================="

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ Error: uv is not installed"
    echo "Please install uv first: https://docs.astral.sh/uv/getting-started/installation/"
    echo "Quick install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "✅ Found uv: $(uv --version)"

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