#!/bin/bash
# Setup script for MCP server virtual environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "Setting up MCP server virtual environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists at $VENV_DIR"
fi

# Activate virtual environment and install dependencies
echo "Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "✓ Virtual environment setup complete!"
echo ""
echo "The virtual environment is located at: $VENV_DIR"
echo "Python interpreter: $VENV_DIR/bin/python"
echo ""
echo "To activate manually, run:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "Update your Cursor MCP configuration to use:"
echo "  $VENV_DIR/bin/python"
