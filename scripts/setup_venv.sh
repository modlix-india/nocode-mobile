#!/bin/bash

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv nocode-mobile-venv

# Activate virtual environment
echo "Activating virtual environment..."
source nocode-mobile-venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing requirements..."
pip install requests



echo "Virtual environment setup complete!"
echo "To activate: source nocode-mobile-venv/bin/activate"
echo "To deactivate: deactivate"
