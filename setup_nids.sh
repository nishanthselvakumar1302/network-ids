#!/bin/bash
# NIDS Project Setup Script

echo "Setting up Network Intrusion Detection System..."

# Create directories
mkdir -p models logs data

# Create virtual environment
python3 -m venv nids_env
source nids_env/bin/activate

# Install requirements
pip install -r nids_requirements.txt

# Set permissions
chmod +x nids_main.py

echo "NIDS setup completed!"
echo "To activate the environment: source nids_env/bin/activate"
echo "To run the system: python nids_main.py"
