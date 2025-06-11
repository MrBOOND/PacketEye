#!/bin/bash

# DPI Network Monitor Runner
# This script checks requirements and runs the monitor

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo -e "${RED}❌ This program requires root privileges${NC}"
   echo -e "${YELLOW}Trying with sudo...${NC}"
   sudo "$0" "$@"
   exit $?
fi

# Check if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo -e "${RED}❌ tshark is not installed${NC}"
    echo -e "${YELLOW}Please run: ./install.sh${NC}"
    exit 1
fi

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 is not installed${NC}"
    exit 1
fi

# Check if rich is installed
if ! python3 -c "import rich" &> /dev/null; then
    echo -e "${YELLOW}⚠️  Rich library not found${NC}"
    echo -e "${CYAN}Installing rich...${NC}"
    pip3 install rich
fi

# Clear screen
clear

# Run the DPI monitor
python3 DPI.py
