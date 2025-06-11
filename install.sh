#!/bin/bash

# DPI Network Monitor Installation Script
# Author: 0x1ez

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║       DPI Network Monitor Installer          ║"
echo "║              by 0x1ez                        ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${YELLOW}⚠️  Running as root${NC}"
else
   echo -e "${RED}❌ This installer needs sudo privileges${NC}"
   echo -e "${GREEN}Please run: sudo ./install.sh${NC}"
   exit 1
fi

# Detect OS
echo -e "${BLUE}🔍 Detecting operating system...${NC}"
if [ -f /etc/debian_version ]; then
    OS="debian"
    echo -e "${GREEN}✓ Detected: Debian/Ubuntu${NC}"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    echo -e "${GREEN}✓ Detected: RedHat/Fedora${NC}"
elif [ -f /etc/arch-release ]; then
    OS="arch"
    echo -e "${GREEN}✓ Detected: Arch Linux${NC}"
elif [ -d /data/data/com.termux ]; then
    OS="termux"
    echo -e "${GREEN}✓ Detected: Termux${NC}"
else
    OS="unknown"
    echo -e "${YELLOW}⚠️  Unknown OS - manual installation may be required${NC}"
fi

# Install tshark
echo -e "\n${BLUE}📦 Installing tshark...${NC}"
case $OS in
    debian)
        apt update
        apt install -y tshark python3-pip
        ;;
    redhat)
        dnf install -y wireshark-cli python3-pip
        ;;
    arch)
        pacman -Sy --noconfirm wireshark-cli python-pip
        ;;
    termux)
        pkg update
        pkg install -y root-repo
        pkg install -y tshark python
        ;;
    *)
        echo -e "${YELLOW}Please install tshark manually${NC}"
        ;;
esac

# Check if tshark is installed
if command -v tshark &> /dev/null; then
    echo -e "${GREEN}✓ tshark installed successfully${NC}"
else
    echo -e "${RED}❌ tshark installation failed${NC}"
    echo -e "${YELLOW}Please install tshark manually${NC}"
fi

# Install Python requirements
echo -e "\n${BLUE}🐍 Installing Python dependencies...${NC}"
if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt
    echo -e "${GREEN}✓ Python dependencies installed${NC}"
else
    echo -e "${YELLOW}⚠️  requirements.txt not found${NC}"
    echo -e "${BLUE}Installing rich library...${NC}"
    pip3 install rich
fi

# Configure tshark for non-root users (optional)
echo -e "\n${BLUE}🔧 Configuring tshark...${NC}"
if [ "$OS" != "termux" ]; then
    echo -e "${YELLOW}Allow non-root users to capture packets? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        usermod -a -G wireshark $SUDO_USER 2>/dev/null || echo -e "${YELLOW}Note: You may need to logout and login again${NC}"
        chmod +x /usr/bin/dumpcap 2>/dev/null
        setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap 2>/dev/null
        echo -e "${GREEN}✓ Configured for non-root capture${NC}"
    fi
fi

# Make the script executable
if [ -f DPI.py ]; then
    chmod +x DPI.py
    echo -e "${GREEN}✓ Made DPI.py executable${NC}"
fi

# Success message
echo -e "\n${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Installation Complete! 🎉             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo -e "\n${CYAN}To run the DPI Network Monitor:${NC}"
echo -e "${YELLOW}sudo python3 DPI.py${NC}"
echo -e "\n${BLUE}Telegram: @Mr_BOOND${NC}"
