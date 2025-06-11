# PacketEye

# 🔍 DPI Network Monitor

A beautiful and powerful Deep Packet Inspector for network traffic monitoring with real-time analysis.

## ✨ Features

- 🎨 Beautiful colored terminal interface
- 📡 Real-time packet capture and analysis
- 🔍 DNS query/response monitoring
- 🔒 TLS SNI detection
- 🌐 HTTP host and response code tracking
- ⚠️ Traffic anomaly alerts
- 📁 Custom output file selection
- 📊 HTML report generation

## 📋 Requirements

### System Requirements
- Linux operating system (tested on Ubuntu, Kali, Termux)
- Python 3.7 or higher
- Root privileges for packet capture

### Required Software
1. **tshark** (part of Wireshark)
2. **Python libraries** (see requirements.txt)

## 🚀 Installation

### 1. Install tshark

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install tshark
```

**Fedora/RedHat:**
```bash
sudo dnf install wireshark-cli
```

**Arch Linux:**
```bash
sudo pacman -S wireshark-cli
```

**Termux (Android):**
```bash
pkg update
pkg install root-repo
pkg install tshark
```

### 2. Install Python Dependencies

```bash
git clone https://github.com/MrBOOND/PacketEye.git
cd PacketEye

# Install Python requirements
pip install -r requirements.txt
```

###  Usage

```bash
sudo python3 DPI.py
```

### Features During Execution

1. **Output File Selection**: 
   - You'll be prompted to enter a custom filename
   - Press Enter to use default `network_logs.txt`
   - Supports paths like `logs/my_capture.txt`

2. **Real-time Monitoring**:
   - DNS queries and responses
   - TLS Server Name Indication (SNI)
   - HTTP hosts and response codes
   - Traffic flow analysis

3. **Alerts**:
   - Automatic detection of high-traffic flows
   - Visual alerts for anomalies

### Output Files

The script generates two output files:
- **Text log**: Your chosen filename (default: `network_logs.txt`)
- **HTML report**: `network_report.html` with formatted results

## 🛡️ Security Notes

- ⚠️ This tool requires root privileges for packet capture
- 🔴 Running as root is highlighted with security warnings
- 📡 Only captures traffic on the detected network interface

## 🎨 Interface Features

- **Gradient banner** with animated effects
- **Color-coded output** for different packet types:
  - 🔵 Cyan: DNS queries
  - 🔷 Bright Cyan: DNS responses
  - 🟢 Green: TLS SNI
  - 🟣 Magenta: HTTP hosts
  - 🔴 Red: HTTP errors (4xx, 5xx)
  - 🟡 Yellow: Warnings and alerts

## 🔧 Troubleshooting

### "arptype 519 not supported" Warning
This is normal on some interfaces. The tool automatically falls back to cooked socket mode.

### Permission Denied and termux 
Make sure to run with sudo:
```bash
sudo python3 DPI.py
```

### tshark Not Found
Install tshark using your package manager (see Installation section).

## 📝 License

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations.

## 👨‍💻 Author

- **0x1ez**
- Telegram: **@Mr_BOOND**

---

**Note**: Use responsibly and only on networks you own or have permission to monitor.
