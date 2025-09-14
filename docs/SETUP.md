# Setup Instructions

Follow the steps below to set up and run WiFi Sprite - Advanced WiFi Security Analyzer.

---

## 📦 Requirements

### **System Requirements**
- **Windows 10/11** (64-bit recommended)
- **Python 3.7+** with pip package manager
- **Administrator privileges** (required for network scanning)
- **Active WiFi connection** (for testing networks)

### **Hardware Requirements**
- **2GB RAM minimum** (4GB recommended)
- **100MB free disk space**
- **WiFi adapter** (built-in or USB)

### **Network Requirements**
- **WiFi connectivity** to test networks
- **Internet access** for dependency installation
- **No firewall blocking** Python network operations

---

## ⚙️ Installation

### **Option 1: Quick Install (Recommended)**
```bash
# Clone the repository
git clone https://github.com/your-username/wifi-sprite.git
cd wifi-sprite

# Run the automated installer (Windows)
install.bat
```

### **Option 2: Manual Installation**
```bash
# Clone the repository
git clone https://github.com/your-username/wifi-sprite.git
cd wifi-sprite

# Install Python dependencies
pip install -r requirements.txt

# Install as system utility (optional)
pip install -e .
```

### **Option 3: Development Setup**
```bash
# Clone for development
git clone https://github.com/your-username/wifi-sprite.git
cd wifi-sprite

# Create virtual environment (optional)
python -m venv wifi-sprite-env
wifi-sprite-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Running the Project

### **Method 1: Batch File (Easiest)**
```bash
# Double-click or run from command line
run.bat
```

### **Method 2: Python Direct**
```bash
# Run from project root
python src/main.py
```

### **Method 3: System Command (After Installation)**
```bash
# If installed as system utility
wifi-sprite
```

---

## 🔧 Configuration

### **First Run Setup**
1. **Connect to WiFi**: Ensure you're connected to a WiFi network
2. **Run as Administrator**: Right-click and "Run as Administrator" for full functionality
3. **Allow Firewall**: Accept any Windows Firewall prompts for Python

### **Advanced Configuration**
- **Timeout Settings**: Modify scan timeouts in `scripts/port_scanner.py`
- **Port Lists**: Customize dangerous ports in `scripts/port_scanner.py`
- **DNS Servers**: Update test DNS servers in `scripts/dns_analyzer.py`

---

## 🛠️ Troubleshooting

### **Common Issues**

#### **"No module named 'scapy'" Error**
```bash
# Install missing dependencies
pip install scapy psutil requests cryptography netifaces urllib3
```

#### **"Permission Denied" Errors**
```bash
# Run as Administrator
# Right-click Command Prompt → "Run as Administrator"
# Then run the application
```

#### **"No WiFi Networks Detected"**
- Ensure WiFi adapter is enabled
- Connect to a WiFi network first
- Check Windows WiFi settings

#### **Slow Scanning Performance**
- Close other network-intensive applications
- Reduce scan timeout values
- Use "Simple Test" mode for faster results

### **Dependency Issues**

#### **Scapy Installation Problems**
```bash
# For Windows, try:
pip install scapy[complete]

# Or install WinPcap alternative:
pip install winpcap-py
```

#### **SSL Certificate Errors**
```bash
# Update certificates
pip install --upgrade certifi requests urllib3
```

---

## 🔍 Verification

### **Test Installation**
```bash
# Quick test run
python src/main.py

# Should open GUI without errors
# Try "Simple Test" on current network
```

### **Feature Verification**
1. **Basic Scan**: Run Simple Test - should complete in 10-30 seconds
2. **Advanced Scan**: Run Advanced Test with all options - should complete in 1-3 minutes
3. **Report Generation**: Save a report - should create .txt and .json files
4. **GUI Functionality**: Test all buttons and tabs

---

## 📁 Project Structure

```
wifi-sprite/
├── src/
│   ├── main.py                 # Main GUI application
│   └── __init__.py
├── scripts/
│   ├── network_scanner.py      # Core network scanning
│   ├── security_analyzer.py    # Basic security analysis
│   ├── honeypot_detector.py    # Advanced honeypot detection
│   ├── host_scanner.py         # Network host discovery
│   ├── ssl_analyzer.py         # SSL/TLS security analysis
│   ├── dns_analyzer.py         # DNS security testing
│   ├── port_scanner.py         # Port security scanning
│   ├── advanced_report_generator.py # Advanced reporting
│   └── report_generator.py     # Basic report generation
├── docs/
│   ├── SETUP.md               # This file
│   ├── USAGE.md               # Usage instructions
│   └── ACKNOWLEDGEMENTS.md    # Third-party credits
├── requirements.txt           # Python dependencies
├── install.bat               # Windows installer
├── run.bat                   # Quick run script
└── README.md                 # Project overview
```

---

## 🚀 Quick Start Guide

### **5-Minute Setup**
1. **Download**: `git clone https://github.com/your-username/wifi-sprite.git`
2. **Install**: Double-click `install.bat`
3. **Run**: Double-click `run.bat`
4. **Test**: Click "Run Basic Security Scan"
5. **Analyze**: Review the colored security report

### **Advanced Usage**
1. **Switch to Advanced Tab**
2. **Select desired tests** (Honeypot Detection recommended)
3. **Click "Run Advanced Security Scan"**
4. **Wait 1-3 minutes** for comprehensive analysis
5. **Save technical report** for detailed findings

---

## 📞 Support

### **Getting Help**
- **Documentation**: Check `docs/USAGE.md` for detailed usage instructions
- **Issues**: Report bugs via GitHub Issues
- **Community**: Join discussions in GitHub Discussions

### **System Requirements Check**
```bash
# Verify Python version
python --version

# Check pip installation
pip --version

# Test network connectivity
ping google.com
```

---

## ⚠️ Important Notes

- **Administrator Rights**: Required for advanced network scanning
- **Antivirus Software**: May flag network scanning tools - add exception if needed
- **Network Policies**: Ensure compliance with local network usage policies
- **Educational Use**: Tool designed for learning and defensive security only
- **Legal Compliance**: Users responsible for following local cybersecurity laws

---

## 🔄 Updates

### **Keeping WiFi Sprite Updated**
```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade
```

### **Version Information**
- Check `src/__init__.py` for current version
- Review `CHANGELOG.md` for recent updates
- Monitor GitHub releases for new features