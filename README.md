# WiFi Sprite - Advanced WiFi Security Analyzer

🛡️ **Professional-grade network security analysis tool designed for South Africa's unique cybersecurity landscape**

A comprehensive, ethical cybersecurity tool that detects fake access points, honeypots, and network vulnerabilities commonly found in South African networks.

## 🎯 Purpose

WiFi Sprite provides advanced network security analysis to protect users from sophisticated threats including ESP32-based fake access points, DNS hijacking, and network surveillance - specifically targeting threats prevalent in South Africa.

**Key Benefits:**
- 🔒 **Defensive Security**: Protects against network-based attacks
- 📚 **Educational**: Learn about real-world cybersecurity threats
- 🌍 **Localized**: Designed for South African threat landscape
- ⚖️ **Ethical**: Completely passive and legal analysis

## ✨ Features

### 🔍 **Simple Security Tests**
- **WiFi Encryption Analysis**: WEP/WPA/WPA2/WPA3 detection
- **Network Risk Assessment**: Color-coded threat levels
- **Captive Portal Detection**: Identifies potentially malicious portals
- **Basic Security Recommendations**: User-friendly guidance

### 🚀 **Advanced Security Tests**
- **🕵️ Honeypot Detection**: Detects ESP32 fake access points and network traps
- **🌐 Host Discovery**: Identifies suspicious devices on the network
- **🔐 SSL/TLS Analysis**: Certificate validation and MITM detection
- **🌍 DNS Security Testing**: DNS hijacking and manipulation detection
- **🔓 Port Security Scanning**: Identifies dangerous open ports and services

### 🛡️ **Safe Scan Mode** *(NEW)*
- **🔍 Passive Network Discovery**: Finds nearby open networks WITHOUT connecting
- **⚡ ESP32/Arduino Detection**: Identifies DIY honeypot devices by signature
- **🚨 Quarantined Analysis**: Analyzes network safety before any connection
- **📊 Risk Scoring**: 0-100 safety score with detailed recommendations
- **🛡️ Zero-Risk Assessment**: Complete analysis without network exposure

### 🎨 **Professional Interface**
- **Dark Theme**: Modern, professional appearance
- **Colored Reports**: Syntax-highlighted security analysis
- **Tabbed Interface**: Simple vs Advanced testing modes
- **Real-time Status**: Dynamic progress and risk indicators

## 🚀 Quick Start

### **Option 1: One-Click Install (Recommended)**
```bash
# Clone the repository
git clone https://github.com/your-username/wifi-sprite.git
cd wifi-sprite

# Run the installer
install.bat
```

### **Option 2: Manual Setup**
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python src/main.py
```

### **Option 3: Direct Run**
```bash
# Quick start without installation
run.bat
```

## 📋 Requirements

- **Windows 10/11** (optimized for Windows networking)
- **Python 3.7+** with pip
- **Network Access** (WiFi connection required for testing)
- **Administrator Privileges** (for advanced network scanning)

## 🛡️ Security Analysis Capabilities

### **Threat Detection**
- **Fake Access Points**: ESP32-based honeypots common in SA
- **DNS Manipulation**: Hijacking and redirection attacks
- **SSL Interception**: Man-in-the-middle certificate attacks
- **Port Vulnerabilities**: Dangerous services and backdoors
- **Network Surveillance**: Traffic monitoring detection

### **Risk Assessment**
- 🚨 **DANGEROUS**: Do not connect - likely honeypot/fake AP
- ⚠️ **SUSPICIOUS**: Use extreme caution - multiple risk indicators
- ✅ **RELATIVELY SAFE**: Monitor connection - standard precautions
- 🔴 **CRITICAL**: Immediate disconnect required (connected networks)
- 🟠 **HIGH**: Dangerous - avoid sensitive activities
- 🟡 **MEDIUM**: Caution advised - use VPN
- 🟢 **LOW**: Generally safe with precautions
- 🟢 **MINIMAL**: Secure network

## 📊 Sample Advanced Report

```
============================================================
ADVANCED WIFI SECURITY ANALYSIS REPORT
============================================================
Network: FreeWiFi_Hotspot
Scan Time: 2024-01-15 14:30:22

🔴 CRITICAL RISK LEVEL: CRITICAL
Risk Score: 95/100

HONEYPOT DETECTION ANALYSIS
------------------------------
🚨 POTENTIAL HONEYPOT DETECTED (Confidence: 85%)

Suspicious Indicators:
  • ESP32 device detected as gateway
  • No actual internet connectivity
  • DNS returns fake responses
  • Artificially consistent response times

NETWORK PORT SECURITY ANALYSIS
-----------------------------------
🚨 DANGEROUS PORTS DETECTED:
  🚨 Port 23 - Telnet (CRITICAL RISK)
     Unencrypted remote access - sends passwords in plain text
     Potential Threats:
       • Password interception
       • Complete system compromise

SECURITY RECOMMENDATIONS:
----------------------------
  🚨 CRITICAL: Potential honeypot detected - disconnect immediately
  🚨 Do not enter any personal information or credentials
  🚨 Report this network to local authorities if suspicious
```

## 🔧 Technical Architecture

```
src/
├── main.py                     # Main GUI application
└── scripts/
    ├── network_scanner.py      # WiFi network detection
    ├── security_analyzer.py    # Basic security analysis
    ├── honeypot_detector.py    # Advanced honeypot detection
    ├── host_scanner.py         # Network host discovery
    ├── ssl_analyzer.py         # SSL/TLS security analysis
    ├── dns_analyzer.py         # DNS security testing
    ├── port_scanner.py         # Port security scanning
    └── report_generator.py     # Report generation
```

## 🌍 South African Context

### **Common Threats Detected**
- **Shopping Mall WiFi Traps**: Fake hotspots in retail areas
- **Coffee Shop Honeypots**: Malicious networks in public spaces
- **Airport/Hotel Scams**: Credential harvesting networks
- **ESP32 Devices**: Low-cost fake access point hardware

### **Localized Features**
- **ISP Detection**: Identifies major SA internet providers
- **DNS Server Analysis**: Tests against local DNS providers
- **Regulatory Compliance**: Aligns with POPIA privacy requirements

## ⚖️ Legal & Ethical Use

### ✅ **Permitted Uses**
- Testing networks you own or have permission to test
- Educational cybersecurity learning
- Defensive security assessment
- Personal network safety verification

### ❌ **Prohibited Uses**
- Unauthorized network penetration testing
- Attacking or compromising networks
- Violating others' privacy or network policies
- Any illegal cybersecurity activities

## 🤝 Contributing

We welcome contributions that enhance the educational and defensive security value:

1. **Ethical Focus**: All features must be passive and educational
2. **South African Relevance**: Consider local threat landscape
3. **User Safety**: Prioritize user protection and privacy
4. **Code Quality**: Follow Python best practices

## 📄 License

This project is licensed for educational and defensive security purposes. Users must comply with local laws and network policies.

## ⚠️ Disclaimer

WiFi Sprite is designed exclusively for educational and defensive cybersecurity purposes. Users are responsible for ensuring compliance with applicable laws, including South African cybersecurity regulations. The tool performs only passive analysis and does not attempt to compromise or attack networks.

**Use responsibly. Protect yourself and others.**