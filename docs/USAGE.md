# Usage Guide

Complete guide to using WiFi Sprite - Advanced WiFi Security Analyzer for network security assessment.

---

## ▶️ Running the Application

### **Quick Launch**
```bash
# Method 1: Double-click the batch file
run.bat

# Method 2: Command line execution
python src/main.py

# Method 3: System command (if installed)
wifi-sprite
```

### **Administrator Mode (Recommended)**
```bash
# Right-click Command Prompt → "Run as Administrator"
# Then execute any of the above commands
```

---

## 🖥️ How to Use

### **Basic Workflow**

#### **Step 1: Connect to WiFi Network**
1. Ensure your computer is connected to the WiFi network you want to test
2. Launch WiFi Sprite application
3. The current network will be displayed in the "Current Network" section

#### **Step 2: Choose Test Type**
- **Simple Test Tab**: Quick basic security analysis (30 seconds)
- **Advanced Test Tab**: Comprehensive security testing (1-3 minutes)

#### **Step 3: Run Security Analysis**
1. Click "Run Basic Security Scan" or "Run Advanced Security Scan"
2. Wait for the analysis to complete (progress bar will show activity)
3. Review the colored security report in the results area

#### **Step 4: Interpret Results**
- **🔴 CRITICAL/HIGH**: Disconnect immediately - network is dangerous
- **🟠 MEDIUM**: Use caution - enable VPN, avoid sensitive activities
- **🟡 LOW**: Generally safe with precautions
- **🟢 MINIMAL**: Secure network - safe to use

#### **Step 5: Save Reports**
1. Click "Save Report" or "Save Technical Report"
2. Reports saved as both .txt (human-readable) and .json (machine-readable)
3. Files saved with timestamp in current directory

---

## 🔍 Simple Test Features

### **What It Tests**
- ✅ **WiFi Encryption**: WEP/WPA/WPA2/WPA3 detection
- ✅ **Network Security**: Basic risk assessment
- ✅ **Captive Portal**: Public network detection
- ✅ **Signal Analysis**: Connection quality evaluation

### **Sample Simple Test Output**
```
=== WiFi Security Analysis Report ===
Network: CoffeeShop_Guest
Scan Time: 2024-01-15 14:30:22

🟠 MEDIUM RISK: Use caution on this network

--- ENCRYPTION ANALYSIS ---
Encryption Type: WPA2
Security Strength: GOOD
Description: Modern encryption with good security

--- RECOMMENDATIONS ---
💡 Use HTTPS websites when possible
💡 Enable VPN for sensitive activities
💡 Avoid banking on public networks
```

---

## 🚀 Advanced Test Features

### **Available Tests** (Check/Uncheck as needed)
- ✅ **Honeypot Detection**: Detects ESP32 fake access points (RECOMMENDED)
- ✅ **Network Host Discovery**: Finds devices on the network
- ✅ **SSL/Certificate Analysis**: Validates website security
- ✅ **DNS Security Testing**: Checks for DNS hijacking
- ✅ **Port Security Scanning**: Identifies dangerous open ports

### **Advanced Test Process**
1. **Select Tests**: Check desired security tests
2. **Start Scan**: Click "Run Advanced Security Scan"
3. **Monitor Progress**: Status updates show current test phase
4. **Review Results**: Comprehensive technical report generated

### **Sample Advanced Test Output**
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

NETWORK PORT SECURITY ANALYSIS
-----------------------------------
🚨 DANGEROUS PORTS DETECTED:
  🚨 Port 23 - Telnet (CRITICAL RISK)
     Unencrypted remote access
     Potential Threats:
       • Password interception
       • Complete system compromise

SECURITY RECOMMENDATIONS:
----------------------------
  🚨 CRITICAL: Disconnect immediately
  🚨 Do not enter personal information
  🚨 Report to authorities if suspicious
```

---

## 🎯 Specific Use Cases

### **Public WiFi Safety Check**
```
Scenario: Coffee shop, airport, hotel WiFi
1. Connect to public WiFi
2. Run "Simple Test" first
3. If MEDIUM+ risk, run "Advanced Test"
4. Follow security recommendations
```

### **Home Network Security Audit**
```
Scenario: Testing your own WiFi security
1. Connect to home WiFi
2. Run "Advanced Test" with all options
3. Review port scanning results
4. Secure any dangerous services found
```

### **Suspicious Network Investigation**
```
Scenario: Network seems fake or malicious
1. DO NOT enter any credentials
2. Run "Advanced Test" with Honeypot Detection
3. If honeypot detected, disconnect immediately
4. Report to local authorities if needed
```

### **Corporate Network Assessment**
```
Scenario: Office WiFi security check
1. Ensure you have permission to test
2. Run "Advanced Test" during off-hours
3. Document findings for IT department
4. Follow responsible disclosure practices
```

---

## 📊 Understanding Reports

### **Risk Levels Explained**
- **CRITICAL** 🔴: Network is actively malicious - disconnect now
- **HIGH** 🔴: Serious vulnerabilities - avoid sensitive activities
- **MEDIUM** 🟠: Some risks present - use VPN and caution
- **LOW** 🟡: Minor issues - generally safe with precautions
- **MINIMAL** 🟢: Secure network - safe for normal use

### **Color-Coded Text**
- **Red Text**: Critical threats and immediate actions
- **Orange Text**: High-risk issues requiring attention
- **Yellow Text**: Medium-risk warnings and cautions
- **Green Text**: Safe conditions and positive findings
- **Blue Text**: Informational content and headers
- **White Text**: General report content

### **Report Sections**
1. **Network Information**: SSID, encryption, signal strength
2. **Risk Assessment**: Overall security rating and score
3. **Test Results**: Detailed findings from each security test
4. **Recommendations**: Specific actions to improve security
5. **Technical Details**: Advanced information for IT professionals

---

## 🎥 Demo

Check out the comprehensive demonstrations:
- [Demo Video](../demo/demo.mp4) - Complete walkthrough of all features
- [Demo Presentation](../demo/demo.pptx) - Technical overview and use cases
- [Demo Overview](../demo/OVERVIEW.md) - Written summary of capabilities

---

## ⚙️ Advanced Configuration

### **Customizing Scans**
```python
# Modify timeout values in scripts/port_scanner.py
timeout = 1  # Seconds per port (increase for slower networks)

# Customize port lists in scripts/port_scanner.py
common_ports = [21, 22, 23, 25, 53, 80, ...]  # Add/remove ports

# Adjust DNS servers in scripts/dns_analyzer.py
dns_servers = ['1.1.1.1', '8.8.8.8', ...]  # Add preferred DNS servers
```

### **Report Customization**
- **Text Reports**: Human-readable format for sharing
- **JSON Reports**: Machine-readable for automation
- **Timestamp Format**: Automatic dating for organization
- **File Location**: Saved in current working directory

---

## 🔧 Troubleshooting Usage Issues

### **"No Network Detected"**
- Ensure WiFi is connected and active
- Try disconnecting and reconnecting to WiFi
- Check Windows network settings

### **Scan Takes Too Long**
- Use "Simple Test" for faster results
- Close other network applications
- Check internet connection speed

### **Permission Errors**
- Run as Administrator (required for advanced scanning)
- Check Windows Firewall settings
- Ensure antivirus isn't blocking Python

### **Incomplete Results**
- Some tests may fail on restricted networks
- Corporate firewalls may block certain scans
- Try different test combinations

---

## 📌 Important Notes

### **Legal & Ethical Usage**
- ⚖️ **Only test networks you own or have permission to test**
- ⚖️ **Respect local cybersecurity laws and regulations**
- ⚖️ **Use for educational and defensive purposes only**
- ⚖️ **Report malicious networks to appropriate authorities**

### **Safety Recommendations**
- 🛡️ **Never enter credentials on suspicious networks**
- 🛡️ **Disconnect immediately if honeypot detected**
- 🛡️ **Use VPN on any public or untrusted networks**
- 🛡️ **Keep WiFi Sprite updated for latest threat detection**

### **Performance Tips**
- 💡 **Run as Administrator for full functionality**
- 💡 **Close bandwidth-heavy applications during scanning**
- 💡 **Use wired connection for testing WiFi networks when possible**
- 💡 **Save reports regularly for security documentation**

### **South African Context**
- 🌍 **Common in shopping malls, airports, coffee shops**
- 🌍 **ESP32-based fake access points are prevalent**
- 🌍 **Always verify network legitimacy with venue staff**
- 🌍 **Report suspicious networks to local cybersecurity authorities**

---

## 🆘 Emergency Procedures

### **If Honeypot Detected**
1. **Disconnect immediately** from the network
2. **Do not enter any personal information**
3. **Clear browser cache and cookies**
4. **Run antivirus scan on your device**
5. **Report to venue management and authorities**

### **If Credentials Compromised**
1. **Change all passwords immediately**
2. **Enable two-factor authentication**
3. **Monitor accounts for suspicious activity**
4. **Contact banks/financial institutions**
5. **Consider identity monitoring services**

---

## 📞 Getting Help

- **Documentation**: Complete guides in `docs/` folder
- **Issues**: Report bugs via GitHub Issues
- **Community**: Join discussions for tips and support
- **Updates**: Check GitHub releases for new features