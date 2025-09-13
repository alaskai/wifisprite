# WiFi Sprite - WiFi Security Analyzer

A user-friendly, educational cybersecurity tool for analyzing WiFi network security safely and ethically.

## 🎯 Purpose

WiFi Sprite helps users understand the security risks of public WiFi networks through passive analysis and educational reporting. It's designed to be:

- **Safe**: Only passive scanning, no network attacks
- **Educational**: Clear explanations of security concepts
- **User-friendly**: Simple traffic light risk system
- **Ethical**: Defensive security tool only

## 🔍 Features

### Security Analysis
- **Encryption Detection**: Identifies WEP/WPA/WPA2/WPA3 encryption
- **Risk Assessment**: Color-coded security ratings (Red/Yellow/Green)
- **Network Characteristics**: Analyzes suspicious naming patterns
- **Captive Portal Detection**: Identifies public network indicators

### Educational Components
- **Plain Language Explanations**: No technical jargon
- **Risk Explanations**: Why something is dangerous
- **Actionable Recommendations**: What users should do
- **Security Education**: General WiFi safety tips

### User Interface
- **Simple GUI**: Easy-to-use graphical interface
- **Real-time Analysis**: Analyze current network connection
- **Detailed Reports**: Comprehensive security assessments
- **Export Functionality**: Save reports for reference

## 🚀 Installation

1. **Install Python 3.7+**
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the Application**:
   ```bash
   python main.py
   ```

## 📋 Requirements

- Windows 10/11 (uses netsh commands)
- Python 3.7 or higher
- Administrator privileges (for network scanning)

## 🛡️ Security Tests

### Passive Analysis Only
- Encryption type detection
- Signal strength measurement
- Network name pattern analysis
- Captive portal checking
- No active network attacks or intrusion

### Risk Factors Evaluated
- **Encryption Strength**: WEP (high risk) to WPA3 (low risk)
- **Network Naming**: Suspicious patterns like "Free WiFi"
- **Signal Characteristics**: Unusual signal strength patterns
- **Public Network Indicators**: Captive portals, open access

## 🎓 Educational Value

### Security Concepts Explained
- What WiFi encryption means
- Why VPNs are important
- How to identify secure networks
- General WiFi safety practices

### Risk Communication
- **High Risk**: Red - Avoid sensitive activities
- **Medium Risk**: Orange - Use VPN, be cautious
- **Low Risk**: Yellow - Generally safe with precautions
- **Minimal Risk**: Green - Secure network

## 📊 Sample Output

```
=== WiFi Security Analysis Report ===
Network: CoffeeShop_Guest
Scan Time: 2024-01-15 14:30:22

OVERALL SECURITY RATING: HIGH
Risk Score: 85/100

🔴 HIGH RISK: This network poses significant security threats.

--- ENCRYPTION ANALYSIS ---
Encryption Type: NONE
Security Strength: NONE
Description: Open network with no security

--- RECOMMENDATIONS ---
1. 💡 DO NOT use this network for sensitive activities
2. 💡 Use a VPN if you must connect
3. 💡 Avoid accessing banking, email, or personal accounts
4. 💡 Consider using mobile data instead
```

## ⚖️ Legal and Ethical Use

### Intended Use
- **Educational purposes**: Learning about WiFi security
- **Defensive security**: Protecting your own devices
- **Network assessment**: Evaluating networks you're authorized to use

### Prohibited Use
- **Unauthorized access**: Don't test networks without permission
- **Malicious activities**: No attacking or compromising networks
- **Privacy violations**: Respect others' network privacy

## 🔧 Technical Details

### Architecture
- **network_scanner.py**: WiFi network detection and information gathering
- **security_analyzer.py**: Risk assessment and vulnerability analysis
- **report_generator.py**: User-friendly report generation
- **main.py**: GUI application and user interface

### Dependencies
- **scapy**: Network packet analysis
- **psutil**: System and network utilities
- **requests**: HTTP requests for captive portal detection
- **tkinter**: GUI framework (built into Python)

## 🤝 Contributing

This is an educational tool focused on defensive security. Contributions should maintain the ethical, educational focus:

1. All features must be passive/non-intrusive
2. Include educational explanations
3. Maintain user-friendly design
4. Follow responsible disclosure practices

## 📄 License

This project is for educational purposes. Use responsibly and in accordance with local laws and network policies.

## ⚠️ Disclaimer

WiFi Sprite is designed for educational and defensive security purposes only. Users are responsible for ensuring their use complies with applicable laws and network policies. The tool performs only passive analysis and does not attempt to compromise or attack networks.