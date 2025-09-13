from typing import Dict, List
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.risk_colors = {
            'HIGH': '#FF4444',
            'MEDIUM': '#FF8800', 
            'LOW': '#FFAA00',
            'MINIMAL': '#44AA44'
        }
    
    def generate_summary_report(self, network_info: Dict, analysis: Dict) -> str:
        """Generate a user-friendly summary report"""
        risk_level = analysis['overall_risk']
        risk_score = analysis['risk_score']
        
        report = f"""
=== WiFi Security Analysis Report ===
Network: {network_info.get('ssid', 'Unknown')}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERALL SECURITY RATING: {risk_level}
Risk Score: {risk_score}/100

{self._get_risk_explanation(risk_level)}

--- ENCRYPTION ANALYSIS ---
{self._format_encryption_analysis(analysis['encryption_analysis'])}

--- NETWORK CHARACTERISTICS ---
{self._format_network_analysis(analysis['network_analysis'])}

--- SECURITY ISSUES FOUND ---
{self._format_security_issues(analysis['security_issues'])}

--- RECOMMENDATIONS ---
{self._format_recommendations(analysis['recommendations'])}

--- EDUCATIONAL INFORMATION ---
{self._get_educational_content(risk_level)}
"""
        return report
    
    def _get_risk_explanation(self, risk_level: str) -> str:
        """Provide educational explanation of risk level"""
        explanations = {
            'HIGH': '🔴 HIGH RISK: This network poses significant security threats. Your data could be easily intercepted.',
            'MEDIUM': '🟡 MEDIUM RISK: This network has security concerns. Use with caution and additional protection.',
            'LOW': '🟠 LOW RISK: This network has minor security issues but is generally acceptable with precautions.',
            'MINIMAL': '🟢 MINIMAL RISK: This network appears secure, but general security practices still apply.'
        }
        return explanations.get(risk_level, 'Unknown risk level')
    
    def _format_encryption_analysis(self, encryption_analysis: Dict) -> str:
        """Format encryption analysis for report"""
        encryption_type = encryption_analysis.get('type', 'Unknown')
        strength = encryption_analysis.get('strength', 'Unknown')
        description = encryption_analysis.get('description', 'No description available')
        
        return f"""
Encryption Type: {encryption_type}
Security Strength: {strength}
Description: {description}
"""
    
    def _format_network_analysis(self, network_analysis: Dict) -> str:
        """Format network analysis for report"""
        suspicious = network_analysis.get('suspicious_naming', False)
        signal_info = network_analysis.get('signal_analysis', {})
        
        result = f"Suspicious Naming: {'Yes' if suspicious else 'No'}\n"
        
        if signal_info:
            result += f"Signal Strength: {signal_info.get('strength', 'Unknown')}\n"
            if 'risk' in signal_info:
                result += f"Signal Risk: {signal_info['risk']}\n"
        
        return result
    
    def _format_security_issues(self, issues: List[str]) -> str:
        """Format security issues list"""
        if not issues:
            return "✅ No major security issues detected"
        
        formatted_issues = []
        for i, issue in enumerate(issues, 1):
            formatted_issues.append(f"{i}. ⚠️  {issue}")
        
        return "\n".join(formatted_issues)
    
    def _format_recommendations(self, recommendations: List[str]) -> str:
        """Format recommendations list"""
        if not recommendations:
            return "No specific recommendations"
        
        formatted_recs = []
        for i, rec in enumerate(recommendations, 1):
            formatted_recs.append(f"{i}. 💡 {rec}")
        
        return "\n".join(formatted_recs)
    
    def _get_educational_content(self, risk_level: str) -> str:
        """Provide educational content based on risk level"""
        base_education = """
🎓 SECURITY EDUCATION:

What is WiFi Encryption?
- Encryption scrambles your data so others can't read it
- WPA3 is the newest and most secure standard
- WEP is very old and easily broken
- Open networks have no encryption at all

Why Use a VPN?
- Creates an encrypted tunnel for your data
- Protects you even on insecure networks
- Hides your browsing from network operators
- Essential for public WiFi safety

General WiFi Safety Tips:
- Always verify network names with venue staff
- Look for official network names (avoid "Free WiFi")
- Keep your devices updated with security patches
- Use HTTPS websites (look for the lock icon)
- Avoid sensitive activities on public networks
"""
        
        risk_specific = {
            'HIGH': """
⚠️  CRITICAL SAFETY MEASURES:
- This network is extremely dangerous for any sensitive activity
- Hackers can easily see all your unencrypted data
- Banking, email, and shopping should be avoided completely
- If you must use it, connect through a VPN first
""",
            'MEDIUM': """
⚠️  IMPORTANT PRECAUTIONS:
- This network has security weaknesses
- Use a VPN before accessing any personal accounts
- Be extra cautious with sensitive information
- Monitor your accounts for unusual activity
""",
            'LOW': """
ℹ️  RECOMMENDED PRECAUTIONS:
- Network is relatively safe but not perfect
- VPN still recommended for sensitive activities
- Good for general browsing with HTTPS sites
- Verify this is the legitimate network
""",
            'MINIMAL': """
✅ GOOD SECURITY PRACTICES:
- Network appears well-secured
- VPN still recommended for maximum privacy
- Safe for most activities with normal precautions
- Continue following general security practices
"""
        }
        
        return base_education + risk_specific.get(risk_level, '')
    
    def generate_json_report(self, network_info: Dict, analysis: Dict) -> Dict:
        """Generate machine-readable JSON report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'network': network_info,
            'security_analysis': analysis,
            'summary': {
                'risk_level': analysis['overall_risk'],
                'risk_score': analysis['risk_score'],
                'safe_to_use': analysis['overall_risk'] in ['MINIMAL', 'LOW'],
                'requires_vpn': analysis['overall_risk'] in ['HIGH', 'MEDIUM'],
                'total_issues': len(analysis['security_issues'])
            }
        }