import subprocess
import re
import time
import socket
from typing import List, Dict, Optional
from scapy.all import *
import threading
import json

class SafeScanner:
    def __init__(self):
        self.discovered_networks = []
        self.quarantine_results = {}
        self.scanning = False
        
    def discover_nearby_networks(self, scan_duration=10) -> List[Dict]:
        """Passively discover nearby WiFi networks without connecting"""
        try:
            # Use netsh to scan for available networks
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True, check=True)
            
            # Get visible networks
            visible_result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                          capture_output=True, text=True, check=True)
            
            networks = self._parse_visible_networks()
            
            # Filter for open networks only
            open_networks = []
            for network in networks:
                if self._is_open_network(network):
                    network['scan_timestamp'] = time.time()
                    network['risk_level'] = 'UNKNOWN'
                    open_networks.append(network)
            
            self.discovered_networks = open_networks
            return open_networks
            
        except Exception as e:
            return []
    
    def _parse_visible_networks(self) -> List[Dict]:
        """Parse visible networks from netsh output"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True)
            
            networks = []
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line:
                    ssid = line.split(':')[1].strip()
                    network_info = self._get_network_security_info(ssid)
                    if network_info:
                        networks.append(network_info)
            
            return networks
        except:
            return []
    
    def _get_network_security_info(self, ssid: str) -> Optional[Dict]:
        """Get security information for a specific network"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profile', ssid], 
                                  capture_output=True, text=True)
            
            network = {
                'ssid': ssid,
                'security': 'Unknown',
                'authentication': 'Unknown',
                'encryption': 'None',
                'signal_strength': 0,
                'is_open': False
            }
            
            for line in result.stdout.split('\n'):
                if 'Authentication' in line:
                    auth = line.split(':')[1].strip()
                    network['authentication'] = auth
                    if 'Open' in auth:
                        network['is_open'] = True
                elif 'Cipher' in line:
                    network['encryption'] = line.split(':')[1].strip()
            
            return network
        except:
            return None
    
    def _is_open_network(self, network: Dict) -> bool:
        """Check if network is open (no password required)"""
        auth = network.get('authentication', '').lower()
        encryption = network.get('encryption', '').lower()
        
        return ('open' in auth or 
                'none' in encryption or 
                network.get('is_open', False))
    
    def analyze_network_safely(self, network: Dict) -> Dict:
        """Analyze network without connecting - quarantined analysis"""
        analysis = {
            'network': network,
            'risk_assessment': {},
            'honeypot_indicators': [],
            'esp32_indicators': [],
            'safety_score': 0,
            'recommendations': [],
            'quarantine_status': 'ANALYZING'
        }
        
        try:
            # Passive analysis without connection
            ssid_analysis = self._analyze_ssid_patterns(network['ssid'])
            analysis['ssid_analysis'] = ssid_analysis
            
            # Check for ESP32/Arduino indicators in SSID
            esp32_check = self._check_esp32_indicators(network)
            analysis['esp32_indicators'] = esp32_check
            
            # Analyze signal characteristics
            signal_analysis = self._analyze_signal_characteristics(network)
            analysis['signal_analysis'] = signal_analysis
            
            # Calculate safety score
            safety_score = self._calculate_safety_score(analysis)
            analysis['safety_score'] = safety_score
            
            # Generate recommendations
            recommendations = self._generate_safety_recommendations(analysis)
            analysis['recommendations'] = recommendations
            
            # Determine quarantine status
            if safety_score < 30:
                analysis['quarantine_status'] = 'DANGEROUS - DO NOT CONNECT'
            elif safety_score < 60:
                analysis['quarantine_status'] = 'SUSPICIOUS - USE EXTREME CAUTION'
            else:
                analysis['quarantine_status'] = 'RELATIVELY SAFE - MONITOR'
            
            return analysis
            
        except Exception as e:
            analysis['error'] = str(e)
            analysis['quarantine_status'] = 'ANALYSIS FAILED'
            return analysis
    
    def _analyze_ssid_patterns(self, ssid: str) -> Dict:
        """Analyze SSID for suspicious patterns"""
        suspicious_patterns = [
            r'free.*wifi',
            r'public.*wifi', 
            r'guest.*network',
            r'.*hotspot.*',
            r'linksys',
            r'netgear',
            r'dlink',
            r'esp32',
            r'arduino',
            r'nodemcu',
            r'wemos'
        ]
        
        honeypot_patterns = [
            r'starbucks.*wifi',
            r'mcdonalds.*wifi',
            r'airport.*wifi',
            r'hotel.*wifi',
            r'.*_nomap'
        ]
        
        analysis = {
            'suspicious_matches': [],
            'honeypot_matches': [],
            'risk_score': 0
        }
        
        ssid_lower = ssid.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, ssid_lower):
                analysis['suspicious_matches'].append(pattern)
                analysis['risk_score'] += 15
        
        for pattern in honeypot_patterns:
            if re.search(pattern, ssid_lower):
                analysis['honeypot_matches'].append(pattern)
                analysis['risk_score'] += 25
        
        return analysis
    
    def _check_esp32_indicators(self, network: Dict) -> List[str]:
        """Check for ESP32/Arduino device indicators"""
        indicators = []
        ssid = network.get('ssid', '').lower()
        
        esp32_terms = ['esp32', 'arduino', 'nodemcu', 'wemos', 'esp8266']
        
        for term in esp32_terms:
            if term in ssid:
                indicators.append(f'ESP32/Arduino term in SSID: {term}')
        
        # Check for default ESP32 SSIDs
        default_patterns = [
            r'esp32-\w+',
            r'arduino-\w+',
            r'nodemcu-\w+'
        ]
        
        for pattern in default_patterns:
            if re.search(pattern, ssid):
                indicators.append(f'Default ESP32 SSID pattern: {pattern}')
        
        return indicators
    
    def _analyze_signal_characteristics(self, network: Dict) -> Dict:
        """Analyze signal strength and characteristics"""
        signal = network.get('signal_strength', 0)
        
        analysis = {
            'strength_category': 'Unknown',
            'risk_factors': []
        }
        
        if signal > 80:
            analysis['strength_category'] = 'Very Strong'
            analysis['risk_factors'].append('Unusually strong signal - device may be very close')
        elif signal > 60:
            analysis['strength_category'] = 'Strong'
        elif signal > 40:
            analysis['strength_category'] = 'Moderate'
        else:
            analysis['strength_category'] = 'Weak'
            analysis['risk_factors'].append('Weak signal - connection may be unstable')
        
        return analysis
    
    def _calculate_safety_score(self, analysis: Dict) -> int:
        """Calculate overall safety score (0-100, higher is safer)"""
        score = 70  # Start with neutral score
        
        # Deduct for suspicious SSID patterns
        ssid_risk = analysis.get('ssid_analysis', {}).get('risk_score', 0)
        score -= ssid_risk
        
        # Deduct for ESP32 indicators
        esp32_count = len(analysis.get('esp32_indicators', []))
        score -= (esp32_count * 20)
        
        # Deduct for signal anomalies
        signal_risks = len(analysis.get('signal_analysis', {}).get('risk_factors', []))
        score -= (signal_risks * 10)
        
        return max(0, min(100, score))
    
    def _generate_safety_recommendations(self, analysis: Dict) -> List[str]:
        """Generate safety recommendations based on analysis"""
        recommendations = []
        safety_score = analysis.get('safety_score', 0)
        
        if safety_score < 30:
            recommendations.extend([
                '🚨 DO NOT CONNECT - High risk of honeypot/fake AP',
                'This network shows multiple suspicious indicators',
                'Consider reporting to local authorities if in public space',
                'Use mobile data instead'
            ])
        elif safety_score < 60:
            recommendations.extend([
                '⚠️ HIGH CAUTION - Suspicious network characteristics detected',
                'If you must connect, use VPN immediately',
                'Avoid any sensitive activities',
                'Monitor for unusual behavior',
                'Disconnect immediately if anything seems wrong'
            ])
        else:
            recommendations.extend([
                '✅ Relatively safe but still use standard precautions',
                'Enable VPN before connecting',
                'Verify network legitimacy with venue staff',
                'Use HTTPS websites only',
                'Monitor connection for anomalies'
            ])
        
        # Add specific recommendations based on findings
        if analysis.get('esp32_indicators'):
            recommendations.append('🔍 ESP32/Arduino device detected - likely DIY/hobbyist setup')
        
        return recommendations
    
    def capture_handshake_safely(self, network: Dict, timeout=30) -> Dict:
        """Safely capture handshake without connecting"""
        # Note: This is a placeholder for handshake capture
        # In practice, this would require monitor mode and packet capture
        return {
            'handshake_captured': False,
            'reason': 'Handshake capture requires monitor mode - not implemented for safety',
            'alternative': 'Using passive analysis instead'
        }
    
    def get_quarantine_report(self, network: Dict) -> str:
        """Generate detailed quarantine report"""
        analysis = self.analyze_network_safely(network)
        
        report = f"""
=== SAFE SCAN QUARANTINE REPORT ===
Network: {network.get('ssid', 'Unknown')}
Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
Quarantine Status: {analysis.get('quarantine_status', 'Unknown')}

SAFETY SCORE: {analysis.get('safety_score', 0)}/100

RISK ANALYSIS:
"""
        
        # Add SSID analysis
        ssid_analysis = analysis.get('ssid_analysis', {})
        if ssid_analysis.get('suspicious_matches'):
            report += f"⚠️ Suspicious SSID patterns: {', '.join(ssid_analysis['suspicious_matches'])}\n"
        
        if ssid_analysis.get('honeypot_matches'):
            report += f"🚨 Potential honeypot patterns: {', '.join(ssid_analysis['honeypot_matches'])}\n"
        
        # Add ESP32 indicators
        esp32_indicators = analysis.get('esp32_indicators', [])
        if esp32_indicators:
            report += f"\n🔍 ESP32/Arduino Indicators:\n"
            for indicator in esp32_indicators:
                report += f"  • {indicator}\n"
        
        # Add recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            report += f"\nRECOMMendations:\n"
            for rec in recommendations:
                report += f"  {rec}\n"
        
        report += f"\n=== END QUARANTINE REPORT ===\n"
        
        return report