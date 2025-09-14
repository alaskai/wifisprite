import subprocess
import re
import json
from typing import List, Dict, Optional

class NetworkScanner:
    def __init__(self):
        self.networks = []
    
    def scan_wifi_networks(self) -> List[Dict]:
        """Scan for available WiFi networks using netsh (Windows)"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True, check=True)
            
            profiles = []
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    profiles.append(profile_name)
            
            networks = []
            for profile in profiles:
                network_info = self._get_network_details(profile)
                if network_info:
                    networks.append(network_info)
            
            # Also scan for visible networks
            visible_networks = self._scan_visible_networks()
            networks.extend(visible_networks)
            
            self.networks = networks
            return networks
            
        except subprocess.CalledProcessError:
            return self._scan_visible_networks()
    
    def _get_network_details(self, profile_name: str) -> Optional[Dict]:
        """Get detailed information about a specific network profile"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile_name, 'key=clear'], 
                                  capture_output=True, text=True, check=True)
            
            network_info = {
                'ssid': profile_name,
                'security': 'Unknown',
                'authentication': 'Unknown',
                'encryption': 'Unknown',
                'signal_strength': 0,
                'channel': 0
            }
            
            for line in result.stdout.split('\n'):
                if 'Security key' in line:
                    network_info['has_password'] = 'Present' in line
                elif 'Authentication' in line:
                    network_info['authentication'] = line.split(':')[1].strip()
                elif 'Cipher' in line:
                    network_info['encryption'] = line.split(':')[1].strip()
            
            return network_info
            
        except subprocess.CalledProcessError:
            return None
    
    def _scan_visible_networks(self) -> List[Dict]:
        """Scan for currently visible WiFi networks"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, check=True)
            
            networks = []
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'SSID' in line and ':' in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid:
                        current_network['ssid'] = ssid
                elif 'Signal' in line:
                    signal = re.search(r'(\d+)%', line)
                    if signal:
                        current_network['signal_strength'] = int(signal.group(1))
                elif 'Radio type' in line:
                    current_network['radio_type'] = line.split(':', 1)[1].strip()
                elif 'Authentication' in line:
                    current_network['authentication'] = line.split(':', 1)[1].strip()
                elif 'Cipher' in line:
                    current_network['encryption'] = line.split(':', 1)[1].strip()
            
            if current_network.get('ssid'):
                networks.append(current_network)
            
            return networks
            
        except subprocess.CalledProcessError:
            return []
    
    def get_current_network(self) -> Optional[Dict]:
        """Get comprehensive information about currently connected network"""
        try:
            # Get interface details
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, check=True)
            
            network_info = {
                'ssid': 'Unknown',
                'bssid': 'Unknown', 
                'authentication': 'Unknown',
                'encryption': 'Unknown',
                'signal_strength': 0,
                'channel': 0,
                'radio_type': 'Unknown',
                'receive_rate': 'Unknown',
                'transmit_rate': 'Unknown'
            }
            
            current_ssid = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'Name' in line and 'Wi-Fi' in line:
                    continue
                elif 'State' in line and 'connected' not in line.lower():
                    return None  # Not connected
                elif 'SSID' in line and ':' in line and 'BSSID' not in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid and ssid != '':
                        network_info['ssid'] = ssid
                        current_ssid = ssid
                elif 'BSSID' in line and ':' in line:
                    bssid = line.split(':', 1)[1].strip()
                    if bssid:
                        network_info['bssid'] = bssid
                elif 'Radio type' in line:
                    network_info['radio_type'] = line.split(':', 1)[1].strip()
                elif 'Authentication' in line:
                    auth = line.split(':', 1)[1].strip()
                    if auth and auth != '':
                        network_info['authentication'] = auth
                elif 'Cipher' in line:
                    cipher = line.split(':', 1)[1].strip()
                    if cipher and cipher != '':
                        network_info['encryption'] = cipher
                elif 'Signal' in line:
                    signal = re.search(r'(\d+)%', line)
                    if signal:
                        network_info['signal_strength'] = int(signal.group(1))
                elif 'Channel' in line:
                    channel = re.search(r'(\d+)', line)
                    if channel:
                        network_info['channel'] = int(channel.group(1))
                elif 'Receive rate' in line:
                    network_info['receive_rate'] = line.split(':', 1)[1].strip()
                elif 'Transmit rate' in line:
                    network_info['transmit_rate'] = line.split(':', 1)[1].strip()
            
            # Get additional profile details if SSID found
            if current_ssid and current_ssid != 'Unknown':
                try:
                    profile_result = subprocess.run(['netsh', 'wlan', 'show', 'profile', current_ssid, 'key=clear'], 
                                                  capture_output=True, text=True)
                    
                    # Extract authentication and encryption from profile if not found in interface
                    for line in profile_result.stdout.split('\n'):
                        line = line.strip()
                        if 'Authentication' in line and network_info['authentication'] == 'Unknown':
                            auth = line.split(':', 1)[1].strip()
                            if auth and auth != '':
                                network_info['authentication'] = auth
                        elif 'Cipher' in line and network_info['encryption'] == 'Unknown':
                            cipher = line.split(':', 1)[1].strip()
                            if cipher and cipher != '':
                                network_info['encryption'] = cipher
                        elif 'Security key' in line and 'Present' in line:
                            network_info['has_password'] = True
                        elif 'Security key' in line and 'Absent' in line:
                            network_info['has_password'] = False
                        elif 'Key Content' in line:
                            # Don't store the actual key for security
                            network_info['key_available'] = True
                except:
                    pass
            
            # Final fallback - try to determine encryption from authentication
            if network_info['encryption'] == 'Unknown' and network_info['authentication'] != 'Unknown':
                auth = network_info['authentication'].upper()
                if 'WPA3' in auth:
                    network_info['encryption'] = 'WPA3'
                elif 'WPA2' in auth:
                    network_info['encryption'] = 'WPA2'
                elif 'WPA' in auth:
                    network_info['encryption'] = 'WPA'
                elif 'WEP' in auth:
                    network_info['encryption'] = 'WEP'
                elif 'OPEN' in auth or 'NONE' in auth:
                    network_info['encryption'] = 'None'
            
            return network_info if network_info['ssid'] != 'Unknown' else None
            
        except subprocess.CalledProcessError:
            return None