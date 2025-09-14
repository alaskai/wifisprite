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
        """Get information about currently connected network"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, check=True)
            
            network_info = {
                'ssid': 'Unknown',
                'bssid': 'Unknown', 
                'authentication': 'Unknown',
                'encryption': 'Unknown',
                'signal_strength': 0,
                'channel': 0
            }
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'SSID' in line and ':' in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid:
                        network_info['ssid'] = ssid
                elif 'BSSID' in line and ':' in line:
                    network_info['bssid'] = line.split(':', 1)[1].strip()
                elif 'Signal' in line:
                    signal = re.search(r'(\d+)%', line)
                    if signal:
                        network_info['signal_strength'] = int(signal.group(1))
                elif 'Channel' in line:
                    channel = re.search(r'(\d+)', line.split(':', 1)[1])
                    if channel:
                        network_info['channel'] = int(channel.group(1))
                elif 'Authentication' in line:
                    network_info['authentication'] = line.split(':', 1)[1].strip()
                elif 'Cipher' in line:
                    network_info['encryption'] = line.split(':', 1)[1].strip()
            
            return network_info if network_info['ssid'] != 'Unknown' else None
            
        except subprocess.CalledProcessError:
            return None