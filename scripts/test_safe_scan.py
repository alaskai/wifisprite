#!/usr/bin/env python3
"""
Test script for Safe Scan functionality
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

from safe_scanner import SafeScanner

def test_safe_scanner():
    """Test the Safe Scanner functionality"""
    print("=== WiFi Sprite Safe Scanner Test ===\n")
    
    scanner = SafeScanner()
    
    # Test network discovery
    print("1. Testing network discovery...")
    networks = scanner.discover_nearby_networks()
    
    if networks:
        print(f"Found {len(networks)} open networks:")
        for i, network in enumerate(networks, 1):
            print(f"  {i}. {network.get('ssid', 'Unknown')} - {network.get('authentication', 'Unknown')}")
        
        # Test analysis on first network
        if networks:
            print(f"\n2. Testing analysis on: {networks[0].get('ssid', 'Unknown')}")
            analysis = scanner.analyze_network_safely(networks[0])
            
            print(f"Safety Score: {analysis.get('safety_score', 0)}/100")
            print(f"Status: {analysis.get('quarantine_status', 'Unknown')}")
            
            # Generate report
            print("\n3. Generating quarantine report...")
            report = scanner.get_quarantine_report(networks[0])
            print(report)
    else:
        print("No open networks found for testing.")
        
        # Test with mock network
        print("\n2. Testing with mock ESP32 network...")
        mock_network = {
            'ssid': 'ESP32-FreeWiFi',
            'authentication': 'Open',
            'encryption': 'None',
            'signal_strength': 85,
            'is_open': True
        }
        
        analysis = scanner.analyze_network_safely(mock_network)
        print(f"Safety Score: {analysis.get('safety_score', 0)}/100")
        print(f"Status: {analysis.get('quarantine_status', 'Unknown')}")
        
        report = scanner.get_quarantine_report(mock_network)
        print(report)

if __name__ == "__main__":
    test_safe_scanner()