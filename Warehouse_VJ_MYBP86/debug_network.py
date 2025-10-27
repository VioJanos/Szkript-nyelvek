#!/usr/bin/env python3

"""
Debug script to test network device loading
"""

import os
import sys

# Path hozzáadása a network_equipment modul eléréséhez
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database_VJ_MYBP86 import get_network_devices_MYBP86
from Warehouse_VJ_MYBP86.network_equipment import PDU, Switch, NetworkManager

DB_PATH = "warehouse_VJ_mybp86.db"

def debug_network_loading():
    print("=== Network Device Loading Debug ===")
    
    # Get devices from database
    devices = get_network_devices_MYBP86(DB_PATH)
    print(f"Found {len(devices)} devices in database")
    
    network_manager = NetworkManager()
    
    for i, device_data in enumerate(devices[:3]):  # Show first 3
        print(f"\nDevice {i+1}:")
        print(f"  Type: {device_data['device_type']}")
        print(f"  Hostname: {device_data['hostname']}")
        print(f"  Port count: {device_data.get('port_count', 'N/A')}")
        print(f"  Model: {device_data.get('model', 'N/A')}")
        
        try:
            if device_data['device_type'] == 'PDU':
                pdu = PDU(
                    serial_number=device_data['serial_number'],
                    hostname=device_data['hostname'],
                    ip_address=device_data['ip_address'],
                    mac_address=device_data['mac_address'],
                    outlet_count=device_data.get('port_count', 8),
                    manufacturer="",
                    model=device_data.get('model', ''),
                    location=device_data.get('location', '')
                )
                network_manager.add_device(pdu)
                print(f"  ✅ PDU created successfully")
                
            elif device_data['device_type'] == 'Switch':
                switch = Switch(
                    serial_number=device_data['serial_number'],
                    hostname=device_data['hostname'],
                    ip_address=device_data['ip_address'],
                    mac_address=device_data['mac_address'],
                    port_count=device_data.get('port_count', 24),
                    manufacturer="",
                    model=device_data.get('model', ''),
                    location=device_data.get('location', '')
                )
                network_manager.add_device(switch)
                print(f"  ✅ Switch created successfully")
                
        except Exception as e:
            print(f"  ❌ Error creating device: {e}")
    
    print(f"\nNetworkManager stats:")
    print(f"  Total devices: {network_manager.device_count}")
    pdus = network_manager.get_devices_by_type('PDU')
    switches = network_manager.get_devices_by_type('Switch')
    print(f"  PDUs: {len(pdus)}")
    print(f"  Switches: {len(switches)}")

if __name__ == "__main__":
    debug_network_loading()