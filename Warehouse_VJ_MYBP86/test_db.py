#!/usr/bin/env python3

"""
Test script to check database contents and load sample data functionality
"""

from database_VJ_MYBP86 import (
    get_database_stats_MYBP86,
    get_items_MYBP86,
    get_network_devices_MYBP86,
    populate_sample_data_MYBP86
)

DB_PATH = "warehouse_VJ_mybp86.db"

def test_database():
    print("=== Database Test ===")
    
    # Get stats
    stats = get_database_stats_MYBP86(DB_PATH)
    print(f"Database stats: {stats}")
    
    # Get items
    items = get_items_MYBP86(DB_PATH)
    print(f"\nItems ({len(items)}):")
    for item in items[:5]:  # Show first 5
        print(f"  {item.get('name', 'N/A')} - {item.get('type', 'N/A')} in {item.get('cabinet', 'N/A')}{item.get('shelf', 'N/A')}")
    
    # Get network devices
    devices = get_network_devices_MYBP86(DB_PATH)
    print(f"\nNetwork devices ({len(devices)}):")
    for device in devices[:5]:  # Show first 5
        print(f"  {device.get('hostname', 'N/A')} - {device.get('device_type', 'N/A')} at {device.get('location', 'N/A')}")

if __name__ == "__main__":
    test_database()