"""
Test script for network device location functionality
"""
import os
import sys

# Path hozzáadása a modulok eléréséhez
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database_VJ_MYBP86 import (
    get_available_locations_MYBP86, 
    validate_location_MYBP86,
    add_network_device_MYBP86,
    get_database_stats_MYBP86
)

DB_PATH = "warehouse_VJ_mybp86.db"

def test_location_features():
    print("=== Location Features Test ===")
    
    # Available locations
    locations = get_available_locations_MYBP86(DB_PATH)
    print(f"Available locations: {locations}")
    
    # Test validation
    test_locations = ["A1", "B2", "C1", "X9", "Network Cabinet"]
    for loc in test_locations:
        is_valid = validate_location_MYBP86(DB_PATH, loc)
        print(f"Location '{loc}' valid: {is_valid}")
    
    # Test adding device with valid location
    print("\nTesting device creation with valid location:")
    success = add_network_device_MYBP86(
        DB_PATH, 
        device_type="PDU",
        hostname="test-pdu-a1",
        location="A1",
        port_count=12,
        ip_address="192.168.1.100",
        serial_number="TEST001"
    )
    print(f"Added device with valid location A1: {success}")
    
    # Test adding device with invalid location
    print("\nTesting device creation with invalid location:")
    success = add_network_device_MYBP86(
        DB_PATH,
        device_type="Switch", 
        hostname="test-switch-x9",
        location="X9",
        port_count=24,
        ip_address="192.168.1.101",
        serial_number="TEST002"
    )
    print(f"Added device with invalid location X9: {success}")
    
    # Final stats
    stats = get_database_stats_MYBP86(DB_PATH)
    print(f"\nFinal database stats: {stats}")

if __name__ == "__main__":
    test_location_features()