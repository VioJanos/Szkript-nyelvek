"""
Database management module for Warehouse & Network Equipment Management System
Handles all database operations including initialization, CRUD operations, and sample data
"""

import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime


def init_db_MYBP86(db_path: str) -> None:
    """Initialize the database with all required tables."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Create cabinets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cabinets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)
        
        # Create items table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                cabinet TEXT NOT NULL,
                shelf TEXT NOT NULL,
                position INTEGER NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create network_devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_type TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                mac_address TEXT,
                serial_number TEXT,
                model TEXT,
                location TEXT,
                port_count INTEGER,
                status TEXT DEFAULT 'active',
                description TEXT,
                switch_group TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create switch_groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS switch_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                location TEXT NOT NULL,
                group_name TEXT NOT NULL,
                max_switches INTEGER NOT NULL DEFAULT 6,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(location, group_name)
            )
        """)
        
        # Check if switch_group column exists, if not add it
        cursor.execute("PRAGMA table_info(network_devices)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'switch_group' not in columns:
            cursor.execute("""
                ALTER TABLE network_devices 
                ADD COLUMN switch_group TEXT
            """)
            print("Added switch_group column to network_devices table")
        
        conn.commit()
        print(f"Database initialized successfully at {db_path}")


def add_cabinet_MYBP86(db_path: str, name: str) -> bool:
    """Add a new cabinet to the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO cabinets (name) VALUES (?)", (name,))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False


def list_cabinets_MYBP86(db_path: str) -> List[str]:
    """Get all cabinet names from the database."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM cabinets ORDER BY name")
        return [row[0] for row in cursor.fetchall()]


def add_item_MYBP86(db_path: str, name: str, item_type: str, cabinet: str, 
                    shelf: str, position: int, description: str = "") -> bool:
    """Add a new item to the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO items (name, type, cabinet, shelf, position, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, item_type, cabinet, shelf, position, description))
            conn.commit()
            return True
    except sqlite3.Error:
        return False


def get_items_MYBP86(db_path: str) -> List[Dict[str, Any]]:
    """Get all items from the database."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, type, cabinet, shelf, position, description, created_at
            FROM items ORDER BY cabinet, shelf, position
        """)
        columns = ['id', 'name', 'type', 'cabinet', 'shelf', 'position', 'description', 'created_at']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def remove_item_MYBP86(db_path: str, item_id: int) -> bool:
    """Remove an item from the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM items WHERE id = ?", (item_id,))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error:
        return False


def add_network_device_MYBP86(db_path: str, device_type: str, hostname: str, 
                              ip_address: str = "", mac_address: str = "", 
                              serial_number: str = "", model: str = "", 
                              location: str = "", port_count: int = 0, 
                              status: str = "active", description: str = "",
                              switch_group: str = "") -> bool:
    """Add a new network device to the database with location validation."""
    
    # Validate location if provided
    if location and not validate_location_MYBP86(db_path, location):
        print(f"Error: Invalid location '{location}'. Available locations: {get_available_locations_MYBP86(db_path)}")
        return False
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO network_devices 
                (device_type, hostname, ip_address, mac_address, serial_number, 
                 model, location, port_count, status, description, switch_group, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (device_type, hostname, ip_address, mac_address, serial_number, 
                  model, location, port_count, status, description, switch_group))
            conn.commit()
            return True
    except sqlite3.Error as e:
        print(f"Error adding network device: {e}")
        return False


def get_network_devices_MYBP86(db_path: str, device_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get network devices from the database, optionally filtered by type."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        if device_type:
            cursor.execute("""
                SELECT id, device_type, hostname, ip_address, mac_address, serial_number,
                       model, location, port_count, status, description, switch_group, 
                       created_at, updated_at
                FROM network_devices WHERE device_type = ?
                ORDER BY hostname
            """, (device_type,))
        else:
            cursor.execute("""
                SELECT id, device_type, hostname, ip_address, mac_address, serial_number,
                       model, location, port_count, status, description, switch_group,
                       created_at, updated_at
                FROM network_devices
                ORDER BY device_type, hostname
            """)
        
        columns = ['id', 'device_type', 'hostname', 'ip_address', 'mac_address', 
                  'serial_number', 'model', 'location', 'port_count', 'status', 
                  'description', 'switch_group', 'created_at', 'updated_at']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def update_network_device_MYBP86(db_path: str, device_id: int, **kwargs) -> bool:
    """Update a network device in the database."""
    if not kwargs:
        return False
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Build the SET clause dynamically
            set_clauses = []
            values = []
            for key, value in kwargs.items():
                if key in ['device_type', 'hostname', 'ip_address', 'mac_address', 
                          'serial_number', 'model', 'location', 'port_count', 
                          'status', 'description']:
                    set_clauses.append(f"{key} = ?")
                    values.append(value)
            
            if not set_clauses:
                return False
            
            set_clauses.append("updated_at = CURRENT_TIMESTAMP")
            values.append(device_id)
            
            query = f"UPDATE network_devices SET {', '.join(set_clauses)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Error updating network device: {e}")
        return False


def remove_network_device_MYBP86(db_path: str, device_id: int) -> bool:
    """Remove a network device from the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM network_devices WHERE id = ?", (device_id,))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error:
        return False


def populate_sample_data_MYBP86(db_path: str) -> None:
    """Populate the database with sample data for testing and demonstration."""
    
    # Check if sample data already exists
    stats = get_database_stats_MYBP86(db_path)
    if stats.get('items', 0) > 0 or stats.get('network_devices', 0) > 0:
        print("Sample data already exists in database. Skipping population.")
        return
    
    # Sample cabinets
    sample_cabinets = ["A", "B", "C", "D"]
    
    # Sample warehouse items including stack containers
    sample_items = [
        ("Server Dell R740", "BOX", "A", "1", 1, "Dell PowerEdge R740 server"),
        ("Network Switch Cisco", "SWITCH", "A", "1", 2, "Cisco Catalyst 2960-X switch"),
        ("PDU APC 12-port", "PDU", "A", "2", 1, "APC Rack PDU with 12 outlets"),
        ("Server HP ProLiant", "BOX", "B", "1", 1, "HP ProLiant DL380 Gen10"),
        ("Firewall FortiGate", "OTHER", "B", "1", 2, "FortiGate 60F firewall appliance"),
        ("UPS APC Smart", "OTHER", "B", "2", 1, "APC Smart-UPS 1500VA"),
        ("Cable Bundle Cat6", "OTHER", "C", "1", 1, "Cat6 Ethernet cables bundle"),
        ("Patch Panel 24-port", "OTHER", "C", "1", 2, "24-port Cat6 patch panel"),
        # Sample stacks that will be used as locations for network devices
        ("Core PDU Stack", "PDU STACK", "A", "3", 1, "Main PDU stack for core equipment - Max 24 outlets"),
        ("Access PDU Stack", "PDU STACK", "B", "3", 1, "PDU stack for access equipment - Max 16 outlets"),
        ("Core Switch Stack", "SWITCH STACK", "C", "3", 1, "Main switch stack for core networking - Max 48 ports"),
        ("Access Switch Stack", "SWITCH STACK", "D", "1", 1, "Switch stack for access layer - Max 24 ports"),
        ("Management Switch Stack", "SWITCH STACK", "D", "2", 1, "Switch stack for management - Max 24 ports"),
    ]
    
    # Sample network devices - using stack names as locations
    sample_network_devices = [
        # PDUs placed in PDU stacks
        ("PDU", "pdu-core-main", "192.168.1.10", "00:C0:B7:12:34:56", "SN12345001", 
         "APC AP8659", "Core PDU Stack", 24, "active", "Main PDU for core equipment"),
        ("PDU", "pdu-core-backup", "192.168.1.11", "00:C0:B7:12:34:57", "SN12345002", 
         "APC AP8659", "Core PDU Stack", 24, "active", "Backup PDU for core equipment"),
        ("PDU", "pdu-access-main", "192.168.1.12", "00:C0:B7:12:34:58", "SN12345003", 
         "APC AP8631", "Access PDU Stack", 16, "active", "Main PDU for access equipment"),
        
        # Switches in switch stacks
        ("Switch", "sw-core-primary", "192.168.1.20", "00:1B:21:AB:CD:EF", "SN56789001", 
         "Cisco Catalyst 2960-X", "Core Switch Stack", 48, "active", "Primary core switch"),
        ("Switch", "sw-core-secondary", "192.168.1.21", "00:1B:21:AB:CD:F0", "SN56789002", 
         "Cisco Catalyst 2960-X", "Core Switch Stack", 48, "active", "Secondary core switch"),
        ("Switch", "sw-access-floor1", "192.168.1.22", "00:1B:21:AB:CD:F1", "SN56789003", 
         "Cisco Catalyst 2960-X", "Access Switch Stack", 24, "active", "Access switch for floor 1"),
        ("Switch", "sw-mgmt-primary", "192.168.100.10", "00:1B:21:AB:CD:F2", "SN56789004", 
         "Cisco Catalyst 2960-CX", "Management Switch Stack", 24, "active", "Primary management switch"),
    ]
    
    print("Populating database with sample data...")
    
    # Add cabinets
    for cabinet in sample_cabinets:
        add_cabinet_MYBP86(db_path, cabinet)
    
    # Add warehouse items
    for item in sample_items:
        add_item_MYBP86(db_path, *item)
    
    # Add network devices
    for device in sample_network_devices:
        add_network_device_MYBP86(db_path, *device)
    
    print(f"✅ Sample data added successfully!")
    print(f"   - {len(sample_cabinets)} cabinets")
    print(f"   - {len(sample_items)} warehouse items") 
    print(f"   - {len(sample_network_devices)} network devices")


def clear_sample_data_MYBP86(db_path: str) -> None:
    """Clear all data from the database (except cabinet structure)."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM network_devices")
        cursor.execute("DELETE FROM items")
        # Keep cabinets A-D but remove any extras
        cursor.execute("DELETE FROM cabinets WHERE name NOT IN ('A', 'B', 'C', 'D')")
        conn.commit()
        print("✅ Sample data cleared successfully!")


def get_available_locations_MYBP86(db_path: str) -> List[str]:
    """Get all available stack locations where network devices can be placed."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Get all stack names from warehouse items
        cursor.execute("""
            SELECT DISTINCT name FROM items 
            WHERE type IN ('SWITCH STACK', 'PDU STACK')
            ORDER BY name
        """)
        
        locations = []
        for (name,) in cursor.fetchall():
            locations.append(name)
        
        return locations


def validate_location_MYBP86(db_path: str, location: str) -> bool:
    """Validate if a location is available for network devices (must be a stack name)."""
    available_locations = get_available_locations_MYBP86(db_path)
    return location in available_locations


def get_database_stats_MYBP86(db_path: str) -> Dict[str, int]:
    """Get statistics about the database contents."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        stats = {}
        
        # Count cabinets
        cursor.execute("SELECT COUNT(*) FROM cabinets")
        stats['cabinets'] = cursor.fetchone()[0]
        
        # Count items
        cursor.execute("SELECT COUNT(*) FROM items")
        stats['items'] = cursor.fetchone()[0]
        
        # Count network devices
        cursor.execute("SELECT COUNT(*) FROM network_devices")
        stats['network_devices'] = cursor.fetchone()[0]
        
        # Count by device type
        cursor.execute("SELECT device_type, COUNT(*) FROM network_devices GROUP BY device_type")
        for device_type, count in cursor.fetchall():
            stats[f'{device_type.lower()}s'] = count
        
        return stats


def add_switch_group_MYBP86(db_path: str, location: str, group_name: str, 
                           max_switches: int = 6, description: str = "") -> bool:
    """Add a new switch group to the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO switch_groups (location, group_name, max_switches, description)
                VALUES (?, ?, ?, ?)
            """, (location, group_name, max_switches, description))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        # Group already exists at this location
        return False
    except sqlite3.Error:
        return False


def get_switch_groups_MYBP86(db_path: str) -> List[Dict[str, Any]]:
    """Get all switch groups from the database."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, location, group_name, max_switches, description, created_at
            FROM switch_groups ORDER BY location, group_name
        """)
        columns = ['id', 'location', 'group_name', 'max_switches', 'description', 'created_at']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def delete_switch_group_MYBP86(db_path: str, location: str, group_name: str) -> bool:
    """Delete a switch group from the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # First check if there are any switches in this group
            cursor.execute("""
                SELECT COUNT(*) FROM network_devices
                WHERE device_type = 'Switch' AND location = ? AND switch_group = ?
            """, (location, group_name))
            
            count = cursor.fetchone()[0]
            if count > 0:
                return False  # Cannot delete group with switches
            
            # Delete the group
            cursor.execute("""
                DELETE FROM switch_groups
                WHERE location = ? AND group_name = ?
            """, (location, group_name))
            
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error:
        return False


def get_switches_in_group_MYBP86(db_path: str, location: str, group_name: str) -> List[Dict[str, Any]]:
    """Get all switches in a specific group."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, device_type, hostname, ip_address, mac_address, serial_number,
                   model, location, port_count, status, description, switch_group,
                   created_at, updated_at
            FROM network_devices
            WHERE device_type = 'Switch' AND location = ? AND switch_group = ?
            ORDER BY hostname
        """, (location, group_name))
        
        columns = ['id', 'device_type', 'hostname', 'ip_address', 'mac_address', 
                  'serial_number', 'model', 'location', 'port_count', 'status', 
                  'description', 'switch_group', 'created_at', 'updated_at']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_available_groups_for_location_MYBP86(db_path: str, location: str) -> List[Dict[str, Any]]:
    """Get all available switch groups for a specific location that have capacity."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sg.location, sg.group_name, sg.max_switches, sg.description,
                   COUNT(nd.id) as current_switches
            FROM switch_groups sg
            LEFT JOIN network_devices nd ON (
                sg.location = nd.location AND 
                sg.group_name = nd.switch_group AND 
                nd.device_type = 'Switch'
            )
            WHERE sg.location = ?
            GROUP BY sg.location, sg.group_name, sg.max_switches, sg.description
            HAVING COUNT(nd.id) < sg.max_switches
            ORDER BY sg.group_name
        """, (location,))
        
        columns = ['location', 'group_name', 'max_switches', 'description', 'current_switches']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


if __name__ == "__main__":
    # Test the database functions
    test_db = "test_warehouse.db"
    print("Testing database functions...")
    
    init_db_MYBP86(test_db)
    populate_sample_data_MYBP86(test_db)
    
    stats = get_database_stats_MYBP86(test_db)
    print("\nDatabase Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")