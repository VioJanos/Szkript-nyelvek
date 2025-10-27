"""
Warehouse management module - simplified version using database_VJ_MYBP86
Contains the StorageMYBP86 class and warehouse-specific logic
"""

from typing import Dict, List, Optional
from database_VJ_MYBP86 import (
    init_db_MYBP86,
    add_cabinet_MYBP86,
    list_cabinets_MYBP86,
    add_item_MYBP86,
    get_items_MYBP86,
    remove_item_MYBP86,
    get_network_devices_MYBP86,
    add_network_device_MYBP86,
    update_network_device_MYBP86,
    remove_network_device_MYBP86,
    populate_sample_data_MYBP86,
    get_database_stats_MYBP86,
    add_switch_group_MYBP86,
    get_switch_groups_MYBP86,
    delete_switch_group_MYBP86,
    get_switches_in_group_MYBP86,
    get_available_groups_for_location_MYBP86
)

# Shelf configuration
SHELVES_MYBP86: range = range(1, 7)


class StorageMYBP86:
    """
    Main storage management class for warehouse operations.
    Integrates with database backend for persistence.
    """

    def __init__(self, db_path: str,
                 allowed_types: Optional[List[str]] = None):
        """
        Initialize storage system.
        
        Args:
            db_path: Path to SQLite database file
            allowed_types: List of allowed item types (optional)
        """
        self.db_path = db_path
        self.allowed_types = (
            [t.upper() for t in allowed_types]
            if allowed_types else None
        )
        init_db_MYBP86(self.db_path)

    def add_cabinet_MYBP86(self, name: str) -> None:
        """Add a new cabinet to the system."""
        add_cabinet_MYBP86(self.db_path, name)

    def list_cabinets_MYBP86(self) -> List[str]:
        """Get list of all cabinets."""
        return list_cabinets_MYBP86(self.db_path)

    def get_items_by_location_MYBP86(self, cabinet: str,
                                     shelf: int) -> List[Dict]:
        """Get all items in a specific location."""
        cab = cabinet.strip().upper()
        all_items = get_items_MYBP86(self.db_path)
        return [
            item for item in all_items
            if (item.get('cabinet') == cab and
                str(item.get('shelf')) == str(shelf))
        ]

    def _next_index_for_type_MYBP86(self, item_type: str, cabinet: str,
                                    shelf: int) -> int:
        """Get the next available index for an item type in a location."""
        items = self.get_items_by_location_MYBP86(cabinet, shelf)
        max_index = 0
        prefix = item_type.upper()
        
        for item in items:
            if item.get('type', '').upper() == prefix:
                # Extract number from item name
                name = item.get('name', '')
                if name.startswith(prefix):
                    try:
                        # Get the number after the prefix
                        number_str = name[len(prefix):].split('_')[0]
                        number = int(number_str)
                        max_index = max(max_index, number)
                    except (ValueError, IndexError):
                        continue
        
        return max_index + 1

    def generate_id_MYBP86(self, item_type: str, cabinet: str,
                           shelf: int) -> str:
        """Generate unique ID for new item."""
        index = self._next_index_for_type_MYBP86(item_type, cabinet, shelf)
        return f"{item_type.upper()}_{index:03d}"

    def add_item_MYBP86(self, item_type: str, cabinet: str, shelf: int,
                        description: str = "", custom_name: str = "") -> Optional[str]:
        """Add a new item to the warehouse."""
        # Validate type if restrictions are set
        typ = item_type.upper()
        if self.allowed_types and typ not in self.allowed_types:
            raise ValueError(f"Type '{typ}' is not allowed.")
        
        # Validate shelf range
        if shelf not in SHELVES_MYBP86:
            raise ValueError("Shelf must be between 1 and 6.")
        
        # Use custom name if provided, otherwise generate unique ID
        if custom_name:
            item_id = custom_name
        else:
            item_id = self.generate_id_MYBP86(typ, cabinet, shelf)
        
        # Generate cabinet letter and ensure it exists
        cab = cabinet.strip().upper()
        if cab not in self.list_cabinets_MYBP86():
            self.add_cabinet_MYBP86(cab)
        
        # Calculate position in shelf
        position = len(self.get_items_by_location_MYBP86(cab, shelf)) + 1
        
        # Add to database
        success = add_item_MYBP86(
            self.db_path, item_id, item_type, cab, str(shelf), position,
            description
        )
        
        return item_id if success else None

    def occupancy_MYBP86(self) -> Dict[str, int]:
        """Get occupancy statistics by cabinet and shelf location (excluding network device types)."""
        all_items = get_items_MYBP86(self.db_path)
        occupancy = {}
        
        # Network device types should not be counted in warehouse occupancy
        network_device_types = ["SWITCH", "PDU", "ROUTER", "FIREWALL", "SERVER"]
        
        for item in all_items:
            item_type = item.get('type', '')
            if item_type not in network_device_types:
                cabinet = item.get('cabinet', '')
                shelf = item.get('shelf', '')
                location = f"{cabinet}{shelf}"
                occupancy[location] = occupancy.get(location, 0) + 1
        
        return occupancy

    def type_breakdown_MYBP86(self) -> Dict[str, int]:
        """Get breakdown of items by type (excluding network device types)."""
        all_items = get_items_MYBP86(self.db_path)
        breakdown = {}
        
        # Network device types should not be counted in warehouse type breakdown
        network_device_types = ["SWITCH", "PDU", "ROUTER", "FIREWALL", "SERVER"]
        
        for item in all_items:
            item_type = item.get('type', 'UNKNOWN')
            if item_type not in network_device_types:
                breakdown[item_type] = breakdown.get(item_type, 0) + 1
        
        return breakdown

    def get_items_MYBP86(self) -> List[Dict]:
        """Get all items from warehouse."""
        return get_items_MYBP86(self.db_path)

    def remove_item_MYBP86(self, item_id: str) -> bool:
        """Remove item from warehouse."""
        return remove_item_MYBP86(self.db_path, item_id)

    # Network device management methods
    def add_network_device_MYBP86(self, device_type: str, hostname: str,
                                  **kwargs) -> bool:
        """Add network device to database."""
        return add_network_device_MYBP86(self.db_path, device_type,
                                         hostname, **kwargs)

    def get_network_devices_MYBP86(self, device_type: Optional[str] = None
                                   ) -> List[Dict]:
        """Get network devices from database."""
        return get_network_devices_MYBP86(self.db_path, device_type)

    def update_network_device_MYBP86(self, serial_number: str,
                                     **kwargs) -> bool:
        """Update network device information."""
        return update_network_device_MYBP86(self.db_path, serial_number,
                                            **kwargs)

    def remove_network_device_MYBP86(self, serial_number: str) -> bool:
        """Remove network device from database."""
        return remove_network_device_MYBP86(self.db_path, serial_number)

    # Switch group management methods
    def add_switch_group_MYBP86(self, location: str, group_name: str,
                               max_switches: int = 6, description: str = "") -> bool:
        """Add a new switch group."""
        return add_switch_group_MYBP86(self.db_path, location, group_name,
                                     max_switches, description)

    def get_switch_groups_MYBP86(self) -> List[Dict]:
        """Get all switch groups."""
        return get_switch_groups_MYBP86(self.db_path)

    def delete_switch_group_MYBP86(self, location: str, group_name: str) -> bool:
        """Delete a switch group."""
        return delete_switch_group_MYBP86(self.db_path, location, group_name)

    def get_switches_in_group_MYBP86(self, location: str, group_name: str) -> List[Dict]:
        """Get all switches in a specific group."""
        return get_switches_in_group_MYBP86(self.db_path, location, group_name)

    def get_available_groups_for_location_MYBP86(self, location: str) -> List[Dict]:
        """Get available switch groups for a location that have capacity."""
        return get_available_groups_for_location_MYBP86(self.db_path, location)


# Export public interface
__all__ = [
    'StorageMYBP86',
    'SHELVES_MYBP86',
    'add_cabinet_MYBP86',
    'list_cabinets_MYBP86',
    'add_item_MYBP86',
    'get_items_MYBP86',
    'remove_item_MYBP86',
    'get_network_devices_MYBP86',
    'add_network_device_MYBP86',
    'update_network_device_MYBP86',
    'remove_network_device_MYBP86',
    'populate_sample_data_MYBP86',
    'get_database_stats_MYBP86'
]
