"""Test shelf content display"""
from warehouse_VJ_MYBP86 import StorageMYBP86

store = StorageMYBP86('warehouse_VJ_mybp86.db', ['BOX', 'SWITCH', 'PDU', 'OTHER'])

print("=== Shelf Contents Test ===")

# Test occupancy
occ = store.occupancy_MYBP86()
print("Occupancy by shelf:", occ)

# Test items in A1
items_a1 = store.get_items_by_location_MYBP86('A', 1)
print(f"\nItems in A1 ({len(items_a1)} items):")
for item in items_a1:
    print(f"  - {item.get('name', 'N/A')} ({item.get('type', 'N/A')})")
    print(f"    Description: {item.get('description', 'No description')}")

# Test items in A2
items_a2 = store.get_items_by_location_MYBP86('A', 2)
print(f"\nItems in A2 ({len(items_a2)} items):")
for item in items_a2:
    print(f"  - {item.get('name', 'N/A')} ({item.get('type', 'N/A')})")
    print(f"    Description: {item.get('description', 'No description')}")