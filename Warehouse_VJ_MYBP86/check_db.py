import sqlite3

conn = sqlite3.connect('warehouse_VJ_mybp86.db')
cursor = conn.cursor()

# Check switch_groups table structure
cursor.execute("PRAGMA table_info(switch_groups)")
columns = cursor.fetchall()
print("Switch_groups table columns:", columns)

# Try to select from switch_groups table
try:
    cursor.execute("SELECT * FROM switch_groups LIMIT 5")
    items = cursor.fetchall()
    print("Switch groups in database:", items)
except Exception as e:
    print("Error selecting from switch_groups:", e)

conn.close()