import sqlite3
from typing import Dict, List, Optional, Sequence


SHELVES_MYBP86: range = range(1, 7)


def _connect_MYBP86(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db_MYBP86(db_path: str) -> None:
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS cabinets ("
            "  name TEXT PRIMARY KEY"
            ")"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS items ("
            "  id TEXT PRIMARY KEY,"
            "  cabinet TEXT NOT NULL,"
            "  shelf INTEGER NOT NULL,"
            "  type TEXT NOT NULL,"
            "  FOREIGN KEY(cabinet) REFERENCES cabinets(name)"
            "    ON DELETE CASCADE ON UPDATE CASCADE"
            ")"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_items_loc "
            "ON items(cabinet, shelf)"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_items_type ON items(type)")
        
        # Hálózati eszközök táblája
        cur.execute(
            "CREATE TABLE IF NOT EXISTS network_devices ("
            "  serial_number TEXT PRIMARY KEY,"
            "  hostname TEXT NOT NULL,"
            "  ip_address TEXT NOT NULL,"
            "  mac_address TEXT NOT NULL,"
            "  device_type TEXT NOT NULL,"
            "  manufacturer TEXT,"
            "  model TEXT,"
            "  firmware_version TEXT,"
            "  location TEXT,"
            "  status TEXT DEFAULT 'offline',"
            "  port_count INTEGER,"
            "  outlet_count INTEGER,"
            "  notes TEXT,"
            "  created_at TEXT,"
            "  updated_at TEXT"
            ")"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_devices_type "
            "ON network_devices(device_type)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_devices_location "
            "ON network_devices(location)"
        )
        
        con.commit()


def db_add_cabinet_MYBP86(db_path: str, name: str) -> None:
    cab = name.strip().upper()
    if not cab:
        raise ValueError("Cabinet name must not be empty.")
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute("INSERT OR IGNORE INTO cabinets(name) VALUES(?)", (cab,))
        con.commit()


def db_list_cabinets_MYBP86(db_path: str) -> List[str]:
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute("SELECT name FROM cabinets ORDER BY name")
        return [r[0] for r in cur.fetchall()]


def db_get_items_by_location_MYBP86(
    db_path: str,
    cabinet: str,
    shelf: int,
) -> List[Dict[str, str]]:
    cab = cabinet.strip().upper()
    if shelf not in SHELVES_MYBP86:
        raise ValueError("Shelf must be between 1 and 6.")
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute(
            "SELECT id, type FROM items "
            "WHERE cabinet = ? AND shelf = ? "
            "ORDER BY id",
            (cab, shelf),
        )
        return [{"id": r[0], "type": r[1]} for r in cur.fetchall()]


def _next_index_for_type_MYBP86(
    items: List[Dict[str, str]],
    type_name: str,
) -> int:
    max_n = 0
    prefix = type_name.upper()
    for it in items:
        if it.get("type", "").upper() == prefix:
            tail = it.get("id", "").split(prefix)[-1]
            try:
                n = int(tail)
                if n > max_n:
                    max_n = n
            except Exception:
                continue
    return max_n + 1


def generate_id_MYBP86(
    customer_code: str,
    location: str,
    type_name: str,
    items_here: List[Dict[str, str]],
) -> str:
    idx = _next_index_for_type_MYBP86(items_here, type_name)
    return f"{customer_code}-{location}-{type_name.upper()}{idx}"


def db_add_item_MYBP86(
    db_path: str,
    cabinet: str,
    shelf: int,
    type_name: str,
    customer_code: str = "TES",
) -> str:
    cab = cabinet.strip().upper()
    if shelf not in SHELVES_MYBP86:
        raise ValueError("Shelf must be between 1 and 6.")
    typ = type_name.strip().upper()
    items = db_get_items_by_location_MYBP86(db_path, cab, shelf)
    loc = f"{cab}{shelf}"
    new_id = generate_id_MYBP86(customer_code, loc, typ, items)
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute("INSERT OR IGNORE INTO cabinets(name) VALUES(?)", (cab,))
        cur.execute(
            "INSERT INTO items(id, cabinet, shelf, type) VALUES(?, ?, ?, ?)",
            (new_id, cab, shelf, typ),
        )
        con.commit()
    return new_id


def db_occupancy_MYBP86(db_path: str) -> Dict[str, int]:
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute(
            "SELECT cabinet, shelf, COUNT(*) "
            "FROM items GROUP BY cabinet, shelf"
        )
        res: Dict[str, int] = {}
        for cab, shelf, cnt in cur.fetchall():
            res[f"{cab}{shelf}"] = int(cnt)
        return res


def db_type_breakdown_MYBP86(db_path: str) -> Dict[str, int]:
    with _connect_MYBP86(db_path) as con:
        cur = con.cursor()
        cur.execute("SELECT type, COUNT(*) FROM items GROUP BY type")
        return {t: int(c) for t, c in cur.fetchall()}


class StorageMYBP86:
    def __init__(
        self,
        db_path: str,
        allowed_types: Optional[Sequence[str]] = None,
    ):
        self.db_path = db_path
        self.allowed_types = (
            [t.upper() for t in allowed_types]
            if allowed_types else None
        )
        init_db_MYBP86(self.db_path)

    def add_cabinet_MYBP86(self, name: str) -> None:
        db_add_cabinet_MYBP86(self.db_path, name)

    def list_cabinets_MYBP86(self) -> List[str]:
        return db_list_cabinets_MYBP86(self.db_path)

    def add_item_MYBP86(
        self,
        cabinet: str,
        shelf: int,
        type_name: str,
        customer_code: str = "TES",
    ) -> str:
        typ = type_name.upper()
        if self.allowed_types and typ not in self.allowed_types:
            raise ValueError(f"Type '{typ}' is not allowed.")
        return db_add_item_MYBP86(
            self.db_path,
            cabinet,
            shelf,
            typ,
            customer_code,
        )

    def get_items_by_location_MYBP86(
        self,
        cabinet: str,
        shelf: int,
    ) -> List[Dict[str, str]]:
        return db_get_items_by_location_MYBP86(self.db_path, cabinet, shelf)

    def occupancy_summary_MYBP86(self) -> Dict[str, int]:
        return db_occupancy_MYBP86(self.db_path)

    def type_breakdown_MYBP86(self) -> Dict[str, int]:
        return db_type_breakdown_MYBP86(self.db_path)

    # Hálózati eszköz kezelő metódusok
    def add_network_device_MYBP86(self, device_data: Dict) -> None:
        """Hálózati eszköz hozzáadása az adatbázishoz"""
        with _connect_MYBP86(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO network_devices ("
                "serial_number, hostname, ip_address, mac_address, "
                "device_type, manufacturer, model, firmware_version, "
                "location, status, port_count, outlet_count, notes, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    device_data['serial_number'],
                    device_data['hostname'],
                    device_data['ip_address'],
                    device_data['mac_address'],
                    device_data['device_type'],
                    device_data.get('manufacturer', ''),
                    device_data.get('model', ''),
                    device_data.get('firmware_version', ''),
                    device_data.get('location', ''),
                    device_data.get('status', 'offline'),
                    device_data.get('port_count'),
                    device_data.get('outlet_count'),
                    device_data.get('notes', ''),
                    device_data.get('created_at', ''),
                    device_data.get('updated_at', '')
                )
            )
            con.commit()

    def get_network_devices_MYBP86(self) -> List[Dict]:
        """Összes hálózati eszköz lekérdezése"""
        with _connect_MYBP86(self.db_path) as con:
            cur = con.cursor()
            cur.execute("SELECT * FROM network_devices ORDER BY hostname")
            rows = cur.fetchall()
            
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_network_devices_by_type_MYBP86(self, device_type: str) -> List[Dict]:
        """Hálózati eszközök lekérdezése típus szerint"""
        with _connect_MYBP86(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "SELECT * FROM network_devices WHERE device_type = ? ORDER BY hostname",
                (device_type,)
            )
            rows = cur.fetchall()
            
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_network_device_MYBP86(self, serial_number: str) -> Optional[Dict]:
        """Egy hálózati eszköz lekérdezése serial number alapján"""
        with _connect_MYBP86(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "SELECT * FROM network_devices WHERE serial_number = ?",
                (serial_number,)
            )
            row = cur.fetchone()
            
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
            return None

    def update_network_device_status_MYBP86(self, serial_number: str, 
                                           status: str, notes: str = "") -> None:
        """Hálózati eszköz állapotának frissítése"""
        from datetime import datetime
        
        with _connect_MYBP86(self.db_path) as con:
            cur = con.cursor()
            
            # Jelenlegi notes lekérdezése
            cur.execute(
                "SELECT notes FROM network_devices WHERE serial_number = ?",
                (serial_number,)
            )
            result = cur.fetchone()
            current_notes = result[0] if result else ""
            
            # Új notes összeállítása
            if notes:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                new_notes = f"{current_notes}\n{timestamp}: {notes}".strip()
            else:
                new_notes = current_notes
            
            # Frissítés
            cur.execute(
                "UPDATE network_devices SET status = ?, notes = ?, updated_at = ? "
                "WHERE serial_number = ?",
                (status, new_notes, datetime.now().isoformat(), serial_number)
            )
            con.commit()

    def delete_network_device_MYBP86(self, serial_number: str) -> bool:
        """Hálózati eszköz törlése"""
        with _connect_MYBP86(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "DELETE FROM network_devices WHERE serial_number = ?",
                (serial_number,)
            )
            deleted = cur.rowcount > 0
            con.commit()
            return deleted
