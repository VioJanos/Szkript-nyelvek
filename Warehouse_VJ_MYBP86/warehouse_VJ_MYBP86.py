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
