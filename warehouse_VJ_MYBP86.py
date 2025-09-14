import json
import sqlite3
from collections import defaultdict
from typing import Dict, List, Tuple


class StorageMYBP86:
    def __init__(self, cabinets: List[str] | None = None):
        self.data: Dict[str, List[Dict[str, str]]] = {}
        self.cabinets: List[str] = []
        if cabinets:
            for c in cabinets:
                self.add_cabinet_MYBP86(c)

    def add_cabinet_MYBP86(self, name: str) -> None:
        n = name.upper().strip()
        if n and n not in self.cabinets:
            self.cabinets.append(n)
        for s in range(1, 7):
            self.data.setdefault(f"{n}{s}", [])

    def list_cabinets_MYBP86(self) -> List[str]:
        if self.cabinets:
            return sorted(self.cabinets)
        c = set()
        for k in self.data.keys():
            if len(k) >= 2:
                c.add(k[:-1])
        self.cabinets = sorted(c) if c else []
        return self.cabinets

    def add_item_MYBP86(
        self,
        cabinet: str,
        shelf: int,
        type_name: str,
        customer_code: str = "TES"
    ) -> str:
        loc = f"{cabinet}{shelf}"
        items = self.data.setdefault(loc, [])
        new_id = generate_id_MYBP86(customer_code, loc, type_name, items)
        items.append({"id": new_id, "type": type_name.upper()})
        if cabinet not in self.cabinets:
            self.cabinets.append(cabinet)
        return new_id

    def occupancy_summary_MYBP86(self) -> Dict[str, int]:
        return {loc: len(items) for loc, items in self.data.items()}

    def type_breakdown_MYBP86(self) -> Dict[str, int]:
        c = defaultdict(int)
        for items in self.data.values():
            for it in items:
                c[it["type"].upper()] += 1
        return dict(c)


def load_data_MYBP86(path: str) -> Dict[str, List[Dict[str, str]]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
            return {k: list(v) for k, v in d.items()}
    except Exception:
        return {}


def save_data_MYBP86(path: str, data: Dict[str, List[Dict[str, str]]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _next_index_for_type_MYBP86(
    items: List[Dict[str, str]],
    type_name: str
) -> int:
    m = 0
    p = type_name.upper()
    for it in items:
        if it.get("type", "").upper() == p:
            tail = it.get("id", "").split(p)[-1]
            try:
                n = int(tail)
                if n > m:
                    m = n
            except Exception:
                pass
    return m + 1


def generate_id_MYBP86(
    customer_code: str,
    location: str,
    type_name: str,
    items_here: List[Dict[str, str]]
) -> str:
    idx = _next_index_for_type_MYBP86(items_here, type_name)
    return f"{customer_code}-{location}-{type_name.upper()}{idx}"


def parse_location_MYBP86(loc: str) -> Tuple[str, int]:
    i = len(loc) - 1
    while i >= 0 and loc[i].isdigit():
        i -= 1
    cab = loc[: i + 1]
    shelf = int(loc[i + 1:]) if i + 1 < len(loc) else 0
    return cab, shelf


def init_db_MYBP86(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS cabinets(name TEXT PRIMARY KEY)")
    cur.execute(
        "CREATE TABLE IF NOT EXISTS items("
        "id TEXT PRIMARY KEY, "
        "cabinet TEXT, "
        "shelf INTEGER, "
        "type TEXT)"
    )
    con.commit()
    con.close()


def db_add_cabinet_MYBP86(db_path: str, name: str) -> None:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO cabinets(name) VALUES(?)",
        (name.upper().strip(),)
    )
    con.commit()
    con.close()


def db_list_cabinets_MYBP86(db_path: str) -> List[str]:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT name FROM cabinets ORDER BY name")
    rows = [r[0] for r in cur.fetchall()]
    con.close()
    return rows


def db_get_items_by_location_MYBP86(
    db_path: str,
    cabinet: str,
    shelf: int
) -> List[Dict[str, str]]:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "SELECT id,type FROM items WHERE cabinet=? AND shelf=? ORDER BY id",
        (cabinet, shelf)
    )
    rows = [{"id": r[0], "type": r[1]} for r in cur.fetchall()]
    con.close()
    return rows


def db_add_item_MYBP86(
    db_path: str,
    cabinet: str,
    shelf: int,
    type_name: str,
    customer_code: str = "TES"
) -> str:
    items = db_get_items_by_location_MYBP86(db_path, cabinet, shelf)
    loc = f"{cabinet}{shelf}"
    new_id = generate_id_MYBP86(customer_code, loc, type_name, items)
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("INSERT OR IGNORE INTO cabinets(name) VALUES(?)", (cabinet,))
    cur.execute(
        "INSERT INTO items(id,cabinet,shelf,type) VALUES(?,?,?,?)",
        (new_id, cabinet, shelf, type_name.upper())
    )
    con.commit()
    con.close()
    return new_id


def db_load_all_MYBP86(db_path: str) -> Dict[str, List[Dict[str, str]]]:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT cabinet,shelf,id,type FROM items")
    d: Dict[str, List[Dict[str, str]]] = {}
    for cab, shelf, idv, typ in cur.fetchall():
        loc = f"{cab}{shelf}"
        d.setdefault(loc, []).append({"id": idv, "type": typ})
    con.close()
    return d


def db_occupancy_MYBP86(db_path: str) -> Dict[str, int]:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "SELECT cabinet,shelf,COUNT(*) "
        "FROM items GROUP BY cabinet,shelf"
    )
    res = {}
    for cab, shelf, cnt in cur.fetchall():
        res[f"{cab}{shelf}"] = int(cnt)
    con.close()
    return res


def db_type_breakdown_MYBP86(db_path: str) -> Dict[str, int]:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT type,COUNT(*) FROM items GROUP BY type")
    d = {t: int(c) for t, c in cur.fetchall()}
    con.close()
    return d


def db_clear_MYBP86(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("DELETE FROM items")
    cur.execute("DELETE FROM cabinets")
    con.commit()
    con.close()


def sync_json_to_sql_MYBP86(
    db_path: str,
    data: Dict[str, List[Dict[str, str]]]
) -> None:
    init_db_MYBP86(db_path)
    db_clear_MYBP86(db_path)
    cabs = set()
    for loc in data.keys():
        cab, _ = parse_location_MYBP86(loc)
        cabs.add(cab)
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    for cab in sorted(cabs):
        cur.execute("INSERT OR IGNORE INTO cabinets(name) VALUES(?)", (cab,))
    for loc, items in data.items():
        cab, shelf = parse_location_MYBP86(loc)
        for it in items:
            cur.execute(
                (
                    "INSERT OR REPLACE INTO items(id,cabinet,shelf,type) "
                    "VALUES(?,?,?,?)"
                ),
                (it["id"], cab, shelf, it["type"])
            )
    con.commit()
    con.close()


def sync_sql_to_json_MYBP86(db_path: str, json_path: str) -> None:
    d = db_load_all_MYBP86(db_path)
    save_data_MYBP86(json_path, d)
