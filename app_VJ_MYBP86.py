import tkinter as tk
from tkinter import ttk, messagebox
from warehouse_VJ_MYBP86 import (
    StorageMYBP86,
    load_data_MYBP86,
    save_data_MYBP86,
    init_db_MYBP86,
    db_add_cabinet_MYBP86,
    db_list_cabinets_MYBP86,
    db_get_items_by_location_MYBP86,
    db_add_item_MYBP86,
    db_load_all_MYBP86,
    db_occupancy_MYBP86,
    db_type_breakdown_MYBP86,
    sync_json_to_sql_MYBP86,
    sync_sql_to_json_MYBP86,
)

DATA_PATH = "data.json"
DB_PATH = "raktar_mybp86.db"
TYPE_OPTIONS = ["BOX", "SWITCH", "PDU", "OTHER"]


class AppMYBP86(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Raktár Szekrény – MYBP86")
        self.geometry("980x640")
        self.resizable(False, False)
        init_db_MYBP86(DB_PATH)
        self.mode_var = tk.StringVar(value="JSON")
        self.store = StorageMYBP86(["A"])
        initial = load_data_MYBP86(DATA_PATH)
        if initial:
            self.store.data.update(initial)
        self._build_ui()
        self.refresh_all()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)
        ttk.Label(
            top,
            text="Tárolás"
        ).grid(row=0, column=0, padx=6, pady=6, sticky="e")
        ttk.Radiobutton(
            top,
            text="JSON",
            value="JSON",
            variable=self.mode_var,
            command=self.on_mode_change
        ).grid(row=0, column=1, padx=2)
        ttk.Radiobutton(
            top,
            text="SQLite",
            value="SQL",
            variable=self.mode_var,
            command=self.on_mode_change
        ).grid(row=0, column=2, padx=2)
        ttk.Label(
            top, text="Szekrény"
        ).grid(row=0, column=3, padx=12, sticky="e")
        self.cab_var = tk.StringVar(value="A")
        self.cab_combo = ttk.Combobox(
            top,
            values=["A"],
            textvariable=self.cab_var,
            state="readonly",
            width=6
        )
        self.cab_combo.grid(row=0, column=4, padx=6)
        ttk.Label(top, text="Polc").grid(row=0, column=5, padx=6, sticky="e")
        self.shelf_var = tk.IntVar(value=1)
        self.shelf_combo = ttk.Combobox(
            top,
            values=[1, 2, 3, 4, 5, 6],
            textvariable=self.shelf_var,
            state="readonly",
            width=4
        )
        self.shelf_combo.grid(row=0, column=6, padx=6)
        ttk.Label(top, text="Típus").grid(row=0, column=7, padx=6, sticky="e")
        self.type_var = tk.StringVar(value=TYPE_OPTIONS[0])
        ttk.Combobox(
            top,
            values=TYPE_OPTIONS,
            textvariable=self.type_var,
            state="readonly",
            width=10
        ).grid(row=0, column=8, padx=6)
        ttk.Button(
            top, text="Hozzáadás", command=self.on_add
        ).grid(row=0, column=9, padx=10)
        ttk.Button(
            top, text="Mentés", command=self.on_save
        ).grid(row=0, column=10, padx=6)
        ttk.Button(
            top,
            text="Frissítés",
            command=self.refresh_all
        ).grid(row=0, column=11, padx=6)
        addc = ttk.Frame(self)
        addc.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Label(
            addc,
            text="Új szekrény neve"
        ).grid(row=0, column=0, padx=6, pady=6, sticky="e")
        self.newcab_var = tk.StringVar()
        entry = ttk.Entry(addc, textvariable=self.newcab_var, width=10)
        entry.grid(row=0, column=1, padx=6)
        ttk.Button(
            addc, text="Szekrény hozzáadása", command=self.on_add_cabinet
        ).grid(row=0, column=2, padx=8)
        self.grid_wrap = ttk.Frame(self)
        self.grid_wrap.pack(fill="both", expand=True, padx=10, pady=10)
        summary = ttk.LabelFrame(self, text="Összesítés")
        summary.pack(fill="x", padx=10, pady=(0, 10))
        self.occ_label = ttk.Label(summary, text="Lokációnként: –")
        self.occ_label.pack(anchor="w", padx=8, pady=4)
        self.type_label = ttk.Label(summary, text="Típusonként: –")
        self.type_label.pack(anchor="w", padx=8, pady=4)

    def on_mode_change(self):
        if self.mode_var.get() == "SQL":
            sync_json_to_sql_MYBP86(DB_PATH, self.store.data)
        else:
            sync_sql_to_json_MYBP86(DB_PATH, DATA_PATH)
            self.store.data = load_data_MYBP86(DATA_PATH)
        self.refresh_all()

    def on_add_cabinet(self):
        name = self.newcab_var.get().strip().upper()
        if not name:
            messagebox.showwarning("Hiba", "Adj meg egy nevet.")
            return
        if self.mode_var.get() == "JSON":
            self.store.add_cabinet_MYBP86(name)
            save_data_MYBP86(DATA_PATH, self.store.data)
            sync_json_to_sql_MYBP86(DB_PATH, self.store.data)
        else:
            db_add_cabinet_MYBP86(DB_PATH, name)
            sync_sql_to_json_MYBP86(DB_PATH, DATA_PATH)
            self.store.data = load_data_MYBP86(DATA_PATH)
        self.newcab_var.set("")
        self.refresh_all()

    def on_add(self):
        cab = self.cab_var.get()
        shelf = int(self.shelf_var.get())
        typ = self.type_var.get()
        if self.mode_var.get() == "JSON":
            new_id = self.store.add_item_MYBP86(
                cab, shelf, typ, customer_code="TES"
            )
            save_data_MYBP86(DATA_PATH, self.store.data)
            sync_json_to_sql_MYBP86(DB_PATH, self.store.data)
        else:
            new_id = db_add_item_MYBP86(
                DB_PATH, cab, shelf, typ, customer_code="TES"
            )
            sync_sql_to_json_MYBP86(DB_PATH, DATA_PATH)
            self.store.data = load_data_MYBP86(DATA_PATH)
        messagebox.showinfo("Hozzáadva", f"Új ID: {new_id}")
        self.refresh_all()

    def on_save(self):
        if self.mode_var.get() == "JSON":
            save_data_MYBP86(DATA_PATH, self.store.data)
            sync_json_to_sql_MYBP86(DB_PATH, self.store.data)
            messagebox.showinfo("Mentve", DATA_PATH)
        else:
            sync_sql_to_json_MYBP86(DB_PATH, DATA_PATH)
            messagebox.showinfo("Info", "SQLite szinkronizálva JSON-nal.")

    def refresh_all(self):
        if self.mode_var.get() == "JSON":
            self._refresh_from_json()
        else:
            self._refresh_from_sql()
        self.draw_cabinets()
        self.update_summaries()

    def _refresh_from_json(self):
        d = load_data_MYBP86(DATA_PATH)
        if d:
            self.store.data = d
        if not self.store.cabinets:
            self.store.list_cabinets_MYBP86()
        if not self.store.cabinets:
            self.store.add_cabinet_MYBP86("A")
        self.cab_combo["values"] = self.store.list_cabinets_MYBP86()
        if self.cab_var.get() not in self.cab_combo["values"]:
            self.cab_var.set(self.cab_combo["values"][0])

    def _refresh_from_sql(self):
        self.store = StorageMYBP86([])
        self.store.data = db_load_all_MYBP86(DB_PATH)
        self.store.cabinets = db_list_cabinets_MYBP86(DB_PATH)
        if not self.store.cabinets:
            db_add_cabinet_MYBP86(DB_PATH, "A")
            self.store.cabinets = ["A"]
        self.cab_combo["values"] = self.store.cabinets
        if self.cab_var.get() not in self.cab_combo["values"]:
            self.cab_var.set(self.cab_combo["values"][0])

    def draw_cabinets(self):
        for w in self.grid_wrap.winfo_children():
            w.destroy()
        if self.mode_var.get() == "JSON":
            cabs = self.store.list_cabinets_MYBP86()
        else:
            cabs = self.store.cabinets
        for i, cab in enumerate(cabs):
            frame = ttk.LabelFrame(self.grid_wrap, text=f"Szekrény {cab}")
            frame.grid(row=0, column=i, padx=8, pady=8, sticky="n")
            for s in range(6, 0, -1):
                loc = f"{cab}{s}"
                count = len(self.store.data.get(loc, []))
                btn = ttk.Button(frame, text=f"{loc}\n{count} db", width=12)
                btn.pack(fill="x", padx=6, pady=6, ipadx=4, ipady=8)
                btn.configure(
                    command=lambda C=cab, S=s: self.show_location(C, S)
                )

    def show_location(self, cabinet: str, shelf: int):
        win = tk.Toplevel(self)
        win.title(f"{cabinet}{shelf} tartalma")
        win.geometry("460x360")
        cols = ("id", "type")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("id", text="ID")
        tree.heading("type", text="Típus")
        tree.pack(fill="both", expand=True, padx=8, pady=8)
        if self.mode_var.get() == "JSON":
            items = self.store.data.get(f"{cabinet}{shelf}", [])
        else:
            items = db_get_items_by_location_MYBP86(DB_PATH, cabinet, shelf)
        for it in items:
            tree.insert("", "end", values=(it["id"], it["type"]))
        ttk.Button(win, text="Bezár", command=win.destroy).pack(pady=6)

    def update_summaries(self):
        if self.mode_var.get() == "JSON":
            occ = self.store.occupancy_summary_MYBP86()
            typ = self.store.type_breakdown_MYBP86()
        else:
            occ = db_occupancy_MYBP86(DB_PATH)
            typ = db_type_breakdown_MYBP86(DB_PATH)
        occ_text = ", ".join(f"{k}:{v}" for k, v in sorted(occ.items()))
        typ_text = ", ".join(f"{k}:{v}" for k, v in sorted(typ.items()))
        self.occ_label.config(text=f"Lokációnként: {occ_text or '–'}")
        self.type_label.config(text=f"Típusonként: {typ_text or '–'}")


if __name__ == "__main__":
    AppMYBP86().mainloop()
