import tkinter as tk
from tkinter import messagebox, ttk

from warehouse_VJ_MYBP86 import SHELVES_MYBP86, StorageMYBP86


DB_PATH = "warehouse_VJ_mybp86.db"
ALLOWED_TYPES = ["BOX", "SWITCH", "PDU", "OTHER"]


class AppMYBP86(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Warehouse – Cabinet View (MYBP86)")
        self.geometry("900x640")
        self.resizable(False, False)

        self.store = StorageMYBP86(DB_PATH, allowed_types=ALLOWED_TYPES)
        if not self.store.list_cabinets_MYBP86():
            self.store.add_cabinet_MYBP86("A")

        self._build_ui()
        self.refresh_all()

    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(
            top,
            text="Cabinet"
        ).grid(row=0, column=0, padx=8, pady=6, sticky="e")
        self.cab_var = tk.StringVar()
        self.cab_combo = ttk.Combobox(
            top,
            values=[],
            textvariable=self.cab_var,
            state="readonly",
            width=8,
        )
        self.cab_combo.grid(row=0, column=1, padx=6)

        ttk.Label(top, text="Shelf").grid(row=0, column=2, padx=6, sticky="e")
        self.shelf_var = tk.IntVar(value=1)
        self.shelf_combo = ttk.Combobox(
            top,
            values=list(SHELVES_MYBP86),
            textvariable=self.shelf_var,
            state="readonly",
            width=4,
        )
        self.shelf_combo.grid(row=0, column=3, padx=6)

        ttk.Label(top, text="Type").grid(row=0, column=4, padx=6, sticky="e")
        self.type_var = tk.StringVar(value=ALLOWED_TYPES[0])
        ttk.Combobox(
            top,
            values=ALLOWED_TYPES,
            textvariable=self.type_var,
            state="readonly",
            width=12,
        ).grid(row=0, column=5, padx=6)

        ttk.Button(
            top, text="Add item", command=self.on_add
        ).grid(row=0, column=6, padx=12)
        ttk.Button(
            top,
            text="Refresh",
            command=self.refresh_all
        ).grid(row=0, column=7, padx=6)

        addc = ttk.Frame(self)
        addc.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Label(
            addc,
            text="New cabinet name"
        ).grid(row=0, column=0, padx=6, pady=6, sticky="e")
        self.newcab_var = tk.StringVar()
        ttk.Entry(
            addc,
            textvariable=self.newcab_var,
            width=12
        ).grid(row=0, column=1, padx=6)
        ttk.Button(
            addc,
            text="Add cabinet",
            command=self.on_add_cabinet
        ).grid(row=0, column=2, padx=8)

        self.grid_wrap = ttk.Frame(self)
        self.grid_wrap.pack(fill="both", expand=True, padx=10, pady=10)

        summary = ttk.LabelFrame(self, text="Summary")
        summary.pack(fill="x", padx=10, pady=(0, 10))
        self.occ_label = ttk.Label(summary, text="By location: –")
        self.occ_label.pack(anchor="w", padx=8, pady=4)
        self.type_label = ttk.Label(summary, text="By type: –")
        self.type_label.pack(anchor="w", padx=8, pady=4)

    def on_add_cabinet(self) -> None:
        name = self.newcab_var.get().strip().upper()
        if not name:
            messagebox.showwarning(
                "Validation", "Please enter a cabinet name."
            )
            return
        self.store.add_cabinet_MYBP86(name)
        self.newcab_var.set("")
        self.refresh_all()

    def on_add(self) -> None:
        try:
            cab = self.cab_var.get()
            shelf = int(self.shelf_var.get())
            typ = self.type_var.get()
            new_id = self.store.add_item_MYBP86(
                cab, shelf, typ, customer_code="TES"
            )
            messagebox.showinfo("Added", f"New ID: {new_id}")
            self.refresh_all()
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))

    def refresh_all(self) -> None:
        cabs = self.store.list_cabinets_MYBP86()
        self.cab_combo["values"] = cabs
        if cabs and self.cab_var.get() not in cabs:
            self.cab_var.set(cabs[0])
        self.draw_cabinets()
        self.update_summaries()

    def draw_cabinets(self) -> None:
        for widget in self.grid_wrap.winfo_children():
            widget.destroy()

        occ = self.store.occupancy_summary_MYBP86()
        cabs = self.store.list_cabinets_MYBP86()

        for i, cab in enumerate(cabs):
            frame = ttk.LabelFrame(self.grid_wrap, text=f"Cabinet {cab}")
            frame.grid(row=0, column=i, padx=8, pady=8, sticky="n")

            for s in range(6, 0, -1):
                loc = f"{cab}{s}"
                count = occ.get(loc, 0)
                btn = ttk.Button(frame, text=f"{loc}\n{count} pcs", width=12)
                btn.pack(fill="x", padx=6, pady=6, ipadx=4, ipady=8)
                btn.configure(
                    command=lambda C=cab, S=s: self.show_location(C, S)
                )

    def show_location(self, cabinet: str, shelf: int) -> None:
        win = tk.Toplevel(self)
        win.title(f"{cabinet}{shelf} contents")
        win.geometry("500x400")

        cols = ("id", "type")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("id", text="ID")
        tree.heading("type", text="Type")
        tree.pack(fill="both", expand=True, padx=8, pady=8)

        items = self.store.get_items_by_location_MYBP86(cabinet, shelf)
        for it in items:
            tree.insert("", "end", values=(it["id"], it["type"]))

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=6)

    def update_summaries(self) -> None:
        occ = self.store.occupancy_summary_MYBP86()
        typ = self.store.type_breakdown_MYBP86()

        occ_text = ", ".join(f"{k}:{v}" for k, v in sorted(occ.items()))
        typ_text = ", ".join(f"{k}:{v}" for k, v in sorted(typ.items()))

        self.occ_label.config(text=f"By location: {occ_text or '–'}")
        self.type_label.config(text=f"By type: {typ_text or '–'}")


if __name__ == "__main__":
    try:
        AppMYBP86().mainloop()
    except Exception as e:
        try:
            messagebox.showerror("Startup error", f"{type(e).__name__}: {e}")
        except Exception:
            pass
        raise
