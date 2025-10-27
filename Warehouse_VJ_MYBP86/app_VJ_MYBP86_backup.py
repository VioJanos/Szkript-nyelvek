import tkinter as tk
from tkinter import messagebox, ttk
import sys
import os

# Hálózati eszköz modulok importálása
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Warehouse_VJ_MYBP86.network_equipment import PDU, Switch, NetworkManager

from warehouse_VJ_MYBP86 import SHELVES_MYBP86, StorageMYBP86


DB_PATH = "warehouse_VJ_mybp86.db"
ALLOWED_TYPES = ["BOX", "SWITCH", "PDU", "OTHER"]


class AppMYBP86(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Warehouse & Network Management (MYBP86)")
        self.geometry("1000x700")
        self.resizable(True, True)

        self.store = StorageMYBP86(DB_PATH, allowed_types=ALLOWED_TYPES)
        if not self.store.list_cabinets_MYBP86():
            self.store.add_cabinet_MYBP86("A")
        
        # Hálózati eszköz manager inicializálása
        self.network_manager = NetworkManager()

        self._build_ui()
        self.refresh_all()

    def _build_ui(self) -> None:
        # Notebook (Tab container) létrehozása
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Warehouse tab
        self.warehouse_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.warehouse_frame, text="Warehouse Management")
        
        # Network Equipment tabs
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="Network Equipment")
        
        # Build warehouse UI
        self._build_warehouse_ui()
        
        # Build network equipment UI
        self._build_network_ui()

    def _build_warehouse_ui(self) -> None:
        top = ttk.Frame(self.warehouse_frame)
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

        addc = ttk.Frame(self.warehouse_frame)
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

        self.grid_wrap = ttk.Frame(self.warehouse_frame)
        self.grid_wrap.pack(fill="both", expand=True, padx=10, pady=10)

        summary = ttk.LabelFrame(self.warehouse_frame, text="Summary")
        summary.pack(fill="x", padx=10, pady=(0, 10))
        self.occ_label = ttk.Label(summary, text="By location: –")
        self.occ_label.pack(anchor="w", padx=8, pady=4)
        self.type_label = ttk.Label(summary, text="By type: –")
        self.type_label.pack(anchor="w", padx=8, pady=4)

    def _build_network_ui(self) -> None:
        # Sub-notebook for network equipment types
        self.network_notebook = ttk.Notebook(self.network_frame)
        self.network_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # PDU Management Tab
        self.pdu_frame = ttk.Frame(self.network_notebook)
        self.network_notebook.add(self.pdu_frame, text="PDU Management")
        self._build_pdu_ui()
        
        # Switch Management Tab
        self.switch_frame = ttk.Frame(self.network_notebook)
        self.network_notebook.add(self.switch_frame, text="Switch Management")
        self._build_switch_ui()
        
        # Network Overview Tab
        self.overview_frame = ttk.Frame(self.network_notebook)
        self.network_notebook.add(self.overview_frame, text="Network Overview")
        self._build_overview_ui()

    def _build_pdu_ui(self) -> None:
        # PDU hozzáadás form
        add_frame = ttk.LabelFrame(self.pdu_frame, text="Add New PDU")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Serial Number
        ttk.Label(add_frame, text="Serial Number:").grid(
            row=0, column=0, sticky="w", padx=5, pady=2)
        self.pdu_serial_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_serial_var,
                  width=15).grid(row=0, column=1, padx=5, pady=2)
        
        # Hostname
        ttk.Label(add_frame, text="Hostname:").grid(
            row=0, column=2, sticky="w", padx=5, pady=2)
        self.pdu_hostname_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_hostname_var,
                  width=15).grid(row=0, column=3, padx=5, pady=2)
        
        # IP Address
        ttk.Label(add_frame, text="IP Address:").grid(
            row=1, column=0, sticky="w", padx=5, pady=2)
        self.pdu_ip_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_ip_var,
                  width=15).grid(row=1, column=1, padx=5, pady=2)
        
        # MAC Address
        ttk.Label(add_frame, text="MAC Address:").grid(
            row=1, column=2, sticky="w", padx=5, pady=2)
        self.pdu_mac_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_mac_var,
                  width=18).grid(row=1, column=3, padx=5, pady=2)
        
        # Location
        ttk.Label(add_frame, text="Location:").grid(
            row=2, column=0, sticky="w", padx=5, pady=2)
        self.pdu_location_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_location_var,
                  width=20).grid(row=2, column=1, columnspan=2, 
                                 padx=5, pady=2, sticky="ew")
        
        # Outlet Count
        ttk.Label(add_frame, text="Outlet Count:").grid(
            row=2, column=3, sticky="w", padx=5, pady=2)
        self.pdu_outlets_var = tk.IntVar(value=8)
        ttk.Spinbox(add_frame, from_=4, to=24, width=8,
                    textvariable=self.pdu_outlets_var).grid(
                        row=2, column=4, padx=5, pady=2)
        
        # Manufacturer & Model
        ttk.Label(add_frame, text="Manufacturer:").grid(
            row=3, column=0, sticky="w", padx=5, pady=2)
        self.pdu_manufacturer_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_manufacturer_var,
                  width=15).grid(row=3, column=1, padx=5, pady=2)
        
        ttk.Label(add_frame, text="Model:").grid(
            row=3, column=2, sticky="w", padx=5, pady=2)
        self.pdu_model_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_model_var,
                  width=15).grid(row=3, column=3, padx=5, pady=2)
        
        # Add button
        ttk.Button(add_frame, text="Add PDU",
                   command=self.add_pdu).grid(row=3, column=4, 
                                              padx=10, pady=5)
        
        # PDU lista
        list_frame = ttk.LabelFrame(self.pdu_frame, text="PDU List")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for PDUs
        pdu_cols = ("serial", "hostname", "ip", "location", "outlets",
                    "status")
        self.pdu_tree = ttk.Treeview(list_frame, columns=pdu_cols,
                                     show="headings", height=10)
        
        self.pdu_tree.heading("serial", text="Serial Number")
        self.pdu_tree.heading("hostname", text="Hostname")
        self.pdu_tree.heading("ip", text="IP Address")
        self.pdu_tree.heading("location", text="Location")
        self.pdu_tree.heading("outlets", text="Outlets")
        self.pdu_tree.heading("status", text="Status")
        
        self.pdu_tree.column("serial", width=120)
        self.pdu_tree.column("hostname", width=120)
        self.pdu_tree.column("ip", width=120)
        self.pdu_tree.column("location", width=150)
        self.pdu_tree.column("outlets", width=60)
        self.pdu_tree.column("status", width=80)
        
        # Scrollbar
        pdu_scroll = ttk.Scrollbar(list_frame, orient="vertical",
                                   command=self.pdu_tree.yview)
        self.pdu_tree.configure(yscrollcommand=pdu_scroll.set)
        
        self.pdu_tree.pack(side="left", fill="both", expand=True)
        pdu_scroll.pack(side="right", fill="y")
        
        # PDU részletek gomb
        ttk.Button(list_frame, text="View Details",
                   command=self.view_pdu_details).pack(pady=5)
        
        # Double-click bind
        self.pdu_tree.bind("<Double-1>", lambda e: self.view_pdu_details())

    def _build_switch_ui(self) -> None:
        # Switch hozzáadás form
        add_frame = ttk.LabelFrame(self.switch_frame, text="Add New Switch")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Serial Number
        ttk.Label(add_frame, text="Serial Number:").grid(
            row=0, column=0, sticky="w", padx=5, pady=2)
        self.switch_serial_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_serial_var,
                  width=15).grid(row=0, column=1, padx=5, pady=2)
        
        # Hostname
        ttk.Label(add_frame, text="Hostname:").grid(
            row=0, column=2, sticky="w", padx=5, pady=2)
        self.switch_hostname_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_hostname_var,
                  width=15).grid(row=0, column=3, padx=5, pady=2)
        
        # IP Address
        ttk.Label(add_frame, text="IP Address:").grid(
            row=1, column=0, sticky="w", padx=5, pady=2)
        self.switch_ip_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_ip_var,
                  width=15).grid(row=1, column=1, padx=5, pady=2)
        
        # MAC Address
        ttk.Label(add_frame, text="MAC Address:").grid(
            row=1, column=2, sticky="w", padx=5, pady=2)
        self.switch_mac_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_mac_var,
                  width=18).grid(row=1, column=3, padx=5, pady=2)
        
        # Location
        ttk.Label(add_frame, text="Location:").grid(
            row=2, column=0, sticky="w", padx=5, pady=2)
        self.switch_location_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_location_var,
                  width=20).grid(row=2, column=1, columnspan=2,
                                 padx=5, pady=2, sticky="ew")
        
        # Port Count
        ttk.Label(add_frame, text="Port Count:").grid(
            row=2, column=3, sticky="w", padx=5, pady=2)
        self.switch_ports_var = tk.IntVar(value=24)
        ttk.Spinbox(add_frame, from_=8, to=48, width=8,
                    textvariable=self.switch_ports_var).grid(
                        row=2, column=4, padx=5, pady=2)
        
        # Manufacturer & Model
        ttk.Label(add_frame, text="Manufacturer:").grid(
            row=3, column=0, sticky="w", padx=5, pady=2)
        self.switch_manufacturer_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_manufacturer_var,
                  width=15).grid(row=3, column=1, padx=5, pady=2)
        
        ttk.Label(add_frame, text="Model:").grid(
            row=3, column=2, sticky="w", padx=5, pady=2)
        self.switch_model_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_model_var,
                  width=15).grid(row=3, column=3, padx=5, pady=2)
        
        # Add button
        ttk.Button(add_frame, text="Add Switch",
                   command=self.add_switch).grid(row=3, column=4,
                                                 padx=10, pady=5)
        
        # Switch lista
        list_frame = ttk.LabelFrame(self.switch_frame, text="Switch List")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for Switches
        switch_cols = ("serial", "hostname", "ip", "location", "ports",
                       "status")
        self.switch_tree = ttk.Treeview(list_frame, columns=switch_cols,
                                        show="headings", height=10)
        
        self.switch_tree.heading("serial", text="Serial Number")
        self.switch_tree.heading("hostname", text="Hostname")
        self.switch_tree.heading("ip", text="IP Address")
        self.switch_tree.heading("location", text="Location")
        self.switch_tree.heading("ports", text="Ports")
        self.switch_tree.heading("status", text="Status")
        
        self.switch_tree.column("serial", width=120)
        self.switch_tree.column("hostname", width=120)
        self.switch_tree.column("ip", width=120)
        self.switch_tree.column("location", width=150)
        self.switch_tree.column("ports", width=60)
        self.switch_tree.column("status", width=80)
        
        # Scrollbar
        switch_scroll = ttk.Scrollbar(list_frame, orient="vertical",
                                      command=self.switch_tree.yview)
        self.switch_tree.configure(yscrollcommand=switch_scroll.set)
        
        self.switch_tree.pack(side="left", fill="both", expand=True)
        switch_scroll.pack(side="right", fill="y")
        
        # Switch részletek gomb
        ttk.Button(list_frame, text="View Details",
                   command=self.view_switch_details).pack(pady=5)
        
        # Double-click bind
        self.switch_tree.bind("<Double-1>",
                              lambda e: self.view_switch_details())

    def _build_overview_ui(self) -> None:
        # Network summary
        summary_frame = ttk.LabelFrame(self.overview_frame,
                                       text="Network Summary")
        summary_frame.pack(fill="x", padx=10, pady=5)
        
        self.network_summary_label = ttk.Label(summary_frame,
                                               text="No devices configured")
        self.network_summary_label.pack(padx=10, pady=10)
        
        # Location mapping
        location_frame = ttk.LabelFrame(self.overview_frame,
                                        text="Location Assignment")
        location_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Location combobox
        ttk.Label(location_frame, text="Select Location:").pack(pady=5)
        self.location_var = tk.StringVar()
        self.location_combo = ttk.Combobox(location_frame,
                                           textvariable=self.location_var,
                                           state="readonly")
        self.location_combo.pack(pady=5)
        self.location_combo.bind("<<ComboboxSelected>>",
                                 self.on_location_selected)
        
        # Devices in location
        devices_frame = ttk.Frame(location_frame)
        devices_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left side - PDUs
        pdu_frame = ttk.LabelFrame(devices_frame, text="PDUs in Location")
        pdu_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        self.location_pdu_listbox = tk.Listbox(pdu_frame)
        self.location_pdu_listbox.pack(fill="both", expand=True,
                                       padx=5, pady=5)
        
        # Right side - Switches
        switch_frame = ttk.LabelFrame(devices_frame,
                                      text="Switches in Location")
        switch_frame.pack(side="right", fill="both", expand=True, padx=5)
        
        self.location_switch_listbox = tk.Listbox(switch_frame)
        self.location_switch_listbox.pack(fill="both", expand=True,
                                          padx=5, pady=5)
        
        # Refresh buttons
        ttk.Button(location_frame, text="Refresh Network Data",
                   command=self.refresh_network_data).pack(pady=10)

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
        # Hálózati adatok frissítése is
        self.refresh_network_data()

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

    # Hálózati eszköz kezelő metódusok
    def add_pdu(self) -> None:
        try:
            pdu = PDU(
                serial_number=self.pdu_serial_var.get().strip(),
                hostname=self.pdu_hostname_var.get().strip(),
                ip_address=self.pdu_ip_var.get().strip(),
                mac_address=self.pdu_mac_var.get().strip(),
                outlet_count=self.pdu_outlets_var.get(),
                manufacturer=self.pdu_manufacturer_var.get().strip(),
                model=self.pdu_model_var.get().strip(),
                location=self.pdu_location_var.get().strip()
            )
            
            if self.network_manager.add_device(pdu):
                messagebox.showinfo("Success", f"PDU {pdu.hostname} added!")
                self.clear_pdu_form()
                self.refresh_network_data()
            else:
                messagebox.showerror("Error",
                                     "Device with this serial number exists!")
        except ValueError as e:
            messagebox.showerror("Validation Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add PDU: {str(e)}")

    def add_switch(self) -> None:
        try:
            switch = Switch(
                serial_number=self.switch_serial_var.get().strip(),
                hostname=self.switch_hostname_var.get().strip(),
                ip_address=self.switch_ip_var.get().strip(),
                mac_address=self.switch_mac_var.get().strip(),
                port_count=self.switch_ports_var.get(),
                manufacturer=self.switch_manufacturer_var.get().strip(),
                model=self.switch_model_var.get().strip(),
                location=self.switch_location_var.get().strip()
            )
            
            if self.network_manager.add_device(switch):
                messagebox.showinfo("Success",
                                    f"Switch {switch.hostname} added!")
                self.clear_switch_form()
                self.refresh_network_data()
            else:
                messagebox.showerror("Error",
                                     "Device with this serial number exists!")
        except ValueError as e:
            messagebox.showerror("Validation Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add Switch: {str(e)}")

    def clear_pdu_form(self) -> None:
        self.pdu_serial_var.set("")
        self.pdu_hostname_var.set("")
        self.pdu_ip_var.set("")
        self.pdu_mac_var.set("")
        self.pdu_location_var.set("")
        self.pdu_outlets_var.set(8)
        self.pdu_manufacturer_var.set("")
        self.pdu_model_var.set("")

    def clear_switch_form(self) -> None:
        self.switch_serial_var.set("")
        self.switch_hostname_var.set("")
        self.switch_ip_var.set("")
        self.switch_mac_var.set("")
        self.switch_location_var.set("")
        self.switch_ports_var.set(24)
        self.switch_manufacturer_var.set("")
        self.switch_model_var.set("")

    def refresh_network_data(self) -> None:
        # PDU lista frissítése
        for item in self.pdu_tree.get_children():
            self.pdu_tree.delete(item)
        
        pdus = self.network_manager.get_devices_by_type('PDU')
        for pdu in pdus:
            self.pdu_tree.insert("", "end", values=(
                pdu.serial_number,
                pdu.hostname,
                pdu.ip_address,
                pdu.location,
                pdu.outlet_count,
                pdu.status.value
            ))
        
        # Switch lista frissítése
        for item in self.switch_tree.get_children():
            self.switch_tree.delete(item)
        
        switches = self.network_manager.get_devices_by_type('Switch')
        for switch in switches:
            self.switch_tree.insert("", "end", values=(
                switch.serial_number,
                switch.hostname,
                switch.ip_address,
                switch.location,
                switch.port_count,
                switch.status.value
            ))
        
        # Network summary frissítése
        summary = self.network_manager.get_summary()
        summary_text = (
            f"Total Devices: {summary['total_devices']} | "
            f"PDUs: {summary['device_types'].get('PDU', 0)} | "
            f"Switches: {summary['device_types'].get('Switch', 0)} | "
            f"Online: {summary['online_devices']}")
        self.network_summary_label.config(text=summary_text)
        
        # Location lista frissítése
        locations = set()
        for device in self.network_manager.devices.values():
            if device.location.strip():
                locations.add(device.location.strip())
        
        self.location_combo['values'] = sorted(list(locations))

    def view_pdu_details(self) -> None:
        selection = self.pdu_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a PDU first!")
            return
        
        item = self.pdu_tree.item(selection[0])
        serial_number = item['values'][0]
        pdu = self.network_manager.get_device(serial_number)
        
        if pdu:
            self.show_pdu_details(pdu)

    def view_switch_details(self) -> None:
        selection = self.switch_tree.selection()
        if not selection:
            messagebox.showwarning("Selection",
                                   "Please select a Switch first!")
            return
        
        item = self.switch_tree.item(selection[0])
        serial_number = item['values'][0]
        switch = self.network_manager.get_device(serial_number)
        
        if switch:
            self.show_switch_details(switch)

    def show_pdu_details(self, pdu) -> None:
        win = tk.Toplevel(self)
        win.title(f"PDU Details - {pdu.hostname}")
        win.geometry("600x500")
        
        # Alapadatok
        info_frame = ttk.LabelFrame(win, text="Device Information")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        info_labels = [
            ("Serial Number:", pdu.serial_number),
            ("Hostname:", pdu.hostname),
            ("IP Address:", pdu.ip_address),
            ("MAC Address:", pdu.mac_address),
            ("Location:", pdu.location),
            ("Manufacturer:", pdu.manufacturer),
            ("Model:", pdu.model),
            ("Status:", pdu.status.value),
            ("Outlet Count:", str(pdu.outlet_count))
        ]
        
        for i, (label, value) in enumerate(info_labels):
            ttk.Label(info_frame, text=label).grid(
                row=i//2, column=(i%2)*2, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, text=value, font=("", 9, "bold")).grid(
                row=i//2, column=(i%2)*2+1, sticky="w", padx=5, pady=2)
        
        # Outlet státusz
        outlet_frame = ttk.LabelFrame(win, text="Outlet Status")
        outlet_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        outlet_tree = ttk.Treeview(outlet_frame,
                                   columns=("number", "name", "status",
                                           "device"),
                                   show="headings")
        outlet_tree.heading("number", text="Outlet #")
        outlet_tree.heading("name", text="Name")
        outlet_tree.heading("status", text="Status")
        outlet_tree.heading("device", text="Connected Device")
        
        for outlet in pdu.outlets:
            outlet_tree.insert("", "end", values=(
                outlet['outlet_number'],
                outlet['name'],
                outlet['status'],
                outlet['connected_device'] or "None"
            ))
        
        outlet_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    def show_switch_details(self, switch) -> None:
        win = tk.Toplevel(self)
        win.title(f"Switch Details - {switch.hostname}")
        win.geometry("700x600")
        
        # Alapadatok
        info_frame = ttk.LabelFrame(win, text="Device Information")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        info_labels = [
            ("Serial Number:", switch.serial_number),
            ("Hostname:", switch.hostname),
            ("IP Address:", switch.ip_address),
            ("MAC Address:", switch.mac_address),
            ("Location:", switch.location),
            ("Manufacturer:", switch.manufacturer),
            ("Model:", switch.model),
            ("Status:", switch.status.value),
            ("Port Count:", str(switch.port_count))
        ]
        
        for i, (label, value) in enumerate(info_labels):
            ttk.Label(info_frame, text=label).grid(
                row=i//2, column=(i%2)*2, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, text=value, font=("", 9, "bold")).grid(
                row=i//2, column=(i%2)*2+1, sticky="w", padx=5, pady=2)
        
        # Port státusz
        port_frame = ttk.LabelFrame(win, text="Port Status")
        port_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        port_tree = ttk.Treeview(port_frame,
                                 columns=("number", "name", "status", "vlan",
                                         "speed", "device"),
                                 show="headings")
        port_tree.heading("number", text="Port #")
        port_tree.heading("name", text="Name")
        port_tree.heading("status", text="Status")
        port_tree.heading("vlan", text="VLAN")
        port_tree.heading("speed", text="Speed")
        port_tree.heading("device", text="Connected Device")
        
        for port in switch.ports:
            port_tree.insert("", "end", values=(
                port.port_number,
                port.port_name,
                port.status.value,
                port.vlan_id or "None",
                port.speed,
                port.connected_device or "None"
            ))
        
        port_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # VLAN info
        vlan_frame = ttk.LabelFrame(win, text="VLAN Information")
        vlan_frame.pack(fill="x", padx=10, pady=5)
        
        vlan_text = ", ".join([f"VLAN {vid}: {vinfo['name']}"
                               for vid, vinfo in switch.vlans.items()])
        ttk.Label(vlan_frame, text=vlan_text or "No VLANs configured").pack(
            padx=10, pady=5)
        
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    def on_location_selected(self, event=None) -> None:
        location = self.location_var.get()
        if not location:
            return
        
        # Clear listboxes
        self.location_pdu_listbox.delete(0, tk.END)
        self.location_switch_listbox.delete(0, tk.END)
        
        # Populate PDUs in location
        pdus = self.network_manager.get_devices_by_location(location)
        for device in pdus:
            if device.device_type == 'PDU':
                self.location_pdu_listbox.insert(tk.END,
                                                 f"{device.hostname} ({device.serial_number})")
        
        # Populate Switches in location
        switches = self.network_manager.get_devices_by_location(location)
        for device in switches:
            if device.device_type == 'Switch':
                self.location_switch_listbox.insert(tk.END,
                                                    f"{device.hostname} ({device.serial_number})")


if __name__ == "__main__":
    try:
        AppMYBP86().mainloop()
    except Exception as e:
        try:
            messagebox.showerror("Startup error", f"{type(e).__name__}: {e}")
        except Exception:
            pass
        raise
