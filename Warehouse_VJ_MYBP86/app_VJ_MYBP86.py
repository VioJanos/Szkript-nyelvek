import tkinter as tk
from tkinter import messagebox, ttk
from typing import List
import sqlite3

from network_equipment import PDU, Switch, NetworkManager
from warehouse_VJ_MYBP86 import SHELVES_MYBP86, StorageMYBP86
from database_VJ_MYBP86 import (
    populate_sample_data_MYBP86,
    clear_sample_data_MYBP86,
    get_available_locations_MYBP86
)

DB_PATH = "warehouse_VJ_mybp86.db"
ALLOWED_TYPES = ["BOX", "CABLE", "RACK", "TOOL", "SPARE", "SWITCH STACK", "PDU STACK", "OTHER"]
# Network devices (SWITCH, PDU, etc.) should be added through Network Equipment tab


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
        self._load_network_devices_from_db()

        self._build_ui()
        self.refresh_all()
        
        # Initialize location dropdowns with stack names
        self.update_location_combos()

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
        # Add info label
        info_frame = ttk.Frame(self.warehouse_frame)
        info_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(info_frame, 
                  text="⚠️ For Network Equipment (Switches, PDUs), use the 'Network Equipment' tab",
                  foreground="orange",
                  font=("Arial", 9, "italic")).pack()
        
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
        ttk.Button(
            top,
            text="Load Sample Data",
            command=self.load_sample_data
        ).grid(row=0, column=8, padx=6)
        ttk.Button(
            top,
            text="Clear Sample Data",
            command=self.clear_sample_data
        ).grid(row=0, column=9, padx=6)

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

        # Summary section removed - not needed in stack-based system

    def _load_network_devices_from_db(self) -> None:
        """Hálózati eszközök betöltése az adatbázisból"""
        try:
            # Töröljük a meglévő eszközöket a memóriából
            self.network_manager.devices.clear()
            
            devices = self.store.get_network_devices_MYBP86()
            for device_data in devices:
                # PDU létrehozása
                if device_data['device_type'] == 'PDU':
                    pdu = PDU(
                        serial_number=device_data['serial_number'],
                        hostname=device_data['hostname'],
                        ip_address=device_data['ip_address'],
                        mac_address=device_data['mac_address'],
                        outlet_count=device_data.get('port_count', 8),
                        manufacturer="",
                        model=device_data.get('model', ''),
                        location=device_data.get('location', '')
                    )
                    self.network_manager.add_device(pdu)
                
                # Switch létrehozása
                elif device_data['device_type'] == 'Switch':
                    switch = Switch(
                        serial_number=device_data['serial_number'],
                        hostname=device_data['hostname'],
                        ip_address=device_data['ip_address'],
                        mac_address=device_data['mac_address'],
                        port_count=device_data.get('port_count', 24),
                        manufacturer="",
                        model=device_data.get('model', ''),
                        location=device_data.get('location', '')
                    )
                    self.network_manager.add_device(switch)
        except Exception as e:
            print(f"Error loading network devices: {e}")

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
        
        # Check if there are any switch stacks and add Stack Management tab if needed
        self._check_and_add_stack_management_tab()

    def _build_pdu_ui(self) -> None:
        # PDU hozzáadás form
        add_frame = ttk.LabelFrame(self.pdu_frame, text="Add New PDU")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Row 0
        ttk.Label(add_frame, text="Serial Number:").grid(
            row=0, column=0, sticky="w", padx=5, pady=2)
        self.pdu_serial_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_serial_var,
                  width=15).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(add_frame, text="Hostname:").grid(
            row=0, column=2, sticky="w", padx=5, pady=2)
        self.pdu_hostname_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_hostname_var,
                  width=15).grid(row=0, column=3, padx=5, pady=2)
        
        # Row 1
        ttk.Label(add_frame, text="IP Address:").grid(
            row=1, column=0, sticky="w", padx=5, pady=2)
        self.pdu_ip_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_ip_var,
                  width=15).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(add_frame, text="MAC Address:").grid(
            row=1, column=2, sticky="w", padx=5, pady=2)
        self.pdu_mac_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.pdu_mac_var,
                  width=18).grid(row=1, column=3, padx=5, pady=2)
        
        # Row 2
        ttk.Label(add_frame, text="Stack:").grid(
            row=2, column=0, sticky="w", padx=5, pady=2)
        self.pdu_location_var = tk.StringVar()
        self.pdu_location_combo = ttk.Combobox(
            add_frame,
            textvariable=self.pdu_location_var,
            values=[], state="readonly", width=18)
        self.pdu_location_combo.grid(row=2, column=1, columnspan=2,
                                     padx=5, pady=2, sticky="ew")
        
        ttk.Label(add_frame, text="Outlet Count:").grid(
            row=2, column=3, sticky="w", padx=5, pady=2)
        self.pdu_outlets_var = tk.IntVar(value=8)
        ttk.Spinbox(add_frame, from_=4, to=24, width=8,
                    textvariable=self.pdu_outlets_var).grid(
                        row=2, column=4, padx=5, pady=2)
        
        # Row 3
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
        self.pdu_tree.heading("location", text="Stack")
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
        
        # Pack tree and scrollbar directly
        self.pdu_tree.pack(side="left", fill="both", expand=True)
        pdu_scroll.pack(side="right", fill="y")
        
        # PDU management buttons (vertical layout)
        pdu_button_frame = ttk.Frame(list_frame)
        pdu_button_frame.pack(side="right", fill="y", padx=5)
        
        ttk.Button(pdu_button_frame, text="View Details", width=12,
                   command=self.view_pdu_details).pack(fill="x", pady=2)
        ttk.Button(pdu_button_frame, text="Edit PDU", width=12,
                   command=self.edit_pdu).pack(fill="x", pady=2)
        ttk.Button(pdu_button_frame, text="Delete PDU", width=12,
                   command=self.delete_pdu).pack(fill="x", pady=2)
        
        # Double-click bind
        self.pdu_tree.bind("<Double-1>", lambda e: self.view_pdu_details())

    def _build_switch_ui(self) -> None:
        # Switch hozzáadás form
        add_frame = ttk.LabelFrame(self.switch_frame, text="Add New Switch")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Row 0
        ttk.Label(add_frame, text="Serial Number:").grid(
            row=0, column=0, sticky="w", padx=5, pady=2)
        self.switch_serial_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_serial_var,
                  width=15).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(add_frame, text="Hostname:").grid(
            row=0, column=2, sticky="w", padx=5, pady=2)
        self.switch_hostname_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_hostname_var,
                  width=15).grid(row=0, column=3, padx=5, pady=2)
        
        # Row 1
        ttk.Label(add_frame, text="IP Address:").grid(
            row=1, column=0, sticky="w", padx=5, pady=2)
        self.switch_ip_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_ip_var,
                  width=15).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(add_frame, text="MAC Address:").grid(
            row=1, column=2, sticky="w", padx=5, pady=2)
        self.switch_mac_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.switch_mac_var,
                  width=18).grid(row=1, column=3, padx=5, pady=2)
        
        # Row 2
        ttk.Label(add_frame, text="Stack:").grid(
            row=2, column=0, sticky="w", padx=5, pady=2)
        self.switch_location_var = tk.StringVar()
        self.switch_location_combo = ttk.Combobox(
            add_frame,
            textvariable=self.switch_location_var,
            values=[], state="readonly", width=18)
        self.switch_location_combo.grid(row=2, column=1, padx=5, pady=2)
        
        # Bind location change to update switch stacks
        self.switch_location_combo.bind("<<ComboboxSelected>>", self.on_switch_location_changed)
        
        # Switch Stack selection
        ttk.Label(add_frame, text="Switch Stack:").grid(
            row=2, column=2, sticky="w", padx=5, pady=2)
        self.switch_stack_var = tk.StringVar()
        self.switch_stack_combo = ttk.Combobox(
            add_frame,
            textvariable=self.switch_stack_var,
            values=[], state="readonly", width=15)
        self.switch_stack_combo.grid(row=2, column=3, padx=5, pady=2)
        
        ttk.Label(add_frame, text="Port Count:").grid(
            row=2, column=4, sticky="w", padx=5, pady=2)
        self.switch_ports_var = tk.IntVar(value=24)
        ttk.Spinbox(add_frame, from_=8, to=48, width=8,
                    textvariable=self.switch_ports_var).grid(
                        row=2, column=5, padx=5, pady=2)
        
        # Row 3
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
        
        ttk.Button(add_frame, text="Add Switch",
                   command=self.add_switch).grid(row=3, column=5,
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
        self.switch_tree.heading("location", text="Stack")
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
        
        # Pack tree and scrollbar directly
        self.switch_tree.pack(side="left", fill="both", expand=True)
        switch_scroll.pack(side="right", fill="y")
        
        # Switch management buttons (vertical layout)
        button_frame = ttk.Frame(list_frame)
        button_frame.pack(side="right", fill="y", padx=5)
        
        ttk.Button(button_frame, text="View Details", width=12,
                   command=self.view_switch_details).pack(fill="x", pady=2)
        ttk.Button(button_frame, text="Edit Switch", width=12,
                   command=self.edit_switch).pack(fill="x", pady=2)
        ttk.Button(button_frame, text="Delete Switch", width=12,
                   command=self.delete_switch).pack(fill="x", pady=2)
        
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
            
            # Special handling for Switch Stack
            if typ == "SWITCH STACK":
                self.create_switch_stack(cab, shelf)
                return
            
            # Special handling for PDU Stack
            if typ == "PDU STACK":
                self.create_pdu_stack(cab, shelf)
                return
            
            # Prevent adding network device types through warehouse interface
            network_device_types = ["SWITCH", "PDU", "ROUTER", "FIREWALL", "SERVER"]
            if typ in network_device_types:
                messagebox.showwarning(
                    "Network Device Detected",
                    f"Please add {typ} devices through the 'Network Equipment' tab.\n\n"
                    f"The warehouse interface is only for non-network items."
                )
                return
            
            new_id = self.store.add_item_MYBP86(typ, cab, shelf)
            messagebox.showinfo("Added", f"New ID: {new_id}")
            self.refresh_all()
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))

    def load_sample_data(self) -> None:
        """Load sample data into the database."""
        try:
            populate_sample_data_MYBP86(DB_PATH)
            messagebox.showinfo(
                "Sample Data Loaded", 
                "Sample data has been successfully loaded!\n\n"
                "This includes:\n"
                "• Sample warehouse items\n"
                "• Example PDUs and Switches\n"
                "• Various device configurations"
            )
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load sample data: {str(e)}")

    def clear_sample_data(self) -> None:
        """Clear sample data from the database."""
        result = messagebox.askyesno(
            "Clear Sample Data",
            "This will remove all items and network devices from the database.\n\n"
            "Are you sure you want to continue?"
        )
        if result:
            try:
                clear_sample_data_MYBP86(DB_PATH)
                messagebox.showinfo(
                    "Sample Data Cleared",
                    "All sample data has been successfully cleared!"
                )
                self.refresh_all()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear sample data: {str(e)}")

    def refresh_all(self) -> None:
        cabs = self.store.list_cabinets_MYBP86()
        self.cab_combo["values"] = cabs
        if cabs and self.cab_var.get() not in cabs:
            self.cab_var.set(cabs[0])
        self.draw_cabinets()
        # Summary removed - not needed in stack-based system
        # Hálózati adatok frissítése is
        self.refresh_network_data()
        # Check if Stack Management tab needs to be added/updated
        self._check_and_add_stack_management_tab()

    def draw_cabinets(self) -> None:
        for widget in self.grid_wrap.winfo_children():
            widget.destroy()

        occ = self.store.occupancy_MYBP86()
        cabs = self.store.list_cabinets_MYBP86()

        for i, cab in enumerate(cabs):
            frame = ttk.LabelFrame(self.grid_wrap, text=f"Cabinet {cab}")
            frame.grid(row=0, column=i, padx=8, pady=8, sticky="n")

            for s in range(6, 0, -1):
                loc = f"{cab}{s}"
                warehouse_count = occ.get(loc, 0)
                
                # Count network devices at this location
                network_devices = self.store.get_network_devices_MYBP86()
                network_count = len([d for d in network_devices
                                    if d.get('location') == loc])
                
                total_count = warehouse_count + network_count
                btn_text = f"{loc}\n{warehouse_count}W + {network_count}N"
                if total_count == 0:
                    btn_text = f"{loc}\nEmpty"
                
                btn = ttk.Button(frame, text=btn_text, width=15)
                btn.pack(fill="x", padx=6, pady=6, ipadx=4, ipady=8)
                btn.configure(
                    command=lambda C=cab, S=s: self.show_location(C, S)
                )

    def show_location(self, cabinet: str, shelf: int) -> None:
        win = tk.Toplevel(self)
        win.title(f"{cabinet}{shelf} contents")
        win.geometry("700x500")

        # Create notebook for different item types
        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)
        
        # Warehouse items tab
        warehouse_frame = ttk.Frame(notebook)
        notebook.add(warehouse_frame, text="Warehouse Items")
        
        cols = ("name", "type", "description")
        warehouse_tree = ttk.Treeview(warehouse_frame, columns=cols,
                                      show="headings")
        warehouse_tree.heading("name", text="Name")
        warehouse_tree.heading("type", text="Type")
        warehouse_tree.heading("description", text="Description")
        warehouse_tree.column("name", width=150)
        warehouse_tree.column("type", width=100)
        warehouse_tree.column("description", width=300)
        warehouse_tree.pack(fill="both", expand=True, padx=5, pady=5)

        items = self.store.get_items_by_location_MYBP86(cabinet, shelf)
        # Filter out network device types from warehouse items
        network_device_types = ["SWITCH", "PDU", "ROUTER", "FIREWALL", "SERVER"]
        for it in items:
            item_type = it.get("type", "N/A")
            if item_type not in network_device_types:
                warehouse_tree.insert("", "end", values=(
                    it.get("name", "N/A"),
                    item_type,
                    it.get("description", "")
                ))
        
        # Stack View tab - show switch stacks at this location
        stack_frame = ttk.Frame(notebook)
        notebook.add(stack_frame, text="Stack View")
        
        stack_cols = ("stack_name", "device_count", "description")
        stack_tree = ttk.Treeview(stack_frame, columns=stack_cols,
                                  show="headings")
        stack_tree.heading("stack_name", text="Stack Name")
        stack_tree.heading("device_count", text="Devices (Current/Max)")
        stack_tree.heading("description", text="Description")
        stack_tree.column("stack_name", width=200)
        stack_tree.column("device_count", width=150)
        stack_tree.column("description", width=350)
        stack_tree.pack(fill="both", expand=True, padx=5, pady=5)

        # Get switch stacks at this location
        location = f"{cabinet}{shelf}"
        
        # Get warehouse items that are stacks (switch and PDU)
        all_items = self.store.get_items_MYBP86()
        stacks = [item for item in all_items 
                 if (item.get('cabinet') == cabinet and 
                     str(item.get('shelf')) == str(shelf) and
                     item.get('type') in ['SWITCH STACK', 'PDU STACK'])]
        
        # Get switch groups at this location (for switch stacks)
        all_groups = self.store.get_switch_groups_MYBP86()
        groups_at_location = [group for group in all_groups 
                            if group.get('location') == location]
        
        # Display stacks (switch and PDU) with their corresponding groups
        # First, try to match stacks with groups by parsing stack name
        displayed_groups = set()
        
        for stack in stacks:
            stack_name = stack.get('name', '')
            stack_description = stack.get('description', '')
            stack_type = stack.get('type', '')
            
            if stack_type == 'SWITCH STACK':
                # Find corresponding switch group by matching stack name with group name
                corresponding_group = None
                for group in groups_at_location:
                    group_name = group.get('group_name', '')
                    # Match by exact name or similar name
                    if (group_name == stack_name or 
                        group_name.lower() == stack_name.lower()):
                        corresponding_group = group
                        displayed_groups.add(group_name)
                        break
                
                if corresponding_group:
                    # Count current switches in this stack (by location = stack_name)
                    all_switches = self.store.get_network_devices_MYBP86("Switch")
                    current_devices = len([switch for switch in all_switches if switch.get('location') == stack_name])
                    
                    max_devices = corresponding_group.get('max_switches', 0)
                    
                    # Determine status
                    if current_devices == 0:
                        status = "Empty"
                    elif current_devices >= max_devices:
                        status = "Full"
                    else:
                        status = "Active"
                    
                    stack_tree.insert("", "end", values=(
                        f"🔀 {stack_name}",  # Switch icon
                        f"{current_devices}/{max_devices}",
                        stack_description
                    ))
                else:
                    # Switch stack without corresponding group
                    stack_tree.insert("", "end", values=(
                        f"🔀 {stack_name}",
                        "N/A",
                        stack_description
                    ))
            
            elif stack_type == 'PDU STACK':
                # For PDU stacks, count PDUs that have this stack name as location
                max_pdus = 4  # Default value, could be extracted from description later
                all_pdus = self.store.get_network_devices_MYBP86("PDU")
                current_pdus = len([pdu for pdu in all_pdus if pdu.get('location') == stack_name])
                
                stack_tree.insert("", "end", values=(
                    f"⚡ {stack_name}",  # Power icon for PDU
                    f"{current_pdus}/{max_pdus}",
                    stack_description
                ))
        
        # Display any groups that don't have warehouse stack items
        for group in groups_at_location:
            group_name = group.get('group_name', '')
            if group_name not in displayed_groups:
                current_switches = len(self.store.get_switches_in_group_MYBP86(
                    location, group_name))
                
                max_switches = group.get('max_switches', 0)
                
                # Determine status
                if current_switches == 0:
                    status = "Empty"
                elif current_switches >= max_switches:
                    status = "Full"
                else:
                    status = "Active"
                
                stack_tree.insert("", "end", values=(
                    f"[Orphaned] {group_name}",
                    f"{current_switches}/{max_switches}",
                    f"Group without warehouse item: {group.get('description', '')}"
                ))

        # Stack management buttons
        stack_button_frame = ttk.Frame(stack_frame)
        stack_button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(stack_button_frame, text="View Stack Details",
                   command=lambda: self.view_stack_details(stack_tree, location)) \
                   .pack(side="left", padx=5)
        
        ttk.Button(stack_button_frame, text="Add Device to Stack",
                   command=lambda: self.add_device_to_stack(stack_tree, location)) \
                   .pack(side="left", padx=5)
        
        ttk.Button(stack_button_frame, text="Refresh",
                   command=lambda: self.refresh_stack_display(cabinet, shelf)) \
                   .pack(side="left", padx=5)
        
        ttk.Button(stack_button_frame, text="Manage Stack",
                   command=lambda: self.manage_stack(stack_tree, location)) \
                   .pack(side="left", padx=5)

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=6)

    def view_switch_contents(self, switch_tree, shelf_location) -> None:
        """View contents of selected switch."""
        selection = switch_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a switch first!")
            return
        
        item = switch_tree.item(selection[0])
        switch_name = item['values'][0]
        
        # Create switch contents window
        switch_win = tk.Toplevel(self)
        switch_win.title(f"Contents of {switch_name}")
        switch_win.geometry("600x400")
        switch_win.transient(self)
        
        ttk.Label(switch_win, text=f"Devices connected to {switch_name}",
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        # Device list
        device_cols = ("hostname", "device_type", "ip_address", "status")
        device_tree = ttk.Treeview(switch_win, columns=device_cols,
                                   show="headings")
        device_tree.heading("hostname", text="Hostname")
        device_tree.heading("device_type", text="Type")
        device_tree.heading("ip_address", text="IP Address")
        device_tree.heading("status", text="Status")
        device_tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Populate with devices in this switch location
        all_devices = self.store.get_network_devices_MYBP86()
        devices_in_switch = [d for d in all_devices
                           if d.get("location") == switch_name]
        
        for device in devices_in_switch:
            device_tree.insert("", "end", values=(
                device.get("hostname", "N/A"),
                device.get("device_type", "N/A"),
                device.get("ip_address", "N/A"),
                device.get("status", "N/A")
            ))
        
        # Management buttons
        button_frame = ttk.Frame(switch_win)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Move Device",
                   command=lambda: self.move_network_device(device_tree)) \
                   .pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Device Details",
                   command=lambda: self.show_network_device_details(device_tree)) \
                   .pack(side="left", padx=5)
        
        ttk.Button(switch_win, text="Close", command=switch_win.destroy).pack(pady=10)

    def move_network_device(self, tree_widget) -> None:
        """Move selected network device to different location."""
        selection = tree_widget.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a device first!")
            return
        
        item = tree_widget.item(selection[0])
        hostname = item['values'][0]
        device_type = item['values'][1]
        
        # Find device in database
        all_devices = self.store.get_network_devices_MYBP86()
        device = None
        for d in all_devices:
            if d.get('hostname') == hostname and d.get('device_type') == device_type:
                device = d
                break
        
        if not device:
            messagebox.showerror("Error", "Device not found in database!")
            return
        
        # Show location selection dialog
        self.show_move_device_dialog(device)

    def show_move_device_dialog(self, device) -> None:
        """Show dialog to select new location for device."""
        dialog = tk.Toplevel(self)
        dialog.title(f"Move {device.get('hostname')}")
        dialog.geometry("400x300")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Moving: {device.get('hostname')} ({device.get('device_type')})").pack(pady=10)
        ttk.Label(dialog, text=f"Current location: {device.get('location')}").pack(pady=5)
        
        ttk.Label(dialog, text="Select new location:").pack(pady=10)
        
        location_var = tk.StringVar()
        all_locations = get_available_locations_MYBP86(DB_PATH)
        location_combo = ttk.Combobox(dialog, textvariable=location_var,
                                     values=all_locations, state="readonly")
        location_combo.pack(pady=5)
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        def do_move():
            new_location = location_var.get()
            if not new_location:
                messagebox.showwarning("Warning", "Please select a location!")
                return
            
            # Update device location in database
            success = self.store.update_network_device_MYBP86(
                device.get('serial_number'), location=new_location)
            
            if success:
                messagebox.showinfo("Success", 
                                   f"Device moved to {new_location}")
                dialog.destroy()
                self.refresh_all()  # Refresh everything
            else:
                messagebox.showerror("Error", "Failed to move device!")
        
        ttk.Button(button_frame, text="Move", command=do_move).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side="left", padx=5)

    def show_network_device_details(self, tree_widget) -> None:
        """Show detailed information about selected network device."""
        selection = tree_widget.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a device first!")
            return
        
        item = tree_widget.item(selection[0])
        hostname = item['values'][0]
        device_type = item['values'][1]
        
        # Find device in database
        all_devices = self.store.get_network_devices_MYBP86()
        device = None
        for d in all_devices:
            if d.get('hostname') == hostname and d.get('device_type') == device_type:
                device = d
                break
        
        if not device:
            messagebox.showerror("Error", "Device not found in database!")
            return
        
        # Show details dialog
        details_dialog = tk.Toplevel(self)
        details_dialog.title(f"Device Details: {hostname}")
        details_dialog.geometry("500x400")
        details_dialog.transient(self)
        
        # Create scrollable text widget
        text_frame = ttk.Frame(details_dialog)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(text_frame, wrap="word")
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Insert device details
        details_text = f"""Device Details:

Hostname: {device.get('hostname', 'N/A')}
Device Type: {device.get('device_type', 'N/A')}
Serial Number: {device.get('serial_number', 'N/A')}
IP Address: {device.get('ip_address', 'N/A')}
MAC Address: {device.get('mac_address', 'N/A')}
Model: {device.get('model', 'N/A')}
Location: {device.get('location', 'N/A')}
Port Count: {device.get('port_count', 'N/A')}
Status: {device.get('status', 'N/A')}
Description: {device.get('description', 'N/A')}
Created: {device.get('created_at', 'N/A')}
Updated: {device.get('updated_at', 'N/A')}
"""
        text_widget.insert("1.0", details_text)
        text_widget.config(state="disabled")
        
        ttk.Button(details_dialog, text="Close", command=details_dialog.destroy).pack(pady=10)

    # update_summaries function removed - not needed in stack-based system

    # Hálózati eszköz kezelő metódusok
    def add_pdu(self) -> None:
        # First update location dropdown with current available locations
        self.update_location_combos()
        
        try:
            location = self.pdu_location_var.get().strip()
            if not location:
                messagebox.showerror("Error", "Please select a location!")
                return
            
            # Auto-generate unique serial number if empty
            serial_number = self.pdu_serial_var.get().strip()
            if not serial_number:
                serial_number = self.generate_unique_serial_number("PDU", location)
                self.pdu_serial_var.set(serial_number)
            
            pdu = PDU(
                serial_number=serial_number,
                hostname=self.pdu_hostname_var.get().strip(),
                ip_address=self.pdu_ip_var.get().strip(),
                mac_address=self.pdu_mac_var.get().strip(),
                outlet_count=self.pdu_outlets_var.get(),
                manufacturer=self.pdu_manufacturer_var.get().strip(),
                model=self.pdu_model_var.get().strip(),
                location=location
            )
            
            # Először adatbázisba mentés
            success = self.store.add_network_device_MYBP86(
                device_type="PDU",
                hostname=pdu.hostname,
                ip_address=pdu.ip_address,
                mac_address=pdu.mac_address,
                serial_number=pdu.serial_number,
                model=pdu.model,
                location=pdu.location,
                port_count=pdu.outlet_count,
                status="active",
                description=f"PDU with {pdu.outlet_count} outlets"
            )
            
            if success:
                # Memóriába is hozzáadjuk
                self.network_manager.add_device(pdu)
                messagebox.showinfo("Success",
                                    f"PDU {pdu.hostname} added!")
                self.clear_pdu_form()
                self.refresh_network_data()
            else:
                messagebox.showerror("Error",
                                     "Failed to save PDU to database!")
        except ValueError as e:
            messagebox.showerror("Validation Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add PDU: {str(e)}")

    def generate_switch_hostname(self, location: str) -> str:
        """Generate next available switch hostname for location."""
        if not location:
            return "Switch-001"
        
        # Get existing switches at this location
        existing_switches = self.store.get_network_devices_MYBP86("Switch")
        location_switches = [s for s in existing_switches
                             if s.get('location') == location]
        
        # Find highest switch number
        max_num = 0
        prefix = f"{location}-Switch"
        for switch in location_switches:
            hostname = switch.get('hostname', '')
            if hostname.startswith(prefix):
                try:
                    num_str = hostname[len(prefix):]
                    num = int(num_str)
                    max_num = max(max_num, num)
                except ValueError:
                    continue
        
        return f"{prefix}{max_num + 1}"

    def update_location_dropdown_on_demand(self, combo_widget, device_type="ALL"):
        """Update location dropdown when user clicks Add button."""
        try:
            # Get available stack locations from database
            shelf_locations = get_available_locations_MYBP86(DB_PATH)
            
            # Get stack names from warehouse items
            stack_locations = []
            all_items = self.store.get_items_MYBP86()
            for item in all_items:
                if item.get('type') in ['SWITCH STACK', 'PDU STACK']:
                    stack_name = item.get('name', '')
                    if stack_name:
                        stack_locations.append(stack_name)
            
            if device_type == "PDU":
                # PDU can go to shelf locations, switch locations, OR PDU stacks
                switch_devices = self.store.get_network_devices_MYBP86("Switch")
                switch_locations = []
                for switch in switch_devices:
                    switch_hostname = switch.get('hostname', '')
                    if switch_hostname and '-Switch' in switch_hostname:
                        switch_locations.append(switch_hostname)
                
                # Include PDU stacks for PDUs
                pdu_stacks = [stack for stack in stack_locations if any(
                    item.get('name') == stack and item.get('type') == 'PDU STACK' 
                    for item in all_items)]
                
                all_locations = shelf_locations + switch_locations + pdu_stacks
                combo_widget["values"] = all_locations
                
            elif device_type == "Switch":
                # Switches can go to shelf locations OR switch stacks
                switch_stacks = [stack for stack in stack_locations if any(
                    item.get('name') == stack and item.get('type') == 'SWITCH STACK' 
                    for item in all_items)]
                
                all_locations = shelf_locations + switch_stacks
                combo_widget["values"] = all_locations
            else:
                # For other device types, show all locations
                all_locations = shelf_locations + stack_locations
                combo_widget["values"] = all_locations
                
        except Exception as e:
            print(f"Error updating location dropdown: {e}")

    def generate_unique_serial_number(self, device_type: str, location: str) -> str:
        """Generate unique serial number for device at specific location."""
        # Get existing devices at this location
        all_devices = self.store.get_network_devices_MYBP86()
        devices_at_location = [d for d in all_devices 
                              if d.get('location') == location and 
                                 d.get('device_type') == device_type]
        
        # Find highest number for this device type at this location
        max_num = 0
        prefix = f"{location}_{device_type.upper()}_"
        
        for device in devices_at_location:
            serial = device.get('serial_number', '')
            if serial.startswith(prefix):
                try:
                    num_str = serial[len(prefix):]
                    num = int(num_str.zfill(3)[-3:])  # Take last 3 digits
                    max_num = max(max_num, num)
                except (ValueError, IndexError):
                    continue
        
        return f"{prefix}{max_num + 1:03d}"

    def add_switch(self) -> None:
        # First update location dropdown with current available locations
        self.update_location_combos()
        
        try:
            location = self.switch_location_var.get().strip()
            switch_stack = self.switch_stack_var.get().strip()
            
            if not location:
                messagebox.showerror("Error", "Please select a location!")
                return
            
            if not switch_stack:
                messagebox.showerror("Error", "Please select a switch stack!")
                return
            
            # Check if the selected stack has capacity
            # In new system, location IS the stack name, so we check capacity differently
            try:
                # Get the switch group/stack information
                all_groups = self.store.get_switch_groups_MYBP86()
                selected_stack = None
                for group in all_groups:
                    if group.get('group_name') == switch_stack:
                        selected_stack = group
                        break
                
                if not selected_stack:
                    messagebox.showerror("Error", 
                                       f"Switch stack '{switch_stack}' does not exist!")
                    return
                
                # Check capacity
                current_switches = len(self.store.get_switches_in_group_MYBP86(
                    selected_stack.get('location'), switch_stack))
                max_switches = selected_stack.get('max_switches', 6)
                
                if current_switches >= max_switches:
                    messagebox.showerror("Error", 
                                       f"Switch stack '{switch_stack}' is full! ({current_switches}/{max_switches})")
                    return
                    
            except Exception as e:
                messagebox.showerror("Error", f"Error checking stack capacity: {str(e)}")
                return
            
            # Auto-generate hostname if empty (now includes stack)
            hostname = self.switch_hostname_var.get().strip()
            if not hostname:
                hostname = self.generate_switch_hostname_for_stack(location, switch_stack)
                # Also update the UI field to show the generated hostname
                self.switch_hostname_var.set(hostname)
            
            # Auto-generate unique serial number if empty
            serial_number = self.switch_serial_var.get().strip()
            if not serial_number:
                serial_number = self.generate_unique_serial_number("Switch", location)
                self.switch_serial_var.set(serial_number)
            
            switch = Switch(
                serial_number=serial_number,
                hostname=hostname,
                ip_address=self.switch_ip_var.get().strip(),
                mac_address=self.switch_mac_var.get().strip(),
                port_count=self.switch_ports_var.get(),
                manufacturer=self.switch_manufacturer_var.get().strip(),
                model=self.switch_model_var.get().strip(),
                location=location
            )
            
            # Save to database with switch stack
            # In new system, location field should be the stack name for proper device counting
            success = self.store.add_network_device_MYBP86(
                device_type="Switch",
                hostname=switch.hostname,
                ip_address=switch.ip_address,
                mac_address=switch.mac_address,
                serial_number=switch.serial_number,
                model=switch.model,
                location=switch_stack,  # Use stack name as location for device counting
                port_count=switch.port_count,
                status="active",
                description=f"Switch with {switch.port_count} ports in stack {switch_stack}",
                switch_group=switch_stack  # Use switch_group field to store stack name
            )
            
            # In stack-based system, we don't need virtual locations
            # Each device is directly in the stack
            
            if success:
                # Memóriába is hozzáadjuk
                self.network_manager.add_device(switch)
                messagebox.showinfo("Success",
                                    f"Switch {switch.hostname} added to stack {switch_stack}!")
                self.clear_switch_form()
                self.refresh_network_data()
            else:
                messagebox.showerror("Error",
                                     "Failed to save Switch to database!")
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
        self.switch_stack_var.set("")
        self.switch_ports_var.set(24)
        self.switch_manufacturer_var.set("")
        self.switch_model_var.set("")

    def get_network_device_locations(self, device_type: str) -> List[str]:
        """Get locations where specific device type exists."""
        try:
            devices = self.store.get_network_devices_MYBP86(device_type)
            locations = set()
            for device in devices:
                if device.get('location'):
                    locations.add(device.get('location'))
            return sorted(list(locations))
        except Exception as e:
            print(f"Error getting {device_type} locations: {e}")
            return []

    def update_location_combos(self) -> None:
        """Update location comboboxes with stack names only."""
        try:
            # Get PDU stack names from warehouse
            pdu_stack_names = []
            warehouse_items = self.store.get_items_MYBP86()
            for item in warehouse_items:
                if item.get('type') == 'PDU STACK':  # Note: uppercase
                    stack_name = item.get('name')
                    if stack_name:
                        pdu_stack_names.append(stack_name)
            
            # Get Switch stack names from switch_groups table
            switch_stack_names = []
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT group_name FROM switch_groups")
                rows = cursor.fetchall()
                switch_stack_names = [row[0] for row in rows]
            
            self.pdu_location_combo["values"] = pdu_stack_names
            self.switch_location_combo["values"] = switch_stack_names
        except Exception as e:
            print(f"Error updating location combos: {e}")

    def refresh_network_data(self) -> None:
        # Reload devices from database first
        self._load_network_devices_from_db()
        
        # Location dropdowns will be updated on-demand when Add buttons are clicked
        
        # PDU lista frissítése adatbázisból
        for item in self.pdu_tree.get_children():
            self.pdu_tree.delete(item)
        
        pdu_devices = self.store.get_network_devices_MYBP86("PDU")
        for pdu in pdu_devices:
            self.pdu_tree.insert("", "end", values=(
                pdu.get('serial_number', ''),
                pdu.get('hostname', ''),
                pdu.get('ip_address', ''),
                pdu.get('location', ''),
                pdu.get('port_count', 8),
                pdu.get('status', 'offline')
            ))
        
        # Switch lista frissítése adatbázisból
        for item in self.switch_tree.get_children():
            self.switch_tree.delete(item)
        
        switch_devices = self.store.get_network_devices_MYBP86("Switch")
        for switch in switch_devices:
            self.switch_tree.insert("", "end", values=(
                switch.get('serial_number', ''),
                switch.get('hostname', ''),
                switch.get('ip_address', ''),
                switch.get('location', ''),
                switch.get('port_count', 24),
                switch.get('status', 'offline')
            ))
        
        # Network summary frissítése adatbázisból
        pdu_devices = self.store.get_network_devices_MYBP86("PDU")
        switch_devices = self.store.get_network_devices_MYBP86("Switch")
        all_devices = pdu_devices + switch_devices
        pdu_count = len(pdu_devices)
        switch_count = len(switch_devices)
        online_count = len([d for d in all_devices
                           if d.get('status') in ['active', 'online']])
        
        summary_text = (
            f"Total Devices: {len(all_devices)} | "
            f"PDUs: {pdu_count} | "
            f"Switches: {switch_count} | "
            f"Online: {online_count}")
        self.network_summary_label.config(text=summary_text)
        
        # Location lista frissítése adatbázisból
        locations = set()
        for device in all_devices:
            location = device.get('location', '').strip()
            if location:
                locations.add(location)
        
        self.location_combo['values'] = sorted(list(locations))
        
        # Update location combos with stack names
        self.update_location_combos()
        
        # Also refresh Stack View if it exists
        if hasattr(self, 'stacks_tree'):
            self.refresh_stack_management()

    def get_selected_pdu(self):
        """Get the currently selected PDU from the tree."""
        selection = self.pdu_tree.selection()
        if not selection:
            return None
        
        item = self.pdu_tree.item(selection[0])
        serial_number = item['values'][0]
        
        # Get PDU from database
        devices = self.store.get_network_devices_MYBP86("PDU")
        for device in devices:
            if device.get('serial_number') == serial_number:
                return device
        return None

    def edit_pdu(self) -> None:
        """Edit the selected PDU."""
        pdu = self.get_selected_pdu()
        if not pdu:
            messagebox.showwarning("Selection", "Please select a PDU first!")
            return
        
        self.show_pdu_edit_dialog(pdu)

    def delete_pdu(self) -> None:
        """Delete the selected PDU."""
        pdu = self.get_selected_pdu()
        if not pdu:
            messagebox.showwarning("Selection", "Please select a PDU first!")
            return
        
        result = messagebox.askyesno(
            "Delete PDU",
            f"Are you sure you want to delete PDU '{pdu.get('hostname')}'?\n"
            f"This action cannot be undone."
        )
        
        if result:
            try:
                # Remove from database using direct SQL
                import sqlite3
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM network_devices WHERE serial_number = ?", 
                                   (pdu.get('serial_number'),))
                    conn.commit()
                    success = cursor.rowcount > 0
                
                if success:
                    # Remove from network manager
                    serial_num = pdu.get('serial_number')
                    if serial_num in self.network_manager.devices:
                        del self.network_manager.devices[serial_num]
                    
                    messagebox.showinfo("Success",
                                        f"PDU '{pdu.get('hostname')}' deleted!")
                    self.refresh_network_data()
                else:
                    messagebox.showerror("Error", "Failed to delete PDU!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete PDU: {str(e)}")

    def view_pdu_details(self) -> None:
        pdu = self.get_selected_pdu()
        if not pdu:
            messagebox.showwarning("Selection", "Please select a PDU first!")
            return
        
        # Convert database record to PDU object for display
        pdu_obj = self.network_manager.get_device(pdu.get('serial_number'))
        if not pdu_obj:
            # Create temporary PDU object from database data
            from network_equipment import PDU
            pdu_obj = PDU(
                serial_number=pdu.get('serial_number', ''),
                hostname=pdu.get('hostname', ''),
                ip_address=pdu.get('ip_address', ''),
                mac_address=pdu.get('mac_address', ''),
                outlet_count=pdu.get('port_count', 8),
                manufacturer=pdu.get('manufacturer', ''),
                model=pdu.get('model', ''),
                location=pdu.get('location', '')
            )
        
        self.show_pdu_details(pdu_obj)

    def show_pdu_edit_dialog(self, pdu_data) -> None:
        """Show dialog to edit PDU information."""
        win = tk.Toplevel(self)
        win.title(f"Edit PDU - {pdu_data.get('hostname')}")
        win.geometry("500x400")
        win.resizable(False, False)
        
        # Make dialog modal
        win.transient(self)
        win.grab_set()
        
        # Edit form
        edit_frame = ttk.LabelFrame(win, text="PDU Information")
        edit_frame.pack(fill="x", padx=10, pady=5)
        
        # Hostname (read-only)
        ttk.Label(edit_frame, text="Hostname:").grid(
            row=0, column=0, sticky="w", padx=5, pady=2)
        hostname_var = tk.StringVar(value=pdu_data.get('hostname', ''))
        ttk.Entry(edit_frame, textvariable=hostname_var,
                  state="readonly", width=20).grid(
                      row=0, column=1, padx=5, pady=2)
        
        # IP Address
        ttk.Label(edit_frame, text="IP Address:").grid(
            row=1, column=0, sticky="w", padx=5, pady=2)
        ip_var = tk.StringVar(value=pdu_data.get('ip_address', ''))
        ttk.Entry(edit_frame, textvariable=ip_var,
                  width=20).grid(row=1, column=1, padx=5, pady=2)
        
        # MAC Address
        ttk.Label(edit_frame, text="MAC Address:").grid(
            row=2, column=0, sticky="w", padx=5, pady=2)
        mac_var = tk.StringVar(value=pdu_data.get('mac_address', ''))
        ttk.Entry(edit_frame, textvariable=mac_var,
                  width=20).grid(row=2, column=1, padx=5, pady=2)
        
        # Model
        ttk.Label(edit_frame, text="Model:").grid(
            row=3, column=0, sticky="w", padx=5, pady=2)
        model_var = tk.StringVar(value=pdu_data.get('model', ''))
        ttk.Entry(edit_frame, textvariable=model_var,
                  width=20).grid(row=3, column=1, padx=5, pady=2)
        
        # Outlet Count
        ttk.Label(edit_frame, text="Outlet Count:").grid(
            row=4, column=0, sticky="w", padx=5, pady=2)
        outlets_var = tk.IntVar(value=pdu_data.get('port_count', 8))
        ttk.Spinbox(edit_frame, from_=4, to=24, width=18,
                    textvariable=outlets_var).grid(row=4, column=1, padx=5, pady=2)
        
        # Status
        ttk.Label(edit_frame, text="Status:").grid(
            row=5, column=0, sticky="w", padx=5, pady=2)
        status_var = tk.StringVar(value=pdu_data.get('status', 'active'))
        status_combo = ttk.Combobox(edit_frame, textvariable=status_var,
                                    values=['active', 'inactive', 'maintenance'],
                                    state="readonly", width=18)
        status_combo.grid(row=5, column=1, padx=5, pady=2)
        
        def save_changes():
            try:
                # Update in database
                success = self.store.update_network_device_MYBP86(
                    pdu_data.get('serial_number'),
                    ip_address=ip_var.get().strip(),
                    mac_address=mac_var.get().strip(),
                    model=model_var.get().strip(),
                    port_count=outlets_var.get(),
                    status=status_var.get()
                )
                
                if success:
                    messagebox.showinfo("Success", "PDU updated successfully!")
                    win.destroy()
                    self.refresh_network_data()
                else:
                    messagebox.showerror("Error", "Failed to update PDU!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update: {str(e)}")
        
        # Buttons
        button_frame = ttk.Frame(win)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Save Changes",
                   command=save_changes).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel",
                   command=win.destroy).pack(side="left", padx=5)

    def get_selected_switch(self):
        """Get the currently selected switch from the tree."""
        selection = self.switch_tree.selection()
        if not selection:
            return None
        
        item = self.switch_tree.item(selection[0])
        serial_number = item['values'][0]
        
        # Get switch from database
        devices = self.store.get_network_devices_MYBP86("Switch")
        for device in devices:
            if device.get('serial_number') == serial_number:
                return device
        return None

    def edit_switch(self) -> None:
        """Edit the selected switch."""
        switch = self.get_selected_switch()
        if not switch:
            messagebox.showwarning("Selection", "Please select a Switch first!")
            return
        
        self.show_switch_edit_dialog(switch)

    def delete_switch(self) -> None:
        """Delete the selected switch."""
        switch = self.get_selected_switch()
        if not switch:
            messagebox.showwarning("Selection", "Please select a Switch first!")
            return
        
        result = messagebox.askyesno(
            "Delete Switch",
            f"Are you sure you want to delete switch '{switch.get('hostname')}'?\n"
            f"This action cannot be undone."
        )
        
        if result:
            try:
                # Remove from database using direct SQL
                import sqlite3
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM network_devices WHERE serial_number = ?",
                                   (switch.get('serial_number'),))
                    conn.commit()
                    success = cursor.rowcount > 0
                
                if success:
                    # Remove from network manager
                    serial_num = switch.get('serial_number')
                    if serial_num in self.network_manager.devices:
                        del self.network_manager.devices[serial_num]
                    
                    messagebox.showinfo("Success",
                                        f"Switch '{switch.get('hostname')}' deleted!")
                    self.refresh_network_data()
                else:
                    messagebox.showerror("Error", "Failed to delete switch!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete switch: {str(e)}")

    def view_switch_details(self) -> None:
        switch = self.get_selected_switch()
        if not switch:
            messagebox.showwarning("Selection",
                                   "Please select a Switch first!")
            return
        
        # Convert database record to switch object for display
        switch_obj = self.network_manager.get_device(switch.get('serial_number'))
        if not switch_obj:
            # Create temporary switch object from database data
            from network_equipment import Switch
            switch_obj = Switch(
                serial_number=switch.get('serial_number', ''),
                hostname=switch.get('hostname', ''),
                ip_address=switch.get('ip_address', ''),
                mac_address=switch.get('mac_address', ''),
                port_count=switch.get('port_count', 24),
                manufacturer=switch.get('manufacturer', ''),
                model=switch.get('model', ''),
                location=switch.get('location', '')
            )
        
        self.show_switch_details(switch_obj)

    def show_switch_edit_dialog(self, switch_data) -> None:
        """Show dialog to edit switch information."""
        win = tk.Toplevel(self)
        win.title(f"Edit Switch - {switch_data.get('hostname')}")
        win.geometry("500x400")
        win.resizable(False, False)
        
        # Make dialog modal
        win.transient(self)
        win.grab_set()
        
        # Edit form
        edit_frame = ttk.LabelFrame(win, text="Switch Information")
        edit_frame.pack(fill="x", padx=10, pady=5)
        
        # Hostname (read-only)
        ttk.Label(edit_frame, text="Hostname:").grid(
            row=0, column=0, sticky="w", padx=5, pady=2)
        hostname_var = tk.StringVar(value=switch_data.get('hostname', ''))
        ttk.Entry(edit_frame, textvariable=hostname_var,
                  state="readonly", width=20).grid(
                      row=0, column=1, padx=5, pady=2)
        
        # IP Address
        ttk.Label(edit_frame, text="IP Address:").grid(
            row=1, column=0, sticky="w", padx=5, pady=2)
        ip_var = tk.StringVar(value=switch_data.get('ip_address', ''))
        ttk.Entry(edit_frame, textvariable=ip_var,
                  width=20).grid(row=1, column=1, padx=5, pady=2)
        
        # MAC Address
        ttk.Label(edit_frame, text="MAC Address:").grid(
            row=2, column=0, sticky="w", padx=5, pady=2)
        mac_var = tk.StringVar(value=switch_data.get('mac_address', ''))
        ttk.Entry(edit_frame, textvariable=mac_var,
                  width=20).grid(row=2, column=1, padx=5, pady=2)
        
        # Model
        ttk.Label(edit_frame, text="Model:").grid(
            row=3, column=0, sticky="w", padx=5, pady=2)
        model_var = tk.StringVar(value=switch_data.get('model', ''))
        ttk.Entry(edit_frame, textvariable=model_var,
                  width=20).grid(row=3, column=1, padx=5, pady=2)
        
        # Port Count
        ttk.Label(edit_frame, text="Port Count:").grid(
            row=4, column=0, sticky="w", padx=5, pady=2)
        ports_var = tk.IntVar(value=switch_data.get('port_count', 24))
        ttk.Spinbox(edit_frame, from_=8, to=48, width=18,
                    textvariable=ports_var).grid(row=4, column=1, padx=5, pady=2)
        
        # Status
        ttk.Label(edit_frame, text="Status:").grid(
            row=5, column=0, sticky="w", padx=5, pady=2)
        status_var = tk.StringVar(value=switch_data.get('status', 'active'))
        status_combo = ttk.Combobox(edit_frame, textvariable=status_var,
                                    values=['active', 'inactive', 'maintenance'],
                                    state="readonly", width=18)
        status_combo.grid(row=5, column=1, padx=5, pady=2)
        
        def save_changes():
            try:
                # Update in database
                success = self.store.update_network_device_MYBP86(
                    switch_data.get('serial_number'),
                    ip_address=ip_var.get().strip(),
                    mac_address=mac_var.get().strip(),
                    model=model_var.get().strip(),
                    port_count=ports_var.get(),
                    status=status_var.get()
                )
                
                if success:
                    messagebox.showinfo("Success", "Switch updated successfully!")
                    win.destroy()
                    self.refresh_network_data()
                else:
                    messagebox.showerror("Error", "Failed to update switch!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update: {str(e)}")
        
        # Buttons
        button_frame = ttk.Frame(win)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Save Changes",
                   command=save_changes).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel",
                   command=win.destroy).pack(side="left", padx=5)

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
                row=i//2, column=(i % 2)*2, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, text=value, font=("", 9, "bold")).grid(
                row=i//2, column=(i % 2)*2+1, sticky="w", padx=5, pady=2)
        
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
                row=i//2, column=(i % 2)*2, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, text=value, font=("", 9, "bold")).grid(
                row=i//2, column=(i % 2)*2+1, sticky="w", padx=5, pady=2)
        
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
        
        # Populate devices in location
        devices = self.network_manager.get_devices_by_location(location)
        for device in devices:
            device_info = f"{device.hostname} ({device.serial_number})"
            if device.device_type == 'PDU':
                self.location_pdu_listbox.insert(tk.END, device_info)
            elif device.device_type == 'Switch':
                self.location_switch_listbox.insert(tk.END, device_info)

    def _build_switch_group_ui(self):
        """Build the switch group management interface"""
        # Control frame for group operations
        control_frame = ttk.Frame(self.switch_group_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Left panel for group creation
        left_frame = ttk.LabelFrame(control_frame, text="Switch Group Creation")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Location selection for group
        ttk.Label(left_frame, text="Location:").pack(anchor=tk.W, padx=5, pady=2)
        
        self.group_location_var = tk.StringVar()
        self.group_location_dropdown = ttk.Combobox(left_frame, textvariable=self.group_location_var, 
                                                   state="readonly", width=30)
        self.group_location_dropdown.pack(fill=tk.X, padx=5, pady=2)
        
        # Update locations when dropdown is clicked - include warehouse locations
        self.group_location_dropdown.bind("<Button-1>", lambda e: self.update_warehouse_locations_for_groups())
        
        # Group name
        ttk.Label(left_frame, text="Group Name:").pack(anchor=tk.W, padx=5, pady=2)
        self.group_name_var = tk.StringVar()
        group_name_entry = ttk.Entry(left_frame, textvariable=self.group_name_var, width=30)
        group_name_entry.pack(fill=tk.X, padx=5, pady=2)
        
        # Maximum switches in group
        ttk.Label(left_frame, text="Max Switches:").pack(anchor=tk.W, padx=5, pady=2)
        self.group_max_switches_var = tk.StringVar(value="6")
        max_switches_entry = ttk.Entry(left_frame, textvariable=self.group_max_switches_var, width=30)
        max_switches_entry.pack(fill=tk.X, padx=5, pady=2)
        
        # Description
        ttk.Label(left_frame, text="Description:").pack(anchor=tk.W, padx=5, pady=2)
        self.group_description_var = tk.StringVar()
        description_entry = ttk.Entry(left_frame, textvariable=self.group_description_var, width=30)
        description_entry.pack(fill=tk.X, padx=5, pady=2)
        
        # Create group button
        create_group_btn = ttk.Button(left_frame, text="Create Switch Group", 
                                     command=self.create_switch_group)
        create_group_btn.pack(pady=10, padx=5)
        
        # Right panel for group management
        right_frame = ttk.LabelFrame(control_frame, text="Group Management")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Button frame
        button_frame = ttk.Frame(right_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Refresh Groups", 
                  command=self.refresh_switch_groups).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Delete Group", 
                  command=self.delete_switch_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="View Group Details", 
                  command=self.view_group_details).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Manage Groups", 
                  command=self.open_group_management_window).pack(side=tk.LEFT, padx=2)
        
        # Switch groups list
        list_frame = ttk.Frame(self.switch_group_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Groups tree
        self.groups_tree = ttk.Treeview(list_frame, columns=("Location", "GroupName", "MaxSwitches", 
                                                           "CurrentSwitches", "Description"), show="headings")
        
        # Define headings
        self.groups_tree.heading("Location", text="Location")
        self.groups_tree.heading("GroupName", text="Group Name")
        self.groups_tree.heading("MaxSwitches", text="Max Switches")
        self.groups_tree.heading("CurrentSwitches", text="Current Switches")
        self.groups_tree.heading("Description", text="Description")
        
        # Configure column widths
        self.groups_tree.column("Location", width=120)
        self.groups_tree.column("GroupName", width=150)
        self.groups_tree.column("MaxSwitches", width=100)
        self.groups_tree.column("CurrentSwitches", width=120)
        self.groups_tree.column("Description", width=200)
        
        # Scrollbar for groups tree
        groups_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.groups_tree.yview)
        self.groups_tree.configure(yscrollcommand=groups_scrollbar.set)
        
        # Pack tree and scrollbar
        self.groups_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        groups_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial refresh
        self.refresh_switch_groups()

    def create_switch_group(self):
        """Create a new switch group"""
        try:
            # Get form data
            location = self.group_location_var.get().strip()
            group_name = self.group_name_var.get().strip()
            max_switches = int(self.group_max_switches_var.get().strip())
            description = self.group_description_var.get().strip()
            
            # Validate input
            if not location:
                messagebox.showerror("Error", "Please select a location!")
                return
            
            if not group_name:
                messagebox.showerror("Error", "Please enter a group name!")
                return
            
            if max_switches <= 0 or max_switches > 48:
                messagebox.showerror("Error", "Max switches must be between 1 and 48!")
                return
            
            # Check if group already exists at this location
            existing_groups = self.store.get_switch_groups_MYBP86()
            for group in existing_groups:
                if (group.get('location') == location and 
                    group.get('group_name') == group_name):
                    messagebox.showerror("Error", 
                                       f"Group '{group_name}' already exists at {location}!")
                    return
            
            # Create the group
            success = self.store.add_switch_group_MYBP86(
                location=location,
                group_name=group_name,
                max_switches=max_switches,
                description=description
            )
            
            if success:
                messagebox.showinfo("Success", 
                                   f"Switch group '{group_name}' created at {location}!")
                # Clear form
                self.group_name_var.set("")
                self.group_description_var.set("")
                self.group_max_switches_var.set("6")
                # Refresh the groups list
                self.refresh_switch_groups()
            else:
                messagebox.showerror("Error", "Failed to create switch group!")
        
        except ValueError as e:
            messagebox.showerror("Validation Error", f"Invalid max switches value: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create switch group: {str(e)}")

    def refresh_switch_groups(self):
        """Refresh the switch groups display - now deprecated, stacks are used instead"""
        # This method is kept for compatibility but does nothing
        # since we switched from groups to stacks
        pass

    def delete_switch_group(self):
        """Delete selected switch group"""
        selection = self.groups_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a group to delete!")
            return
        
        item = self.groups_tree.item(selection[0])
        location = item['values'][0]
        group_name = item['values'][1]
        current_switches = item['values'][3]
        
        if current_switches > 0:
            messagebox.showerror("Error", 
                               f"Cannot delete group '{group_name}' - it contains {current_switches} switches!\n"
                               "Please move or remove all switches first.")
            return
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", 
                                   f"Are you sure you want to delete the group '{group_name}' at {location}?"):
            return
        
        try:
            success = self.store.delete_switch_group_MYBP86(location, group_name)
            if success:
                messagebox.showinfo("Success", f"Switch group '{group_name}' deleted!")
                self.refresh_switch_groups()
            else:
                messagebox.showerror("Error", "Failed to delete switch group!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete switch group: {str(e)}")

    def view_group_details(self):
        """View details of selected switch group"""
        selection = self.groups_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a group to view!")
            return
        
        item = self.groups_tree.item(selection[0])
        location = item['values'][0]
        group_name = item['values'][1]
        
        # Create details window
        details_window = tk.Toplevel(self)
        details_window.title(f"Group Details: {group_name} at {location}")
        details_window.geometry("600x500")
        details_window.transient(self)
        
        # Group info
        info_frame = ttk.LabelFrame(details_window, text="Group Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Location: {location}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Group Name: {group_name}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Max Switches: {item['values'][2]}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Current Switches: {item['values'][3]}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Description: {item['values'][4]}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Switches in group
        switches_frame = ttk.LabelFrame(details_window, text="Switches in Group")
        switches_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        switches_tree = ttk.Treeview(switches_frame, 
                                   columns=("Hostname", "SerialNumber", "IPAddress", "Status"), 
                                   show="headings")
        
        switches_tree.heading("Hostname", text="Hostname")
        switches_tree.heading("SerialNumber", text="Serial Number")
        switches_tree.heading("IPAddress", text="IP Address")
        switches_tree.heading("Status", text="Status")
        
        # Get switches in this group
        try:
            switches = self.store.get_switches_in_group_MYBP86(location, group_name)
            for switch in switches:
                switches_tree.insert("", "end", values=(
                    switch.get('hostname', ''),
                    switch.get('serial_number', ''),
                    switch.get('ip_address', ''),
                    switch.get('status', '')
                ))
        except Exception as e:
            print(f"Error loading switches for group: {e}")
        
        switches_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(details_window, text="Close", command=details_window.destroy).pack(pady=10)

    def on_switch_location_changed(self, event=None):
        """Location is now stack name - no need for additional stack dropdown"""
        # Since location is now the stack name itself, we don't need a separate stack selection
        location = self.switch_location_var.get()
        if location:
            # Set stack name same as location (which is the stack name)
            self.switch_stack_var.set(location)

    def generate_switch_hostname_for_stack(self, location: str, stack_name: str) -> str:
        """Generate next available switch hostname for location and stack."""
        if not location or not stack_name:
            return "Switch-001"
        
        # Get existing switches in this stack
        existing_switches = self.store.get_switches_in_group_MYBP86(location, stack_name)
        
        # Find highest switch number in this stack
        max_num = 0
        prefix = f"{location}-{stack_name}"
        for switch in existing_switches:
            hostname = switch.get('hostname', '')
            if hostname.startswith(prefix):
                try:
                    # Extract number after the prefix and dash
                    parts = hostname.split('-')
                    if len(parts) >= 3:  # location-stackname-number
                        num_str = parts[-1]
                        num = int(num_str)
                        max_num = max(max_num, num)
                except (ValueError, IndexError):
                    continue
        
        # Return next available hostname
        return f"{prefix}-{max_num + 1:02d}"

    def get_available_stacks_for_location(self, location):
        """Get available switch stacks for a specific location that have capacity"""
        try:
            # Get switch groups at this location
            all_groups = self.store.get_switch_groups_MYBP86()
            groups_at_location = [group for group in all_groups if group.get('location') == location]
            
            available_stacks = []
            for group in groups_at_location:
                # Count current switches in this group/stack
                current_switches = len(self.store.get_switches_in_group_MYBP86(
                    location, group.get('group_name')))
                max_switches = group.get('max_switches', 6)
                
                # Only include if there's capacity
                if current_switches < max_switches:
                    available_stacks.append({
                        'stack_name': group.get('group_name'),
                        'location': location,
                        'max_switches': max_switches,
                        'current_switches': current_switches,
                        'description': group.get('description', '')
                    })
            
            return available_stacks
        except Exception as e:
            print(f"Error getting available stacks: {e}")
            return []

    def update_warehouse_locations_for_groups(self):
        """Update location dropdown with warehouse locations for switch groups"""
        try:
            # Get all warehouse locations (cabinets + shelves)
            cabinets = self.store.list_cabinets_MYBP86()
            locations = []
            
            for cabinet in cabinets:
                for shelf in range(1, 7):  # Shelves 1-6
                    location = f"{cabinet}{shelf}"
                    locations.append(location)
            
            # Add any existing switch group locations that might not be in warehouse
            existing_groups = self.store.get_switch_groups_MYBP86()
            for group in existing_groups:
                group_location = group.get('location', '')
                if group_location and group_location not in locations:
                    locations.append(group_location)
            
            locations.sort()
            self.group_location_dropdown['values'] = locations
            
        except Exception as e:
            print(f"Error updating warehouse locations: {e}")
            self.group_location_dropdown['values'] = []

    def open_group_management_window(self):
        """Open a separate window for comprehensive switch group management"""
        group_window = tk.Toplevel(self)
        group_window.title("Switch Group Management")
        group_window.geometry("800x600")
        group_window.transient(self)
        
        # Main notebook for different views
        notebook = ttk.Notebook(group_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create Group Tab
        create_frame = ttk.Frame(notebook)
        notebook.add(create_frame, text="Create Groups")
        self._build_create_group_tab(create_frame)
        
        # Manage Groups Tab
        manage_frame = ttk.Frame(notebook)
        notebook.add(manage_frame, text="Manage Existing Groups")
        self._build_manage_groups_tab(manage_frame)
        
        # Group Assignment Tab
        assign_frame = ttk.Frame(notebook)
        notebook.add(assign_frame, text="Assign Switches to Groups")
        self._build_assign_switches_tab(assign_frame)

    def _build_create_group_tab(self, parent):
        """Build the create group tab"""
        # Location selection frame
        location_frame = ttk.LabelFrame(parent, text="Select Warehouse Location")
        location_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Cabinet selection
        ttk.Label(location_frame, text="Cabinet:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        cabinet_var = tk.StringVar()
        cabinet_combo = ttk.Combobox(location_frame, textvariable=cabinet_var, 
                                   values=self.store.list_cabinets_MYBP86(), 
                                   state="readonly", width=10)
        cabinet_combo.grid(row=0, column=1, padx=5, pady=2)
        
        # Shelf selection
        ttk.Label(location_frame, text="Shelf:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        shelf_var = tk.StringVar()
        shelf_combo = ttk.Combobox(location_frame, textvariable=shelf_var,
                                 values=[str(i) for i in range(1, 7)],
                                 state="readonly", width=5)
        shelf_combo.grid(row=0, column=3, padx=5, pady=2)
        
        # Current location display
        current_location_var = tk.StringVar()
        ttk.Label(location_frame, text="Full Location:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        location_display = ttk.Label(location_frame, textvariable=current_location_var, 
                                   font=("", 9, "bold"), foreground="blue")
        location_display.grid(row=1, column=1, columnspan=3, sticky="w", padx=5, pady=2)
        
        def update_location_display(*args):
            cabinet = cabinet_var.get()
            shelf = shelf_var.get()
            if cabinet and shelf:
                current_location_var.set(f"{cabinet}{shelf}")
            else:
                current_location_var.set("")
        
        cabinet_var.trace('w', update_location_display)
        shelf_var.trace('w', update_location_display)
        
        # Group creation frame
        group_frame = ttk.LabelFrame(parent, text="Create Switch Group")
        group_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Group name
        ttk.Label(group_frame, text="Group Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        group_name_var = tk.StringVar()
        ttk.Entry(group_frame, textvariable=group_name_var, width=20).grid(row=0, column=1, padx=5, pady=2)
        
        # Max switches
        ttk.Label(group_frame, text="Max Switches:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        max_switches_var = tk.StringVar(value="6")
        ttk.Entry(group_frame, textvariable=max_switches_var, width=10).grid(row=0, column=3, padx=5, pady=2)
        
        # Description
        ttk.Label(group_frame, text="Description:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        description_var = tk.StringVar()
        ttk.Entry(group_frame, textvariable=description_var, width=50).grid(row=1, column=1, columnspan=3, padx=5, pady=2, sticky="ew")
        
        def create_group():
            cabinet = cabinet_var.get()
            shelf = shelf_var.get()
            group_name = group_name_var.get().strip()
            
            if not cabinet or not shelf:
                messagebox.showerror("Error", "Please select both cabinet and shelf!")
                return
            
            if not group_name:
                messagebox.showerror("Error", "Please enter a group name!")
                return
            
            location = f"{cabinet}{shelf}"
            
            try:
                max_switches = int(max_switches_var.get())
                success = self.store.add_switch_group_MYBP86(
                    location=location,
                    group_name=group_name,
                    max_switches=max_switches,
                    description=description_var.get().strip()
                )
                
                if success:
                    messagebox.showinfo("Success", f"Switch group '{group_name}' created at {location}!")
                    # Clear form
                    group_name_var.set("")
                    description_var.set("")
                    max_switches_var.set("6")
                    # Refresh main group display
                    self.refresh_switch_groups()
                else:
                    messagebox.showerror("Error", "Failed to create switch group! Group may already exist.")
            except ValueError:
                messagebox.showerror("Error", "Max switches must be a number!")
        
        ttk.Button(group_frame, text="Create Group", command=create_group).grid(row=2, column=1, pady=10)

    def _build_manage_groups_tab(self, parent):
        """Build the manage groups tab"""
        # Groups list
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tree for existing groups
        manage_tree = ttk.Treeview(list_frame, 
                                 columns=("Location", "GroupName", "MaxSwitches", "CurrentSwitches", "Description"), 
                                 show="headings")
        
        manage_tree.heading("Location", text="Location")
        manage_tree.heading("GroupName", text="Group Name")
        manage_tree.heading("MaxSwitches", text="Max Switches")
        manage_tree.heading("CurrentSwitches", text="Current Switches")
        manage_tree.heading("Description", text="Description")
        
        manage_tree.column("Location", width=100)
        manage_tree.column("GroupName", width=150)
        manage_tree.column("MaxSwitches", width=100)
        manage_tree.column("CurrentSwitches", width=120)
        manage_tree.column("Description", width=200)
        
        # Scrollbar
        manage_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=manage_tree.yview)
        manage_tree.configure(yscrollcommand=manage_scrollbar.set)
        
        manage_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        manage_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load groups
        def refresh_manage_tree():
            for item in manage_tree.get_children():
                manage_tree.delete(item)
            
            groups = self.store.get_switch_groups_MYBP86()
            for group in groups:
                current_switches = len(self.store.get_switches_in_group_MYBP86(
                    group.get('location'), group.get('group_name')))
                
                manage_tree.insert("", "end", values=(
                    group.get('location', ''),
                    group.get('group_name', ''),
                    group.get('max_switches', ''),
                    current_switches,
                    group.get('description', '')
                ))
        
        refresh_manage_tree()
        
        # Buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=refresh_manage_tree).pack(side=tk.LEFT, padx=5)
        
        def delete_selected_group():
            selection = manage_tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select a group to delete!")
                return
            
            item = manage_tree.item(selection[0])
            location = item['values'][0]
            group_name = item['values'][1]
            current_switches = item['values'][3]
            
            if current_switches > 0:
                messagebox.showerror("Error", 
                                   f"Cannot delete group '{group_name}' - it contains {current_switches} switches!")
                return
            
            if messagebox.askyesno("Confirm Delete", 
                                 f"Delete group '{group_name}' at {location}?"):
                success = self.store.delete_switch_group_MYBP86(location, group_name)
                if success:
                    messagebox.showinfo("Success", "Group deleted!")
                    refresh_manage_tree()
                    self.refresh_switch_groups()
                else:
                    messagebox.showerror("Error", "Failed to delete group!")
        
        ttk.Button(button_frame, text="Delete Selected", command=delete_selected_group).pack(side=tk.LEFT, padx=5)

    def _build_assign_switches_tab(self, parent):
        """Build the assign switches tab"""
        info_label = ttk.Label(parent, text="Switch assignment is handled in the Switch Management tab.\nSelect a location, then choose an available group when adding switches.")
        info_label.pack(pady=20)
        
        # Show current assignments
        assign_frame = ttk.LabelFrame(parent, text="Current Switch Assignments")
        assign_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        assign_tree = ttk.Treeview(assign_frame,
                                 columns=("Hostname", "Location", "Group", "SerialNumber", "Status"),
                                 show="headings")
        
        assign_tree.heading("Hostname", text="Switch Hostname")
        assign_tree.heading("Location", text="Location")
        assign_tree.heading("Group", text="Switch Group")
        assign_tree.heading("SerialNumber", text="Serial Number")
        assign_tree.heading("Status", text="Status")
        
        assign_scrollbar = ttk.Scrollbar(assign_frame, orient=tk.VERTICAL, command=assign_tree.yview)
        assign_tree.configure(yscrollcommand=assign_scrollbar.set)
        
        assign_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        assign_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load switch assignments
        def refresh_assignments():
            for item in assign_tree.get_children():
                assign_tree.delete(item)
            
            switches = self.store.get_network_devices_MYBP86("Switch")
            for switch in switches:
                assign_tree.insert("", "end", values=(
                    switch.get('hostname', ''),
                    switch.get('location', ''),
                    switch.get('switch_group', 'No Group'),
                    switch.get('serial_number', ''),
                    switch.get('status', '')
                ))
        
        refresh_assignments()
        
        ttk.Button(assign_frame, text="Refresh Assignments", command=refresh_assignments).pack(pady=5)

    def create_switch_stack(self, cabinet: str, shelf: int):
        """Create a switch stack (switch group) from warehouse interface"""
        location = f"{cabinet}{shelf}"
        
        # Create dialog for switch stack details
        stack_dialog = tk.Toplevel(self)
        stack_dialog.title(f"Create Switch Stack at {location}")
        stack_dialog.geometry("400x300")
        stack_dialog.transient(self)
        stack_dialog.grab_set()
        
        # Center the dialog
        stack_dialog.update_idletasks()
        x = (stack_dialog.winfo_screenwidth() // 2) - (stack_dialog.winfo_width() // 2)
        y = (stack_dialog.winfo_screenheight() // 2) - (stack_dialog.winfo_height() // 2)
        stack_dialog.geometry(f"+{x}+{y}")
        
        # Location info
        info_frame = ttk.LabelFrame(stack_dialog, text="Location Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Cabinet: {cabinet}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Shelf: {shelf}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Full Location: {location}", 
                 font=("", 9, "bold"), foreground="blue").pack(anchor=tk.W, padx=5, pady=2)
        
        # Stack details frame
        details_frame = ttk.LabelFrame(stack_dialog, text="Switch Stack Details")
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Stack name
        ttk.Label(details_frame, text="Stack Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        stack_name_var = tk.StringVar()
        stack_name_entry = ttk.Entry(details_frame, textvariable=stack_name_var, width=25)
        stack_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        stack_name_entry.focus()
        
        # Max switches
        ttk.Label(details_frame, text="Max Switches:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        max_switches_var = tk.StringVar(value="6")
        max_switches_spinbox = ttk.Spinbox(details_frame, from_=1, to=48, width=23,
                                         textvariable=max_switches_var)
        max_switches_spinbox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Description
        ttk.Label(details_frame, text="Description:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        description_var = tk.StringVar()
        description_entry = ttk.Entry(details_frame, textvariable=description_var, width=25)
        description_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        # Configure grid weights
        details_frame.columnconfigure(1, weight=1)
        
        # Button frame
        button_frame = ttk.Frame(stack_dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def create_stack():
            stack_name = stack_name_var.get().strip()
            if not stack_name:
                messagebox.showerror("Error", "Please enter a stack name!")
                return
            
            # Check if stack name already exists anywhere
            existing_groups = self.store.get_switch_groups_MYBP86()
            for group in existing_groups:
                if group.get('group_name', '').lower() == stack_name.lower():
                    messagebox.showerror("Error", 
                                       f"Switch stack '{stack_name}' already exists at location {group.get('location')}!\n"
                                       "Please choose a different name.")
                    return
            
            try:
                max_switches = int(max_switches_var.get())
                if max_switches < 1:
                    messagebox.showerror("Error", "Max switches must be at least 1!")
                    return
                
                # Create the switch group
                success = self.store.add_switch_group_MYBP86(
                    location=location,
                    group_name=stack_name,
                    max_switches=max_switches,
                    description=description_var.get().strip()
                )
                
                if success:
                    # Also add a warehouse item to represent the stack
                    # Use the user-provided stack name as the warehouse item name
                    # Use only the user description in the description field
                    user_description = description_var.get().strip()
                    warehouse_item_id = self.store.add_item_MYBP86(
                        "SWITCH STACK", cabinet, shelf, 
                        description=user_description,
                        custom_name=stack_name
                    )
                    
                    messagebox.showinfo("Success", 
                                       f"Switch Stack '{stack_name}' created successfully!\n\n"
                                       f"Location: {location}\n"
                                       f"Warehouse Item ID: {warehouse_item_id}\n"
                                       f"Max Switches: {max_switches}\n\n"
                                       f"You can now add switches to this stack in the Network Equipment tab.")
                    
                    stack_dialog.destroy()
                    self.refresh_all()
                    # Refresh Stack Management if it exists
                    if hasattr(self, 'stacks_tree'):
                        self.refresh_stack_management()
                else:
                    messagebox.showerror("Error", 
                                       f"Failed to create switch stack!\n"
                                       f"Database error occurred.")
            
            except ValueError:
                messagebox.showerror("Error", "Max switches must be a valid number!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create switch stack: {str(e)}")
        
        def cancel():
            stack_dialog.destroy()
        
        ttk.Button(button_frame, text="Create Stack", command=create_stack).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key to create
        stack_dialog.bind('<Return>', lambda e: create_stack())

    def _check_and_add_stack_management_tab(self):
        """Check if there are switch stacks and add Stack Management tab if needed"""
        try:
            # Check if there are any switch groups (stacks)
            switch_groups = self.store.get_switch_groups_MYBP86()
            if switch_groups:
                # Add Stack Management tab
                self.stack_mgmt_frame = ttk.Frame(self.network_notebook)
                self.network_notebook.add(self.stack_mgmt_frame, text="Stack Management")
                self._build_stack_management_ui()
        except Exception as e:
            print(f"Error checking for switch stacks: {e}")

    def _build_stack_management_ui(self):
        """Build the Stack Management interface"""
        # Stack overview frame
        overview_frame = ttk.LabelFrame(self.stack_mgmt_frame, text="Switch Stack Overview")
        overview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Stacks tree
        self.stacks_tree = ttk.Treeview(overview_frame, 
                                       columns=("Location", "StackName", "MaxSwitches", "CurrentSwitches", "Status", "Description"), 
                                       show="headings")
        
        self.stacks_tree.heading("Location", text="Location")
        self.stacks_tree.heading("StackName", text="Stack Name")
        self.stacks_tree.heading("MaxSwitches", text="Max Switches")
        self.stacks_tree.heading("CurrentSwitches", text="Current Switches")
        self.stacks_tree.heading("Status", text="Status")
        self.stacks_tree.heading("Description", text="Description")
        
        self.stacks_tree.column("Location", width=100)
        self.stacks_tree.column("StackName", width=150)
        self.stacks_tree.column("MaxSwitches", width=100)
        self.stacks_tree.column("CurrentSwitches", width=120)
        self.stacks_tree.column("Status", width=80)
        self.stacks_tree.column("Description", width=200)
        
        # Scrollbar for stacks tree
        stacks_scrollbar = ttk.Scrollbar(overview_frame, orient=tk.VERTICAL, command=self.stacks_tree.yview)
        self.stacks_tree.configure(yscrollcommand=stacks_scrollbar.set)
        
        self.stacks_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stacks_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Stack management buttons
        button_frame = ttk.Frame(self.stack_mgmt_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Refresh Stacks", 
                  command=self.refresh_stack_management).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Stack Details", 
                  command=self.view_stack_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add Switches to Stack", 
                  command=self.add_switches_to_stack).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Stack", 
                  command=self.remove_stack).pack(side=tk.LEFT, padx=5)
        
        # Load initial data
        self.refresh_stack_management()

    def refresh_stack_management(self):
        """Refresh the stack management display"""
        try:
            # Clear existing items
            for item in self.stacks_tree.get_children():
                self.stacks_tree.delete(item)
            
            # Get all switch groups (stacks)
            stacks = self.store.get_switch_groups_MYBP86()
            
            for stack in stacks:
                location = stack.get('location', '')
                stack_name = stack.get('group_name', '')
                
                # Count current switches in this stack
                switches_in_stack = self.store.get_switches_in_group_MYBP86(location, stack_name)
                current_switches = len(switches_in_stack)
                max_switches = stack.get('max_switches', 0)
                
                # Determine status
                if current_switches == 0:
                    status = "Empty"
                elif current_switches >= max_switches:
                    status = "Full"
                else:
                    status = "Partial"
                
                self.stacks_tree.insert("", "end", values=(
                    location,
                    stack_name,
                    max_switches,
                    current_switches,
                    status,
                    stack.get('description', '')
                ))
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh stack management: {str(e)}")

    def view_stack_details(self):
        """View details of selected stack"""
        selection = self.stacks_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack to view!")
            return
        
        item = self.stacks_tree.item(selection[0])
        location = item['values'][0]
        stack_name = item['values'][1]
        
        # Create details window
        details_window = tk.Toplevel(self)
        details_window.title(f"Stack Details: {stack_name} at {location}")
        details_window.geometry("700x500")
        details_window.transient(self)
        
        # Stack info
        info_frame = ttk.LabelFrame(details_window, text="Stack Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Location: {location}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Stack Name: {stack_name}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Max Switches: {item['values'][2]}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Current Switches: {item['values'][3]}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Status: {item['values'][4]}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Description: {item['values'][5]}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Switches in stack
        switches_frame = ttk.LabelFrame(details_window, text="Switches in Stack")
        switches_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        switches_tree = ttk.Treeview(switches_frame, 
                                   columns=("Hostname", "SerialNumber", "IPAddress", "Status", "Model"), 
                                   show="headings")
        
        switches_tree.heading("Hostname", text="Hostname")
        switches_tree.heading("SerialNumber", text="Serial Number")
        switches_tree.heading("IPAddress", text="IP Address")
        switches_tree.heading("Status", text="Status")
        switches_tree.heading("Model", text="Model")
        
        # Get switches in this stack
        try:
            switches = self.store.get_switches_in_group_MYBP86(location, stack_name)
            for switch in switches:
                switches_tree.insert("", "end", values=(
                    switch.get('hostname', ''),
                    switch.get('serial_number', ''),
                    switch.get('ip_address', ''),
                    switch.get('status', ''),
                    switch.get('model', '')
                ))
        except Exception as e:
            print(f"Error loading switches for stack: {e}")
        
        switches_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(details_window, text="Close", command=details_window.destroy).pack(pady=10)

    def add_switches_to_stack(self):
        """Navigate to Switch Management tab to add switches to selected stack"""
        selection = self.stacks_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack first!")
            return
        
        item = self.stacks_tree.item(selection[0])
        location = item['values'][0]
        stack_name = item['values'][1]
        
        # Switch to Switch Management tab
        self.network_notebook.select(2)  # Switch Management is typically the 3rd tab (index 2)
        
        # Pre-fill the location and group
        self.switch_location_var.set(location)
        self.on_switch_location_changed()  # This will populate the group dropdown
        self.switch_group_var.set(stack_name)
        
        messagebox.showinfo("Info", f"Switched to Switch Management tab.\nLocation and Stack are pre-selected for '{stack_name}' at {location}")

    def remove_stack(self):
        """Remove selected stack"""
        selection = self.stacks_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack to remove!")
            return
        
        item = self.stacks_tree.item(selection[0])
        location = item['values'][0]
        stack_name = item['values'][1]
        current_switches = item['values'][3]
        
        if current_switches > 0:
            messagebox.showerror("Error", 
                               f"Cannot remove stack '{stack_name}' - it contains {current_switches} switches!\n"
                               "Please move or remove all switches first.")
            return
        
        # Confirm removal
        if not messagebox.askyesno("Confirm Remove", 
                                   f"Are you sure you want to remove the stack '{stack_name}' at {location}?\n"
                                   "This will also remove the warehouse item."):
            return
        
        try:
            # Remove from switch groups
            success = self.store.delete_switch_group_MYBP86(location, stack_name)
            
            if success:
                # Also remove the warehouse item
                all_items = self.store.get_items_MYBP86()
                for item in all_items:
                    if (item.get('type') == 'SWITCH STACK' and 
                        f"{item.get('cabinet')}{item.get('shelf')}" == location):
                        self.store.remove_item_MYBP86(item.get('id'))
                        break
                
                messagebox.showinfo("Success", f"Stack '{stack_name}' removed successfully!")
                self.refresh_stack_management()
                self.refresh_all()  # Refresh warehouse display
                self.refresh_switch_groups()  # Refresh network equipment display
            else:
                messagebox.showerror("Error", "Failed to remove stack!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove stack: {str(e)}")

    def view_stack_details(self, stack_tree, location):
        """View details of selected stack"""
        selection = stack_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack to view!")
            return
        
        item = stack_tree.item(selection[0])
        stack_name = item['values'][0]
        group_name = item['values'][1]
        
        if group_name == "No Group":
            messagebox.showinfo("Stack Details", f"Stack '{stack_name}' has no associated switch group.")
            return
        
        # Show group details window (reuse existing method)
        self.show_group_details_by_name(location, group_name)

    def show_group_details_by_name(self, location, group_name):
        """Show group details by location and group name"""
        details_window = tk.Toplevel(self)
        details_window.title(f"Stack Details: {group_name} at {location}")
        details_window.geometry("600x500")
        details_window.transient(self)
        
        # Group info
        info_frame = ttk.LabelFrame(details_window, text="Stack Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Get group details
        groups = self.store.get_switch_groups_MYBP86()
        group_details = None
        for group in groups:
            if (group.get('location') == location and 
                group.get('group_name') == group_name):
                group_details = group
                break
        
        if group_details:
            current_switches = len(self.store.get_switches_in_group_MYBP86(location, group_name))
            
            ttk.Label(info_frame, text=f"Location: {location}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Stack Name: {group_name}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Max Switches: {group_details.get('max_switches')}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Current Switches: {current_switches}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Description: {group_details.get('description', '')}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Switches in stack
        switches_frame = ttk.LabelFrame(details_window, text="Switches in Stack")
        switches_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        switches_tree = ttk.Treeview(switches_frame, 
                                   columns=("Hostname", "SerialNumber", "IPAddress", "Status"), 
                                   show="headings")
        
        switches_tree.heading("Hostname", text="Hostname")
        switches_tree.heading("SerialNumber", text="Serial Number")
        switches_tree.heading("IPAddress", text="IP Address")
        switches_tree.heading("Status", text="Status")
        
        # Get switches in this group
        try:
            switches = self.store.get_switches_in_group_MYBP86(location, group_name)
            for switch in switches:
                switches_tree.insert("", "end", values=(
                    switch.get('hostname', ''),
                    switch.get('serial_number', ''),
                    switch.get('ip_address', ''),
                    switch.get('status', '')
                ))
        except Exception as e:
            print(f"Error loading switches for stack: {e}")
        
        switches_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(details_window, text="Close", command=details_window.destroy).pack(pady=10)

    def add_switch_to_stack(self, stack_tree, location):
        """Add a switch to selected stack"""
        selection = stack_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack first!")
            return
        
        item = stack_tree.item(selection[0])
        stack_name = item['values'][0]
        
        # Extract clean stack name
        clean_stack_name = stack_name.replace("🔀 ", "").replace("[Orphaned] ", "")
        
        if "No Group" in stack_name:
            messagebox.showerror("Error", "Cannot add switch to stack without associated group!")
            return
        
        # Switch to Network Equipment tab and pre-select the location and stack
        self.notebook.select(1)  # Switch to Network Equipment tab
        self.network_notebook.select(1)  # Switch to Switch Management tab (was index 2, now 1)
        
        # Pre-fill location with stack name instead of shelf location
        self.switch_location_var.set(clean_stack_name)
        self.on_switch_location_changed()  # Update stack dropdown
        if clean_stack_name in self.switch_stack_combo['values']:
            self.switch_stack_var.set(clean_stack_name)
        
        messagebox.showinfo("Add Switch", 
                           f"Switched to Switch Management tab.\nLocation: {clean_stack_name}\nStack: {clean_stack_name}\n\nPlease fill in switch details and click 'Add Switch'.")

    def manage_stack(self, stack_tree, location):     
        """Manage selected stack"""
        selection = stack_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack to manage!")
            return
        
        item = stack_tree.item(selection[0])
        stack_name = item['values'][0]
        group_name = item['values'][1]
        
        # Create management window
        manage_window = tk.Toplevel(self)
        manage_window.title(f"Manage Stack: {stack_name}")
        manage_window.geometry("500x400")
        manage_window.transient(self)
        
        # Stack info
        info_frame = ttk.LabelFrame(manage_window, text="Stack Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Stack Name: {stack_name}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Location: {location}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Group: {group_name}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Management buttons
        button_frame = ttk.Frame(manage_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        if group_name != "No Group":
            ttk.Button(button_frame, text="View Stack Details",
                      command=lambda: self.show_group_details_by_name(location, group_name)).pack(pady=5)
            
            ttk.Button(button_frame, text="Add Switch to Stack",
                      command=lambda: [manage_window.destroy(), 
                                     self.add_switch_to_stack(stack_tree, location)]).pack(pady=5)
        
        ttk.Button(button_frame, text="Delete Stack",
                  command=lambda: self.delete_stack_from_manage(stack_name, location, manage_window)).pack(pady=5)
        
        ttk.Button(button_frame, text="Close", command=manage_window.destroy).pack(pady=10)

    def delete_stack_from_manage(self, stack_name, location, parent_window):
        """Delete stack from management window"""
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete stack '{stack_name}'?\n\nThis will not delete associated switches."):
            # Find the stack item in database
            all_items = self.store.get_items_MYBP86()
            for item in all_items:
                if (item.get('name') == stack_name and 
                    item.get('type') == 'SWITCH STACK'):
                    success = self.store.remove_item_MYBP86(item.get('id'))
                    if success:
                        messagebox.showinfo("Success", f"Stack '{stack_name}' deleted!")
                        parent_window.destroy()
                        self.refresh_all()
                        return
                    else:
                        messagebox.showerror("Error", "Failed to delete stack!")
                        return
            
            messagebox.showerror("Error", "Stack not found in database!")

    def view_stack_details(self, stack_tree, location):
        """View detailed information about selected stack"""
        selection = stack_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack to view details!")
            return
        
        item = stack_tree.item(selection[0])
        stack_name = item['values'][0]
        device_count = item['values'][1]  # This is now "current/max" format
        description = item['values'][2]
        
        # Remove prefixes and determine stack type
        display_name = stack_name.replace("[Orphaned] ", "").replace("🔀 ", "").replace("⚡ ", "")
        is_pdu_stack = "⚡" in stack_name
        is_switch_stack = "🔀" in stack_name
        
        # Parse device count (current/max format)
        if "/" in device_count:
            current_devices, max_devices = device_count.split("/")
        else:
            current_devices = "N/A"
            max_devices = device_count
        
        # Create details window
        details_window = tk.Toplevel(self)
        details_window.title(f"Stack Details: {display_name}")
        details_window.geometry("700x500")
        details_window.transient(self)
        
        # Stack info frame
        info_frame = ttk.LabelFrame(details_window, text="Stack Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Stack Name: {display_name}", 
                 font=("", 10, "bold")).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Location: {location}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Show appropriate device type labels
        if is_pdu_stack:
            ttk.Label(info_frame, text=f"Max PDUs: {max_devices}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Current PDUs: {current_devices}").pack(anchor=tk.W, padx=5, pady=2)
        else:
            ttk.Label(info_frame, text=f"Max Switches: {max_devices}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Current Switches: {current_devices}").pack(anchor=tk.W, padx=5, pady=2)
            

        ttk.Label(info_frame, text=f"Description: {description}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Devices in stack frame
        if is_pdu_stack:
            devices_frame = ttk.LabelFrame(details_window, text="PDUs in Stack")
        else:
            devices_frame = ttk.LabelFrame(details_window, text="Switches in Stack")
        devices_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Devices tree
        devices_tree = ttk.Treeview(devices_frame, 
                                   columns=("Hostname", "SerialNumber", "IPAddress", "Model", "Status"), 
                                   show="headings")
        
        devices_tree.heading("Hostname", text="Hostname")
        devices_tree.heading("SerialNumber", text="Serial Number")
        devices_tree.heading("IPAddress", text="IP Address")
        devices_tree.heading("Model", text="Model")
        devices_tree.heading("Status", text="Status")
        
        devices_tree.column("Hostname", width=140)
        devices_tree.column("SerialNumber", width=120)
        devices_tree.column("IPAddress", width=120)
        devices_tree.column("Model", width=100)
        devices_tree.column("Status", width=80)
        
        # Scrollbar for devices
        devices_scrollbar = ttk.Scrollbar(devices_frame, orient=tk.VERTICAL, command=devices_tree.yview)
        devices_tree.configure(yscrollcommand=devices_scrollbar.set)
        
        devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        devices_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load devices in this stack
        try:
            if is_pdu_stack:
                # For PDU stacks, get PDUs by location (stack name)
                pdu_devices = self.store.get_network_devices_MYBP86("PDU")
                stack_pdus = [pdu for pdu in pdu_devices if pdu.get('location') == display_name]
                for pdu in stack_pdus:
                    devices_tree.insert("", "end", values=(
                        pdu.get('hostname', ''),
                        pdu.get('serial_number', ''),
                        pdu.get('ip_address', ''),
                        pdu.get('model', ''),
                        pdu.get('status', '')
                    ))
                if not stack_pdus:
                    devices_tree.insert("", "end", values=(
                        "No PDUs found", "in this stack", "", "", ""
                    ))
            else:
                # For switch stacks, get switches by location (stack name)
                switch_devices = self.store.get_network_devices_MYBP86("Switch")
                stack_switches = [switch for switch in switch_devices if switch.get('location') == display_name]
                for switch in stack_switches:
                    devices_tree.insert("", "end", values=(
                        switch.get('hostname', ''),
                        switch.get('serial_number', ''),
                        switch.get('ip_address', ''),
                        switch.get('model', ''),
                        switch.get('status', '')
                    ))
                if not stack_switches:
                    devices_tree.insert("", "end", values=(
                        "No switches found", "in this stack", "", "", ""
                    ))
        except Exception as e:
            print(f"Error loading devices for stack: {e}")
            devices_tree.insert("", "end", values=(
                "Error loading devices", str(e), "", "", ""
            ))
        
        # Close button
        ttk.Button(details_window, text="Close", command=details_window.destroy).pack(pady=10)

    def refresh_stack_display(self, cabinet, shelf):
        """Refresh the stack display for a specific location"""
        # This would refresh the current location view
        # For now, show a message to the user
        messagebox.showinfo("Refresh", "Please close and reopen this location view to see updated data.")

    def create_pdu_stack(self, cabinet: str, shelf: int):
        """Create a PDU stack from warehouse interface"""
        location = f"{cabinet}{shelf}"
        
        # Create dialog for PDU stack details
        stack_dialog = tk.Toplevel(self)
        stack_dialog.title(f"Create PDU Stack at {location}")
        stack_dialog.geometry("400x300")
        stack_dialog.transient(self)
        stack_dialog.grab_set()
        
        # Center the dialog
        stack_dialog.update_idletasks()
        x = (stack_dialog.winfo_screenwidth() // 2) - (stack_dialog.winfo_width() // 2)
        y = (stack_dialog.winfo_screenheight() // 2) - (stack_dialog.winfo_height() // 2)
        stack_dialog.geometry(f"+{x}+{y}")
        
        # Location info
        info_frame = ttk.LabelFrame(stack_dialog, text="Location Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Cabinet: {cabinet}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Shelf: {shelf}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Full Location: {location}", 
                 font=("", 9, "bold"), foreground="blue").pack(anchor=tk.W, padx=5, pady=2)
        
        # Stack details frame
        details_frame = ttk.LabelFrame(stack_dialog, text="PDU Stack Details")
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Stack name
        ttk.Label(details_frame, text="Stack Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        stack_name_var = tk.StringVar()
        stack_name_entry = ttk.Entry(details_frame, textvariable=stack_name_var, width=25)
        stack_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        stack_name_entry.focus()
        
        # Max PDUs
        ttk.Label(details_frame, text="Max PDUs:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        max_pdus_var = tk.StringVar(value="4")
        max_pdus_spinbox = ttk.Spinbox(details_frame, from_=1, to=24, width=23,
                                      textvariable=max_pdus_var)
        max_pdus_spinbox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Description
        ttk.Label(details_frame, text="Description:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        description_var = tk.StringVar()
        description_entry = ttk.Entry(details_frame, textvariable=description_var, width=25)
        description_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        # Configure grid weights
        details_frame.columnconfigure(1, weight=1)
        
        # Button frame
        button_frame = ttk.Frame(stack_dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def create_stack():
            stack_name = stack_name_var.get().strip()
            if not stack_name:
                messagebox.showerror("Error", "Please enter a stack name!")
                return
            
            # Check if stack name already exists anywhere
            existing_items = self.store.get_items_MYBP86()
            for item in existing_items:
                if (item.get('name', '').lower() == stack_name.lower() and 
                    item.get('type') in ['PDU STACK', 'SWITCH STACK']):
                    messagebox.showerror("Error", 
                                       f"Stack '{stack_name}' already exists!\n"
                                       "Please choose a different name.")
                    return
            
            try:
                max_pdus = int(max_pdus_var.get())
                if max_pdus < 1:
                    messagebox.showerror("Error", "Max PDUs must be at least 1!")
                    return
                
                # Create the PDU stack warehouse item
                user_description = description_var.get().strip()
                warehouse_item_id = self.store.add_item_MYBP86(
                    "PDU STACK", cabinet, shelf, 
                    description=user_description,
                    custom_name=stack_name
                )
                
                if warehouse_item_id:
                    messagebox.showinfo("Success", 
                                       f"PDU Stack '{stack_name}' created successfully!\n\n"
                                       f"Location: {location}\n"
                                       f"Warehouse Item ID: {warehouse_item_id}\n"
                                       f"Max PDUs: {max_pdus}\n\n"
                                       f"You can now add PDUs to this stack in the Network Equipment tab.")
                    
                    stack_dialog.destroy()
                    self.refresh_all()
                    # Refresh Stack Management if it exists
                    if hasattr(self, 'stacks_tree'):
                        self.refresh_stack_management()
                else:
                    messagebox.showerror("Error", 
                                       f"Failed to create PDU stack!\n"
                                       f"Database error occurred.")
            
            except ValueError:
                messagebox.showerror("Error", "Max PDUs must be a valid number!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create PDU stack: {str(e)}")
        
        def cancel():
            stack_dialog.destroy()
        
        ttk.Button(button_frame, text="Create Stack", command=create_stack).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key to create
        stack_dialog.bind('<Return>', lambda e: create_stack())

    def add_device_to_stack(self, stack_tree, location):
        """Add a device (switch or PDU) to selected stack based on stack type"""
        selection = stack_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a stack first!")
            return
        
        item = stack_tree.item(selection[0])
        stack_name = item['values'][0]
        
        # Determine stack type based on icon
        is_pdu_stack = "⚡" in stack_name
        is_switch_stack = "🔀" in stack_name
        
        # Remove prefixes for clean name
        clean_stack_name = stack_name.replace("🔀 ", "").replace("⚡ ", "").replace("[Orphaned] ", "")
        
        if is_pdu_stack:
            # For PDU stacks - switch to PDU management tab
            self.notebook.select(1)  # Switch to Network Equipment tab
            self.network_notebook.select(0)  # Switch to PDU Management tab
            
            # Pre-fill location with stack name instead of shelf location
            self.pdu_location_var.set(clean_stack_name)
            self.update_location_combos()
            
            messagebox.showinfo("Add PDU", 
                              f"Switched to PDU Management tab.\n\n"
                              f"Target Stack: {clean_stack_name}\n"
                              f"Location: {clean_stack_name}\n\n"
                              f"Please fill in PDU details and click 'Add PDU'.")
        elif is_switch_stack:
            # For switch stacks - call the existing switch functionality
            self.add_switch_to_stack(stack_tree, location)
        else:
            messagebox.showwarning("Unknown Stack Type", 
                                 f"Cannot determine stack type for '{clean_stack_name}'.\n"
                                 f"Please check the stack configuration.")


if __name__ == "__main__":
    try:
        AppMYBP86().mainloop()
    except Exception as e:
        try:
            messagebox.showerror("Startup error", f"{type(e).__name__}: {e}")
        except Exception:
            pass
        raise
