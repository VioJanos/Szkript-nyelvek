"""
Network Equipment Management System
=====================================

Ez a modul hálózati eszközök (PDU és Switch) kezelésére szolgál.
Tartalmazza az alapvető attribútumokat és funkciókat mindkét eszköztípushoz.

Szerző: Network Admin
Dátum: 2025-10-25
"""

from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class DeviceStatus(Enum):
    """Eszköz állapotok"""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"


class PortStatus(Enum):
    """Port állapotok"""
    UP = "up"
    DOWN = "down"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class NetworkDevice:
    """
    Alapvető hálózati eszköz osztály
    Minden hálózati eszköz közös tulajdonságait tartalmazza
    """
    serial_number: str
    hostname: str
    ip_address: str
    mac_address: str
    device_type: str
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    location: str = ""
    status: DeviceStatus = DeviceStatus.OFFLINE
    last_seen: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    notes: str = ""
    
    def __post_init__(self):
        """Inicializálás után futó validáció"""
        if not self.serial_number:
            raise ValueError("Serial number kötelező!")
        if not self.hostname:
            raise ValueError("Hostname kötelező!")
        if not self.ip_address:
            raise ValueError("IP cím kötelező!")
    
    def update_status(self, new_status: DeviceStatus, notes: str = ""):
        """Eszköz állapotának frissítése"""
        self.status = new_status
        self.updated_at = datetime.now()
        if notes:
            self.notes = f"{self.notes}\n{datetime.now()}: {notes}".strip()
        
        if new_status == DeviceStatus.ONLINE:
            self.last_seen = datetime.now()
    
    def to_dict(self) -> Dict:
        """Objektum dictionary-vé alakítása"""
        return {
            'serial_number': self.serial_number,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'device_type': self.device_type,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'firmware_version': self.firmware_version,
            'location': self.location,
            'status': self.status.value,
            'last_seen': (self.last_seen.isoformat()
                          if self.last_seen else None),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'notes': self.notes
        }
    
    def __str__(self):
        return (f"{self.device_type} - {self.hostname} "
                f"({self.ip_address}) - {self.status.value}")


@dataclass
class Port:
    """Port információk tárolására"""
    port_number: int
    port_name: str = ""
    status: PortStatus = PortStatus.DOWN
    speed: str = "auto"  # pl: "1G", "10G", "auto"
    duplex: str = "auto"  # "full", "half", "auto"
    vlan_id: Optional[int] = None
    description: str = ""
    connected_device: str = ""
    last_activity: Optional[datetime] = None
    
    def __str__(self):
        return (f"Port {self.port_number}: {self.port_name} "
                f"({self.status.value})")


class PDU(NetworkDevice):
    """
    Power Distribution Unit (PDU) osztály
    Tápellátás kezelésére szolgáló eszközök kezelése
    """
    
    def __init__(self, serial_number: str, hostname: str, ip_address: str,
                 mac_address: str, outlet_count: int = 8, **kwargs):
        super().__init__(
            serial_number=serial_number,
            hostname=hostname,
            ip_address=ip_address,
            mac_address=mac_address,
            device_type="PDU",
            **kwargs
        )
        
        self.outlet_count = outlet_count
        self.outlets: List[Dict] = []
        self.max_power = 0.0  # Watts
        self.current_power = 0.0  # Watts
        self.voltage = 230.0  # Volts
        self.frequency = 50.0  # Hz
        self.power_factor = 1.0
        
        # Outlet-ek inicializálása
        self._initialize_outlets()
    
    def _initialize_outlets(self):
        """Outlet-ek inicializálása alapértelmezett értékekkel"""
        for i in range(1, self.outlet_count + 1):
            outlet = {
                'outlet_number': i,
                'name': f"Outlet {i}",
                'status': 'off',  # 'on', 'off', 'error'
                'power_consumption': 0.0,  # Watts
                'connected_device': '',
                'is_controllable': True,
                'last_switched': None
            }
            self.outlets.append(outlet)
    
    def power_on_outlet(self, outlet_number: int) -> bool:
        """Adott outlet bekapcsolása"""
        if 1 <= outlet_number <= self.outlet_count:
            outlet = self.outlets[outlet_number - 1]
            if outlet['is_controllable']:
                outlet['status'] = 'on'
                outlet['last_switched'] = datetime.now()
                self.updated_at = datetime.now()
                return True
        return False
    
    def power_off_outlet(self, outlet_number: int) -> bool:
        """Adott outlet kikapcsolása"""
        if 1 <= outlet_number <= self.outlet_count:
            outlet = self.outlets[outlet_number - 1]
            if outlet['is_controllable']:
                outlet['status'] = 'off'
                outlet['last_switched'] = datetime.now()
                self.updated_at = datetime.now()
                return True
        return False
    
    def get_outlet_status(self, outlet_number: int) -> Optional[Dict]:
        """Outlet állapotának lekérdezése"""
        if 1 <= outlet_number <= self.outlet_count:
            return self.outlets[outlet_number - 1].copy()
        return None
    
    def set_outlet_name(self, outlet_number: int, name: str):
        """Outlet nevének beállítása"""
        if 1 <= outlet_number <= self.outlet_count:
            self.outlets[outlet_number - 1]['name'] = name
            self.updated_at = datetime.now()
    
    def get_power_consumption(self) -> Dict:
        """Teljes energiafogyasztás információk"""
        total_consumption = sum(outlet['power_consumption']
                                for outlet in self.outlets)
        return {
            'total_power': total_consumption,
            'max_power': self.max_power,
            'voltage': self.voltage,
            'frequency': self.frequency,
            'power_factor': self.power_factor,
            'utilization_percent': ((total_consumption / self.max_power * 100)
                                    if self.max_power > 0 else 0)
        }
    
    def get_active_outlets(self) -> List[Dict]:
        """Aktív (bekapcsolt) outlet-ek listája"""
        return [outlet for outlet in self.outlets if outlet['status'] == 'on']


class Switch(NetworkDevice):
    """
    Network Switch osztály
    Hálózati kapcsolók kezelésére
    """
    
    def __init__(self, serial_number: str, hostname: str, ip_address: str,
                 mac_address: str, port_count: int = 24, **kwargs):
        super().__init__(
            serial_number=serial_number,
            hostname=hostname,
            ip_address=ip_address,
            mac_address=mac_address,
            device_type="Switch",
            **kwargs
        )
        
        self.port_count = port_count
        self.ports: List[Port] = []
        self.vlans: Dict[int, Dict] = {}
        self.spanning_tree_enabled = True
        self.management_vlan = 1
        self.uplink_ports: List[int] = []
        
        # Portok inicializálása
        self._initialize_ports()
        # Alapértelmezett VLAN létrehozása
        self._initialize_default_vlan()
    
    def _initialize_ports(self):
        """Portok inicializálása"""
        for i in range(1, self.port_count + 1):
            port = Port(
                port_number=i,
                port_name=f"GigabitEthernet0/{i}",
                status=PortStatus.DOWN,
                speed="1G",
                vlan_id=1  # Default VLAN
            )
            self.ports.append(port)
    
    def _initialize_default_vlan(self):
        """Alapértelmezett VLAN létrehozása"""
        self.vlans[1] = {
            'vlan_id': 1,
            'name': 'default',
            'description': 'Default VLAN',
            'ports': list(range(1, self.port_count + 1)),
            'created_at': datetime.now()
        }
    
    def configure_port(self, port_number: int, **config) -> bool:
        """Port konfigurációja"""
        if 1 <= port_number <= self.port_count:
            port = self.ports[port_number - 1]
            
            if 'status' in config:
                port.status = PortStatus(config['status'])
            if 'speed' in config:
                port.speed = config['speed']
            if 'duplex' in config:
                port.duplex = config['duplex']
            if 'vlan_id' in config:
                port.vlan_id = config['vlan_id']
            if 'description' in config:
                port.description = config['description']
            if 'port_name' in config:
                port.port_name = config['port_name']
            
            self.updated_at = datetime.now()
            return True
        return False
    
    def create_vlan(self, vlan_id: int, name: str,
                    description: str = "") -> bool:
        """VLAN létrehozása"""
        if vlan_id not in self.vlans and 1 <= vlan_id <= 4094:
            self.vlans[vlan_id] = {
                'vlan_id': vlan_id,
                'name': name,
                'description': description,
                'ports': [],
                'created_at': datetime.now()
            }
            self.updated_at = datetime.now()
            return True
        return False
    
    def assign_port_to_vlan(self, port_number: int, vlan_id: int) -> bool:
        """Port hozzárendelése VLAN-hoz"""
        if (1 <= port_number <= self.port_count and
                vlan_id in self.vlans):
            
            # Port eltávolítása korábbi VLAN-ból
            old_vlan_id = self.ports[port_number - 1].vlan_id
            if old_vlan_id and old_vlan_id in self.vlans:
                if port_number in self.vlans[old_vlan_id]['ports']:
                    self.vlans[old_vlan_id]['ports'].remove(port_number)
            
            # Port hozzáadása új VLAN-hoz
            self.ports[port_number - 1].vlan_id = vlan_id
            if port_number not in self.vlans[vlan_id]['ports']:
                self.vlans[vlan_id]['ports'].append(port_number)
            
            self.updated_at = datetime.now()
            return True
        return False
    
    def get_port_status(self, port_number: int) -> Optional[Dict]:
        """Port állapotának lekérdezése"""
        if 1 <= port_number <= self.port_count:
            port = self.ports[port_number - 1]
            return {
                'port_number': port.port_number,
                'port_name': port.port_name,
                'status': port.status.value,
                'speed': port.speed,
                'duplex': port.duplex,
                'vlan_id': port.vlan_id,
                'description': port.description,
                'connected_device': port.connected_device,
                'last_activity': (port.last_activity.isoformat()
                                  if port.last_activity else None)
            }
        return None
    
    def get_vlan_info(self, vlan_id: int) -> Optional[Dict]:
        """VLAN információk lekérdezése"""
        return self.vlans.get(vlan_id)
    
    def get_active_ports(self) -> List[Dict]:
        """Aktív portok listája"""
        active_ports = []
        for port in self.ports:
            if port.status == PortStatus.UP:
                active_ports.append({
                    'port_number': port.port_number,
                    'port_name': port.port_name,
                    'speed': port.speed,
                    'vlan_id': port.vlan_id,
                    'connected_device': port.connected_device
                })
        return active_ports
    
    def set_uplink_ports(self, port_numbers: List[int]):
        """Uplink portok beállítása"""
        valid_ports = [p for p in port_numbers if 1 <= p <= self.port_count]
        self.uplink_ports = valid_ports
        self.updated_at = datetime.now()


class NetworkManager:
    """
    Hálózati eszközök központi kezelése
    PDU-k és Switch-ek egyszerű kezelése és nyilvántartása
    """
    
    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}  # serial_number -> device
        self.device_types = {'PDU': [], 'Switch': []}
    
    def add_device(self, device: NetworkDevice) -> bool:
        """Eszköz hozzáadása a rendszerhez"""
        if device.serial_number in self.devices:
            return False  # Már létezik
        
        self.devices[device.serial_number] = device
        if device.device_type in self.device_types:
            self.device_types[device.device_type].append(device.serial_number)
        
        return True
    
    def remove_device(self, serial_number: str) -> bool:
        """Eszköz eltávolítása a rendszerből"""
        if serial_number not in self.devices:
            return False
        
        device = self.devices[serial_number]
        if device.device_type in self.device_types:
            if serial_number in self.device_types[device.device_type]:
                self.device_types[device.device_type].remove(serial_number)
        
        del self.devices[serial_number]
        return True
    
    def get_device(self, serial_number: str) -> Optional[NetworkDevice]:
        """Eszköz lekérdezése serial number alapján"""
        return self.devices.get(serial_number)
    
    def get_device_by_hostname(self, hostname: str) -> Optional[NetworkDevice]:
        """Eszköz lekérdezése hostname alapján"""
        for device in self.devices.values():
            if device.hostname == hostname:
                return device
        return None
    
    def get_device_by_ip(self, ip_address: str) -> Optional[NetworkDevice]:
        """Eszköz lekérdezése IP cím alapján"""
        for device in self.devices.values():
            if device.ip_address == ip_address:
                return device
        return None
    
    def get_devices_by_type(self, device_type: str) -> List[NetworkDevice]:
        """Eszközök lekérdezése típus alapján"""
        if device_type not in self.device_types:
            return []
        
        return [self.devices[sn] for sn in self.device_types[device_type]
                if sn in self.devices]
    
    def get_devices_by_status(self, status: DeviceStatus
                              ) -> List[NetworkDevice]:
        """Eszközök lekérdezése állapot alapján"""
        return [device for device in self.devices.values()
                if device.status == status]
    
    def get_devices_by_location(self, location: str) -> List[NetworkDevice]:
        """Eszközök lekérdezése helyszín alapján"""
        return [device for device in self.devices.values()
                if location.lower() in device.location.lower()]
    
    def update_device_status(self, serial_number: str,
                             new_status: DeviceStatus,
                             notes: str = "") -> bool:
        """Eszköz állapotának frissítése"""
        device = self.get_device(serial_number)
        if device:
            device.update_status(new_status, notes)
            return True
        return False
    
    def get_summary(self) -> Dict:
        """Rendszer összefoglaló"""
        total_devices = len(self.devices)
        online_devices = len(self.get_devices_by_status(DeviceStatus.ONLINE))
        offline_devices = len(self.get_devices_by_status(DeviceStatus.OFFLINE))
        maintenance_devices = len(
            self.get_devices_by_status(DeviceStatus.MAINTENANCE))
        error_devices = len(self.get_devices_by_status(DeviceStatus.ERROR))
        
        return {
            'total_devices': total_devices,
            'online_devices': online_devices,
            'offline_devices': offline_devices,
            'maintenance_devices': maintenance_devices,
            'error_devices': error_devices,
            'device_types': {k: len(v) for k, v in self.device_types.items()},
            'last_updated': datetime.now().isoformat()
        }
    
    def export_devices_to_dict(self) -> List[Dict]:
        """Összes eszköz exportálása dictionary listává"""
        return [device.to_dict() for device in self.devices.values()]
    
    def find_available_outlet(self, location: str = "") -> Optional[Dict]:
        """Szabad outlet keresése PDU-kban"""
        pdus = self.get_devices_by_type('PDU')
        
        for pdu in pdus:
            if location and location.lower() not in pdu.location.lower():
                continue
                
            if pdu.status == DeviceStatus.ONLINE:
                for outlet in pdu.outlets:
                    if (outlet['status'] == 'off' and
                            outlet['is_controllable'] and
                            not outlet['connected_device']):
                        return {
                            'pdu_serial': pdu.serial_number,
                            'pdu_hostname': pdu.hostname,
                            'pdu_location': pdu.location,
                            'outlet_number': outlet['outlet_number'],
                            'outlet_name': outlet['name']
                        }
        return None
    
    def find_available_port(self, location: str = "") -> Optional[Dict]:
        """Szabad port keresése Switch-ekben"""
        switches = self.get_devices_by_type('Switch')
        
        for switch in switches:
            if location and location.lower() not in switch.location.lower():
                continue
                
            if switch.status == DeviceStatus.ONLINE:
                for port in switch.ports:
                    if (port.status == PortStatus.DOWN and
                            not port.connected_device and
                            port.port_number not in switch.uplink_ports):
                        return {
                            'switch_serial': switch.serial_number,
                            'switch_hostname': switch.hostname,
                            'switch_location': switch.location,
                            'port_number': port.port_number,
                            'port_name': port.port_name,
                            'vlan_id': port.vlan_id
                        }
        return None


if __name__ == "__main__":
    print("Network Equipment Management System")
    print("=" * 40)
    
    # PDU példa
    print("\n1. PDU létrehozása és kezelése:")
    pdu = PDU(
        serial_number="PDU001",
        hostname="pdu-rack1",
        ip_address="192.168.1.100",
        mac_address="00:11:22:33:44:55",
        outlet_count=8,
        manufacturer="APC",
        model="AP7900",
        location="Rack 1"
    )
    
    print(f"PDU létrehozva: {pdu}")
    print(f"Outlet-ek száma: {pdu.outlet_count}")
    
    # Outlet-ek kezelése
    pdu.set_outlet_name(1, "Server1")
    pdu.set_outlet_name(2, "Server2")
    pdu.power_on_outlet(1)
    pdu.power_on_outlet(2)
    
    print(f"Aktív outlet-ek: {len(pdu.get_active_outlets())}")
    for outlet in pdu.get_active_outlets():
        print(f"  - {outlet['name']} (#{outlet['outlet_number']}): "
              f"{outlet['status']}")
    
    # Switch példa
    print("\n2. Switch létrehozása és kezelése:")
    switch = Switch(
        serial_number="SW001",
        hostname="sw-floor1",
        ip_address="192.168.1.10",
        mac_address="00:AA:BB:CC:DD:EE",
        port_count=24,
        manufacturer="Cisco",
        model="Catalyst 2960",
        location="Floor 1 - IDF"
    )
    
    print(f"Switch létrehozva: {switch}")
    print(f"Portok száma: {switch.port_count}")
    
    # VLAN létrehozása
    switch.create_vlan(10, "Users", "User VLAN")
    switch.create_vlan(20, "Servers", "Server VLAN")
    
    # Portok konfigurálása
    switch.configure_port(1, status="up", description="Uplink to core",
                          speed="10G")
    switch.configure_port(2, status="up", description="Server connection")
    switch.assign_port_to_vlan(2, 20)  # Server port VLAN 20-ba
    
    switch.set_uplink_ports([1])
    
    print(f"VLAN-ok: {list(switch.vlans.keys())}")
    print(f"Uplink portok: {switch.uplink_ports}")
    
    # Port információk
    port1_info = switch.get_port_status(1)
    if port1_info:
        print(f"Port 1 info: {port1_info['port_name']} - "
              f"{port1_info['status']} - {port1_info['description']}")
    
    print(f"\nAktív portok: {len(switch.get_active_ports())}")
    for port in switch.get_active_ports():
        print(f"  - Port {port['port_number']}: {port['port_name']} "
              f"(VLAN {port['vlan_id']})")

    # NetworkManager példa
    print("\n3. NetworkManager használata:")
    manager = NetworkManager()
    
    # Eszközök hozzáadása
    manager.add_device(pdu)
    manager.add_device(switch)
    
    # Összefoglaló
    summary = manager.get_summary()
    print(f"Összes eszköz: {summary['total_devices']}")
    print(f"Online eszközök: {summary['online_devices']}")
    print(f"Eszköz típusok: {summary['device_types']}")
    
    # Szabad erőforrások keresése
    free_outlet = manager.find_available_outlet()
    if free_outlet:
        print(f"Szabad outlet: {free_outlet['pdu_hostname']} - "
              f"Outlet {free_outlet['outlet_number']}")
    
    free_port = manager.find_available_port()
    if free_port:
        print(f"Szabad port: {free_port['switch_hostname']} - "
              f"Port {free_port['port_number']}")