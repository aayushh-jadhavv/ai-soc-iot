"""Passive identity observations, with persistent UUIDs and IP binding revisions.

MACs/IPs are evidence, *not* authenticated identity. Conflicts are flagged and
inference reset; automatic enforcement is deliberately outside this prototype.
"""
import ipaddress
import json
import os
import threading
import time
import uuid
from pathlib import Path

from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP


class DeviceRegistry:
    def __init__(self, lan_net, gateway_ip=None, gateway_mac=None, path=None, on_change=None):
        self.lan_net = lan_net
        self.gateway_ip = str(gateway_ip) if gateway_ip else None
        self.gateway_mac = (gateway_mac or '').lower() or None
        self.path = Path(path) if path else None
        self.on_change = on_change
        self.lock = threading.RLock()
        self.mac_devices = {}  # MAC -> {device_id, first_seen, last_seen, hostname}
        self.ip_bindings = {}  # IP -> {mac, device_id, binding_revision, conflict, last_seen}
        self._load()

    def is_lan_ip(self, ip):
        try:
            addr = ipaddress.ip_address(str(ip))
            return addr.version == 4 and addr in self.lan_net
        except ValueError:
            return False

    def is_monitored_ip(self, ip):
        return self.is_lan_ip(ip) and str(ip) != self.gateway_ip

    def _valid_mac(self, mac):
        mac = (mac or '').lower()
        if len(mac.split(':')) != 6 or mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
            return False
        if mac.startswith(('01:00:5e', '33:33')):
            return False
        return mac != self.gateway_mac

    def _load(self):
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text())
            self.mac_devices = data.get('mac_devices', {})
            self.ip_bindings = data.get('ip_bindings', {})

    def _save(self):
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + '.tmp')
        tmp.write_text(json.dumps({'mac_devices': self.mac_devices, 'ip_bindings': self.ip_bindings}, indent=2))
        os.replace(tmp, self.path)

    def learn_mac(self, ip, mac, source='packet'):
        """Return True when the IP's identity or attachment binding changes."""
        ip, mac = str(ip), (mac or '').lower()
        if not self.is_monitored_ip(ip) or not self._valid_mac(mac):
            return False
        now = time.time()
        changed = False
        with self.lock:
            known = self.mac_devices.get(mac)
            if not known:
                known = {'device_id': str(uuid.uuid4()), 'first_seen': now,
                         'last_seen': now, 'hostname': ''}
                self.mac_devices[mac] = known
            known['last_seen'] = now
            prev = self.ip_bindings.get(ip)
            if prev is None:
                self.ip_bindings[ip] = {'mac': mac, 'device_id': known['device_id'],
                                        'binding_revision': 1, 'conflict': False,
                                        'last_seen': now, 'identity_source': source}
                changed = True
            elif prev['mac'] != mac:
                self.ip_bindings[ip] = {'mac': mac, 'device_id': known['device_id'],
                                        'binding_revision': prev['binding_revision'] + 1,
                                        'conflict': True, 'last_seen': now,
                                        'identity_source': source}
                changed = True
            else:
                prev['last_seen'] = now
            # An address move for a known MAC is a new attachment context.
            for other_ip, other in list(self.ip_bindings.items()):
                if other_ip != ip and other['mac'] == mac and not other.get('conflict'):
                    other['conflict'] = True
                    self.ip_bindings[ip]['binding_revision'] += 1
                    self.ip_bindings[ip]['conflict'] = True
                    changed = True
            if changed:
                self._save()
            result = self.get_device(ip)
        if changed and self.on_change:
            self.on_change(ip, result)
        return changed

    def learn_dhcp(self, pkt):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return
        bootp = pkt[BOOTP]
        mac = ':'.join(f'{b:02x}' for b in bytes(bootp.chaddr)[:6])
        opts = {x[0]: x[1] for x in pkt[DHCP].options if isinstance(x, tuple) and len(x) > 1}
        name = opts.get('hostname', '')
        if isinstance(name, bytes):
            name = name.decode('utf-8', 'replace')
        if self._valid_mac(mac) and name:
            with self.lock:
                obj = self.mac_devices.setdefault(mac, {'device_id': str(uuid.uuid4()),
                                 'first_seen': time.time(), 'last_seen': time.time(), 'hostname': ''})
                obj['hostname'] = str(name)[:128]
                self._save()
        msg = opts.get('message-type')
        if isinstance(msg, bytes):
            msg = msg[0] if msg else None
        if msg in (2, 5):
            candidates = [bootp.yiaddr, bootp.ciaddr]
        elif msg == 3:
            candidates = [opts.get('requested_addr', ''), bootp.ciaddr]
        else:
            candidates = []
        for ip in candidates:
            if self.is_monitored_ip(ip):
                self.learn_mac(ip, mac, 'dhcp')
                break

    def learn_packet(self, pkt):
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            self.learn_mac(arp.psrc, arp.hwsrc, 'arp')
            return
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if int(udp.sport) in (67, 68) or int(udp.dport) in (67, 68):
                self.learn_dhcp(pkt)
        ip = pkt.getlayer(IP)
        eth = pkt.getlayer(Ether)
        if ip is None or eth is None:
            return
        # Do not mistake an upstream router's MAC for a downstream host.
        if self.is_monitored_ip(ip.src):
            self.learn_mac(ip.src, eth.src, 'ipv4_src')
        if self.is_monitored_ip(ip.dst) and self.is_monitored_ip(ip.src):
            self.learn_mac(ip.dst, eth.dst, 'ipv4_dst')

    def get_device(self, ip):
        ip = str(ip)
        with self.lock:
            binding = self.ip_bindings.get(ip)
            if not binding:
                return {'device_id': None, 'ip': ip, 'mac': '', 'hostname': '',
                        'binding_revision': 0, 'conflict': True}
            known = self.mac_devices.get(binding['mac'], {})
            return {'device_id': binding['device_id'], 'ip': ip, 'mac': binding['mac'],
                    'hostname': known.get('hostname', ''),
                    'binding_revision': binding['binding_revision'],
                    'conflict': binding['conflict']}
