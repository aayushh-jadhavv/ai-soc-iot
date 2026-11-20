"""Raspberry Pi gateway configuration. Change interface/subnet for other labs."""
import ipaddress
import os
from pathlib import Path

LAN_SUBNET = os.getenv('IOT_LAN_SUBNET', '10.10.0.0/24')
LAN_NET = ipaddress.ip_network(LAN_SUBNET)
LAN_INTERFACE = os.getenv('IOT_LAN_INTERFACE', 'wlan0')
GATEWAY_IP = os.getenv('IOT_GATEWAY_IP', '10.10.0.1')
CAPTURE_FILTER = 'ip or arp'  # IPv4-only v1; isolate/disable IPv6 separately
WINDOW_MS = 1000
WINDOW_SECONDS = 1.0
SEQUENCE_LENGTH = 8
ORDERING_ALLOWANCE_MS = 100  # proposed in design; late packets are coverage errors
INACTIVITY_TIMEOUT_SECONDS = 60
GATEWAY_ID = os.getenv('IOT_GATEWAY_ID', 'gw-lab-01')
DATA_DIR = Path(os.getenv('IOT_DATA_DIR', str(Path.home() / '.local/share/iot-gateway')))
REGISTRY_FILE = DATA_DIR / 'device_registry.json'
FIXTURE_DIR = Path(os.getenv('IOT_FIXTURE_DIR', 'fixtures'))
MODEL_ID = os.getenv('IOT_MODEL_ID', 'cnn-unsw-ga-v1')
IDS_BASE_URL = os.getenv('IOT_IDS_URL', 'http://127.0.0.1:8000')
IDS_TOKEN_FILE = os.getenv('IOT_IDS_TOKEN_FILE', str(DATA_DIR / 'ids-token'))
ENABLE_INFERENCE = os.getenv('IOT_ENABLE_INFERENCE', '0') == '1'
CAPTURE_QUEUE_SIZE = 4096
