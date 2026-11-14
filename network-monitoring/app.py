import os
import re
import sys
import json
import time
import queue
import base64
import socket
import ipaddress
import itertools
import functools
import threading
import subprocess
import importlib.util
from collections import deque, OrderedDict
from datetime import datetime
from urllib.parse import urlsplit, parse_qsl

# ------------------------------------------------------------
# Configuration: defaults are built in; no exports required.
# ------------------------------------------------------------
# Your main switch / gateway IP. The whole subnet around it is monitored.
LAN_HOST = "172.16.0.1"
# None = automatic /24 around LAN_HOST (192.168.0.0/24). Or e.g. "192.168.0.0/23".
LAN_SUBNET = "172.16.0.0/20"
# Dashboard address. 127.0.0.1 = only this PC can open it (recommended).
# Use "0.0.0.0" only if you want other PCs to open the dashboard.
HOST = "127.0.0.1"
PORT = 5000
MAX_EVENTS = 20000          # packets kept for the whole network (newest first)
DEVICE_HISTORY = 600        # packets kept PER device, so a quiet device is never pushed out by a busy one
PACKET_STORE_MAX = 8000     # raw packets kept for the "packet details" window
WINDOW_SECONDS = 5
# Find every device: send ARP "who-has" for each address of the subnet at start
# and then every ARP_SWEEP_EVERY seconds (like arp-scan). Set False for a purely passive collector.
ARP_SWEEP = False
ARP_SWEEP_EVERY = 120
ONLINE_SECONDS = 180        # device counts as "online" if seen in the last N seconds

# Needed to see traffic of OTHER devices (switch mirror/SPAN port -> this PC).
PROMISCUOUS = True
# Show empty TCP ACK / control packets too (True = every packet type is monitored).
# Set False to hide them: they are pure noise on busy networks.
SHOW_PURE_ACK = True
FLOW_TTL = 300  # seconds to remember a TCP connection
# Replace Authorization / Cookie / password / token values in previews.
REDACT_SECRETS = True

# Fixed names for devices (also editable from the dashboard with the pencil
# button; those are saved in device_aliases.json).
DEVICE_ALIASES = {
    "172.16.0.1": "Router / gateway",
}

# Leave None for automatic detection. If needed, use the exact
# Scapy device shown by /api/interfaces, e.g. r"\Device\NPF_{GUID}".
LAN_INTERFACE = "wlo1"

def ensure_package(module_name, package_name):
    if importlib.util.find_spec(module_name) is not None:
        return True
    print(f"[SETUP] Missing {package_name}; attempting installation...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_name],
            capture_output=True, text=True, timeout=180
        )
        if result.returncode == 0:
            importlib.invalidate_caches()
            return importlib.util.find_spec(module_name) is not None
        print(result.stderr[-2000:])
    except Exception as exc:
        print(f"[SETUP ERROR] {exc}")
    return False

for module, package in (("flask", "Flask"), ("scapy", "scapy"), ("psutil", "psutil")):
    if not ensure_package(module, package):
        raise SystemExit(
            f"Could not install {package}. Run: python -m pip install Flask scapy psutil"
        )

from flask import Flask, jsonify, render_template
from flask import request as flask_request
import psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALIAS_FILE = os.path.join(BASE_DIR, "device_aliases.json")
LAN_NET = ipaddress.ip_network(LAN_SUBNET or f"{LAN_HOST}/24", strict=False)

def detect_local_ip(target):
    """IP this PC uses to reach `target` (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

THIS_PC_IP = detect_local_ip(LAN_HOST)
LOCAL_HOSTNAME = socket.gethostname()

# Capture EVERY frame on the wire (IPv4, IPv6, ARP, DHCP, LLDP, STP, EAPOL ...),
# but never the dashboard's own traffic. What is shown is decided in classify_packet().
CAPTURE_FILTER = f"not (tcp port {PORT} and host {THIS_PC_IP})"

app = Flask(__name__)
events = deque(maxlen=MAX_EVENTS)
device_events = {}               # ip -> deque of that device's own packets
packet_store = OrderedDict()     # id -> (scapy packet, record) for the detail view
lock = threading.RLock()
stats = {
    "packets": 0, "bytes": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    "requests": 0, "responses": 0, "connections": 0, "dns": 0, "third_party": 0,
    "started_at": time.time(), "capture_status": "starting",
    "capture_error": "", "last_packet_at": None, "interface": "detecting",
    "target_ip": LAN_HOST
}

def get_local_addresses():
    result = {"127.0.0.1", "::1"}
    try:
        for entries in psutil.net_if_addrs().values():
            for item in entries:
                if item.family in (socket.AF_INET, socket.AF_INET6):
                    result.add(item.address.split("%")[0])
    except Exception:
        pass
    return sorted(result)

LOCAL_ADDRESSES = get_local_addresses()
MY_IPS = set(LOCAL_ADDRESSES)
MY_IPS.add(THIS_PC_IP)

# ------------------------------------------------------------
# Device knowledge (names, MAC addresses, per-device counters)
# ------------------------------------------------------------
devices = {}        # ip -> counters
ip_mac = {}         # ip -> mac
dhcp_names = {}     # mac -> hostname announced in DHCP
mdns_names = {}     # ip -> name announced via mDNS (xxx.local)
rdns = {}           # ip -> reverse DNS / NetBIOS name
rdns_state = {}     # ip -> last lookup time
dns_cache = {}      # remote ip -> name that was resolved by some device
dns_dev_cache = {}  # (device ip, remote ip) -> name that THIS device resolved (more exact)
device_sites = {}   # device ip -> OrderedDict(host -> stats); most recent host is last
search_log = deque(maxlen=300)   # plain-HTTP search words + search-engine usage
search_seen = {}    # (device ip, host) -> last time a search-engine visit was logged
MAX_SITES_PER_DEVICE = 400
rdns_queue = queue.Queue()

def load_aliases():
    try:
        with open(ALIAS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            DEVICE_ALIASES.update({str(k): str(v) for k, v in data.items()})
    except FileNotFoundError:
        pass
    except Exception as exc:
        print(f"[ALIAS WARNING] {exc}")

def save_aliases():
    try:
        with open(ALIAS_FILE, "w", encoding="utf-8") as fh:
            json.dump(DEVICE_ALIASES, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"[ALIAS WARNING] {exc}")

load_aliases()

@functools.lru_cache(maxsize=16384)
def in_lan(ip):
    try:
        return ipaddress.ip_address(ip) in LAN_NET
    except ValueError:
        return False

@functools.lru_cache(maxsize=16384)
def is_multicast_or_broadcast(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_multicast or ip == "255.255.255.255" or (a.version == 4 and a == LAN_NET.broadcast_address)
    except ValueError:
        return False

def mac_ok(mac):
    mac = (mac or "").lower()
    return bool(mac) and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") \
        and not mac.startswith(("01:00:5e", "33:33"))

mac_ip = {}         # mac -> ip (reverse of ip_mac; lets IPv6 / ARP-probe packets find their device)

def learn_mac(ip, mac, via="ip"):
    if in_lan(ip) and mac_ok(mac) and not is_multicast_or_broadcast(ip) and ip != "0.0.0.0":
        mac = mac.lower()
        ip_mac[ip] = mac
        mac_ip[mac] = ip
        ensure_device(ip, time.time(), via)

def ensure_device(ip, ts, via=""):
    """Register a LAN device the first time ANYTHING is seen from it (ARP, DHCP, mDNS, IPv4 ...)."""
    dev = devices.get(ip)
    if dev is None:
        if len(devices) > 2000:
            oldest = min(devices.values(), key=lambda x: x["last_seen"])
            devices.pop(oldest["ip"], None)
            device_events.pop(oldest["ip"], None)
        dev = {"ip": ip, "first_seen": ts, "last_seen": ts, "packets": 0, "bytes_out": 0,
               "bytes_in": 0, "requests": 0, "responses": 0, "last_request": "",
               "last_request_ts": None, "recent_hosts": [], "seen_via": [],
               "protocols": {}, "packet_types": {}, "services": {}}
        devices[ip] = dev
    else:
        dev["last_seen"] = max(dev["last_seen"], ts)
    if via and via not in dev["seen_via"]:
        dev["seen_via"].append(via)
    return dev

@functools.lru_cache(maxsize=4096)
def vendor_of(mac):
    if not mac:
        return ""
    try:
        from scapy.config import conf
        v = conf.manufdb._get_manuf(mac)
        return "" if (not v or v.lower() == mac.lower()) else str(v)
    except Exception:
        return ""

def request_rdns(ip, now):
    if not in_lan(ip):
        return
    last = rdns_state.get(ip)
    if last is None or (not rdns.get(ip) and now - last > 600):
        rdns_state[ip] = now
        rdns_queue.put(ip)

def rdns_worker():
    while True:
        ip = rdns_queue.get()
        name = ""
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name and not name.replace(".", "").isdigit():
                name = name.split(".")[0]
            else:
                name = ""
        except Exception:
            name = ""
        with lock:
            rdns[ip] = name

def device_name(ip):
    if ip in DEVICE_ALIASES:
        return DEVICE_ALIASES[ip]
    mac = ip_mac.get(ip)
    if mac and mac in dhcp_names:
        return dhcp_names[mac]
    if ip in mdns_names:
        return mdns_names[ip]
    if rdns.get(ip):
        return rdns[ip]
    if ip in MY_IPS and ip != "127.0.0.1":
        return LOCAL_HOSTNAME
    return ""

# ------------------------------------------------------------
# Passive learning: ARP, DHCP, mDNS
# ------------------------------------------------------------
def _records(rr, count):
    if rr is None:
        return []
    if isinstance(rr, (list, tuple)):
        return list(rr)
    out = []
    try:
        for i in range(count or 0):
            out.append(rr[i])
    except Exception:
        pass
    return out

def _name(x):
    if isinstance(x, bytes):
        x = x.decode("utf-8", errors="replace")
    return str(x).rstrip(".")

def dns_answers(d, section="an"):
    out = []
    try:
        rr = getattr(d, section)
        count = d.ancount if section == "an" else d.arcount
        for r in _records(rr, count)[:20]:
            rdata = getattr(r, "rdata", "")
            out.append({
                "name": _name(getattr(r, "rrname", "")),
                "type": int(getattr(r, "type", 0) or 0),
                "ttl": int(getattr(r, "ttl", 0) or 0),
                "rdata": _name(rdata) if not isinstance(rdata, list) else ", ".join(_name(x) for x in rdata),
            })
    except Exception:
        pass
    return out

def learn_dhcp(pkt):
    from scapy.layers.dhcp import DHCP, BOOTP
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return
    b = pkt[BOOTP]
    mac = ":".join(f"{x:02x}" for x in bytes(b.chaddr)[:6])
    opts = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1]
    host = opts.get("hostname")
    if isinstance(host, bytes):
        host = host.decode("utf-8", errors="replace")
    if host and mac_ok(mac):
        dhcp_names[mac] = str(host).strip()
    for cand in (str(b.yiaddr), str(b.ciaddr), str(opts.get("requested_addr", ""))):
        if cand and cand != "0.0.0.0" and in_lan(cand) and mac_ok(mac):
            learn_mac(cand, mac, "dhcp")
            break

def learn_mdns(d):
    for r in dns_answers(d, "an") + dns_answers(d, "ar"):
        if r["type"] == 1 and r["name"].lower().endswith(".local") and in_lan(r["rdata"]):
            mdns_names[r["rdata"]] = r["name"][:-6]
            ensure_device(r["rdata"], time.time(), "mdns")

def learn_passive(pkt):
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        learn_mac(str(a.psrc), str(a.hwsrc), "arp")
        return
    ip = pkt.getlayer(IP)
    if ip is None:
        return
    udp = pkt.getlayer(UDP)
    if udp is not None:
        sp, dp = int(udp.sport), int(udp.dport)
        if sp in (67, 68) or dp in (67, 68):
            learn_dhcp(pkt)
        elif 5353 in (sp, dp) and pkt.haslayer(DNS):
            learn_mdns(pkt[DNS])
    eth = pkt.getlayer(Ether)
    if eth is not None:
        src, dst = str(ip.src), str(ip.dst)
        learn_mac(src, eth.src)
        if not is_multicast_or_broadcast(dst):
            learn_mac(dst, eth.dst)

# ------------------------------------------------------------
# Secrets redaction (previews only)
# ------------------------------------------------------------
SECRET_HEADER = re.compile(rb"(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)[ \t]*:[^\r\n]*")
SECRET_PARAM = re.compile(rb"(?i)\b(pass(?:word|wd)?|pwd|token|secret|api[_-]?key)=([^&\s\"']*)")
SECRET_JSON = re.compile(rb"(?i)(\"(?:password|passwd|pwd|token|secret|api_?key)\"\s*:\s*)\"[^\"]*\"")

def redact(b):
    if not REDACT_SECRETS or not b:
        return b
    b = SECRET_HEADER.sub(lambda m: m.group(1) + b": [redacted]", b)
    b = SECRET_PARAM.sub(lambda m: m.group(1) + b"=[redacted]", b)
    b = SECRET_JSON.sub(lambda m: m.group(1) + b"\"[redacted]\"", b)
    return b

# ------------------------------------------------------------
# Websites: domain -> friendly app name, search words, search engines
# ------------------------------------------------------------
SITE_EXACT = {
    "www.google.com": "Google Search", "google.com": "Google Search",
    "suggestqueries.google.com": "Google Search (typing / suggestions)",
    "mail.google.com": "Gmail", "inbox.google.com": "Gmail",
    "drive.google.com": "Google Drive", "docs.google.com": "Google Docs",
    "sheets.google.com": "Google Sheets", "slides.google.com": "Google Slides",
    "maps.google.com": "Google Maps", "maps.googleapis.com": "Google Maps",
    "translate.google.com": "Google Translate", "play.google.com": "Google Play",
    "accounts.google.com": "Google Sign-in", "meet.google.com": "Google Meet",
    "calendar.google.com": "Google Calendar", "photos.google.com": "Google Photos",
    "news.google.com": "Google News", "myaccount.google.com": "Google Account",
    "www.youtube.com": "YouTube", "m.youtube.com": "YouTube", "youtubei.googleapis.com": "YouTube (app)",
    "www.bing.com": "Bing Search", "bing.com": "Bing Search",
    "duckduckgo.com": "DuckDuckGo Search", "html.duckduckgo.com": "DuckDuckGo Search",
    "search.yahoo.com": "Yahoo Search", "in.search.yahoo.com": "Yahoo Search",
    "yandex.com": "Yandex Search", "yandex.ru": "Yandex Search",
    "www.baidu.com": "Baidu Search", "search.brave.com": "Brave Search",
    "www.ecosia.org": "Ecosia Search",
    "chat.openai.com": "ChatGPT", "chatgpt.com": "ChatGPT", "claude.ai": "Claude",
}
SITE_SUFFIX = {
    # Google
    "googlevideo.com": "YouTube video", "ytimg.com": "YouTube", "youtube.com": "YouTube", "youtu.be": "YouTube",
    "gstatic.com": "Google (static files)", "googleapis.com": "Google APIs",
    "googleusercontent.com": "Google content", "ggpht.com": "Google content",
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google Ads", "googlesyndication.com": "Google Ads",
    "googleadservices.com": "Google Ads", "gvt1.com": "Google update", "gvt2.com": "Google update",
    "google.com": "Google", "withgoogle.com": "Google", "android.com": "Android",
    # Social / messaging
    "facebook.com": "Facebook", "fbcdn.net": "Facebook", "facebook.net": "Facebook", "fb.com": "Facebook",
    "instagram.com": "Instagram", "cdninstagram.com": "Instagram",
    "whatsapp.com": "WhatsApp", "whatsapp.net": "WhatsApp", "messenger.com": "Messenger",
    "twitter.com": "X (Twitter)", "x.com": "X (Twitter)", "twimg.com": "X (Twitter)",
    "linkedin.com": "LinkedIn", "licdn.com": "LinkedIn", "reddit.com": "Reddit", "redd.it": "Reddit",
    "redditstatic.com": "Reddit", "redditmedia.com": "Reddit", "snapchat.com": "Snapchat",
    "tiktok.com": "TikTok", "tiktokcdn.com": "TikTok", "tiktokv.com": "TikTok", "byteoversea.com": "TikTok",
    "telegram.org": "Telegram", "t.me": "Telegram", "discord.com": "Discord", "discordapp.com": "Discord",
    "pinterest.com": "Pinterest", "quora.com": "Quora", "tumblr.com": "Tumblr",
    # Streaming / music
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix", "nflximg.net": "Netflix", "nflxext.com": "Netflix",
    "spotify.com": "Spotify", "scdn.co": "Spotify", "primevideo.com": "Prime Video",
    "hotstar.com": "Disney+ Hotstar", "jiocinema.com": "JioCinema", "twitch.tv": "Twitch",
    "ttvnw.net": "Twitch", "soundcloud.com": "SoundCloud", "gaana.com": "Gaana", "jiosaavn.com": "JioSaavn",
    # Microsoft / Apple / Amazon
    "bing.com": "Bing", "microsoft.com": "Microsoft", "windows.com": "Windows", "windowsupdate.com": "Windows Update",
    "msftconnecttest.com": "Windows connectivity check", "live.com": "Microsoft account",
    "office.com": "Microsoft Office", "office365.com": "Microsoft Office", "office.net": "Microsoft Office",
    "microsoftonline.com": "Microsoft sign-in", "skype.com": "Skype", "msn.com": "MSN",
    "azure.com": "Microsoft Azure", "azureedge.net": "Microsoft CDN", "trafficmanager.net": "Microsoft Azure",
    "xboxlive.com": "Xbox", "outlook.com": "Outlook", "sharepoint.com": "SharePoint",
    "apple.com": "Apple", "icloud.com": "iCloud", "mzstatic.com": "Apple (App Store)",
    "cdn-apple.com": "Apple", "apple-dns.net": "Apple",
    "amazon.com": "Amazon", "amazon.in": "Amazon", "media-amazon.com": "Amazon",
    "ssl-images-amazon.com": "Amazon", "amazonaws.com": "Amazon AWS", "cloudfront.net": "CloudFront CDN",
    # Dev / AI / work
    "github.com": "GitHub", "githubusercontent.com": "GitHub", "githubassets.com": "GitHub",
    "gitlab.com": "GitLab", "stackoverflow.com": "Stack Overflow", "stackexchange.com": "Stack Exchange",
    "openai.com": "OpenAI", "anthropic.com": "Anthropic", "claude.ai": "Claude", "npmjs.org": "npm",
    "pypi.org": "PyPI", "python.org": "Python", "zoom.us": "Zoom", "slack.com": "Slack",
    "notion.so": "Notion", "dropbox.com": "Dropbox", "wikipedia.org": "Wikipedia", "wikimedia.org": "Wikipedia",
    "mozilla.org": "Mozilla/Firefox", "mozilla.com": "Mozilla/Firefox", "mozilla.net": "Mozilla/Firefox",
    # India
    "flipkart.com": "Flipkart", "swiggy.com": "Swiggy", "zomato.com": "Zomato", "paytm.com": "Paytm",
    "phonepe.com": "PhonePe", "jio.com": "Jio", "myntra.com": "Myntra", "irctc.co.in": "IRCTC",
    # CDN / infrastructure / ads / trackers
    "cloudflare.com": "Cloudflare", "cloudflare-dns.com": "Cloudflare DNS", "cloudflare.net": "Cloudflare",
    "akamai.net": "Akamai CDN", "akamaiedge.net": "Akamai CDN", "akamaihd.net": "Akamai CDN",
    "akamaitechnologies.com": "Akamai CDN", "edgekey.net": "Akamai CDN", "edgesuite.net": "Akamai CDN",
    "fastly.net": "Fastly CDN", "fastlylb.net": "Fastly CDN", "jsdelivr.net": "jsDelivr CDN",
    "unpkg.com": "unpkg CDN", "cdnjs.cloudflare.com": "cdnjs CDN",
    "digicert.com": "Certificate check", "letsencrypt.org": "Certificate check", "ocsp.pki.goog": "Certificate check",
    "pki.goog": "Certificate check", "ntp.org": "Time sync (NTP)", "time.windows.com": "Time sync (NTP)",
    "adnxs.com": "Ads/Tracking", "criteo.com": "Ads/Tracking", "taboola.com": "Ads/Tracking",
    "outbrain.com": "Ads/Tracking", "scorecardresearch.com": "Ads/Tracking", "hotjar.com": "Ads/Tracking",
    "branch.io": "Ads/Tracking", "appsflyer.com": "Ads/Tracking", "adjust.com": "Ads/Tracking",
}
SEARCH_ENGINES = {
    "Google Search", "Google Search (typing / suggestions)", "Bing Search", "DuckDuckGo Search",
    "Yahoo Search", "Yandex Search", "Baidu Search", "Brave Search", "Ecosia Search",
}
GOOGLE_SEARCH_RE = re.compile(r"^(www\.)?google\.(com|co\.[a-z]{2}|[a-z]{2,3})$")
SEARCH_KEYS = ("q", "query", "search_query", "search", "keyword", "keywords",
               "term", "searchterm", "wd", "text", "p")
SEARCH_PATH_HINT = re.compile(r"search|suggest|complete|query|results", re.I)

def host_only(h):
    h = (h or "").strip().lower().rstrip(".")
    return re.sub(r":\d+$", "", h)

def useful_host(h):
    """Real internet host name or ''. Rejects IPs, .local/.arpa and single-label names."""
    h = host_only(h)
    if not h or "." not in h or ":" in h or " " in h:
        return ""
    if h.endswith((".arpa", ".local", ".lan", ".home", ".localdomain", ".internal", ".localhost")):
        return ""
    if re.fullmatch(r"[\d.]+", h):
        return ""
    return h

@functools.lru_cache(maxsize=8192)
def site_app(host):
    """Friendly name of the website/app behind a host name ('' when unknown)."""
    h = host_only(host)
    if not h:
        return ""
    if GOOGLE_SEARCH_RE.match(h):
        return "Google Search"
    found = SITE_EXACT.get(h)
    if found:
        return found
    parts = h.split(".")
    for i in range(len(parts) - 1):
        found = SITE_SUFFIX.get(".".join(parts[i:]))
        if found:
            return found
    return ""

def extract_search(host, target):
    """Search words from a plain-HTTP URL. HTTPS is encrypted, so this only works on http://."""
    try:
        parts = urlsplit(target)
        params = parse_qsl(parts.query, keep_blank_values=False, errors="replace")
    except Exception:
        return ""
    if not params:
        return ""
    if not (site_app(host) in SEARCH_ENGINES or SEARCH_PATH_HINT.search(parts.path or "")):
        return ""
    for key, value in params:
        key = key.lower()
        if key in SEARCH_KEYS and value.strip():
            if key == "p" and "yahoo" not in (host or "").lower():
                continue
            return value.strip()[:160]
    return ""

def ip_kind(ip):
    """gw = the main switch/gateway, bcast = broadcast/multicast, lan = other LAN device, wan = internet."""
    if ip == LAN_HOST:
        return "gw"
    if is_multicast_or_broadcast(ip):
        return "bcast"
    if ":" in ip:                                   # IPv6 link-local peers stay on the LAN side
        try:
            if ipaddress.ip_address(ip).is_link_local:
                return "bcast"
        except ValueError:
            pass
    return "lan" if in_lan(ip) else "wan"

def v6_device(pkt):
    """IPv6 has no ARP entry here: find the LAN device through the Ethernet MAC address.
    Returns (device_ip, outbound)."""
    from scapy.layers.l2 import Ether
    eth = pkt.getlayer(Ether)
    if eth is None:
        return None, False
    d_src = mac_ip.get(str(eth.src).lower())
    if d_src and d_src != LAN_HOST:
        return d_src, True
    d_dst = mac_ip.get(str(eth.dst).lower())
    if d_dst and d_dst != LAN_HOST:
        return d_dst, False
    return None, False

ICMP6_TYPES = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 128: "Echo request",
               129: "Echo reply", 130: "Multicast listener query", 131: "Multicast listener report",
               133: "Router solicitation", 134: "Router advertisement", 135: "Neighbor solicitation",
               136: "Neighbor advertisement", 143: "Multicast listener report v2"}

ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect",
              8: "Echo request", 9: "Router advertisement", 10: "Router solicitation",
              11: "Time exceeded", 12: "Parameter problem", 13: "Timestamp request",
              14: "Timestamp reply", 17: "Address mask request", 18: "Address mask reply"}

# Other IP protocols (everything that is not TCP / UDP / ICMP) so nothing is lumped into "IP"
IP_PROTOS = {1: "ICMP", 2: "IGMP", 4: "IPv4-in-IP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP", 47: "GRE",
             50: "ESP", 51: "AH", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 136: "UDPLite"}

# Non-IP Ethernet frames
L2_TYPES = {0x88cc: "LLDP", 0x888e: "EAPOL (802.1X)", 0x8100: "VLAN", 0x88a8: "VLAN (QinQ)",
            0x0842: "Wake-on-LAN", 0x8808: "Ethernet flow control", 0x88e5: "MACsec",
            0x9000: "Ethernet loopback", 0x8899: "Realtek control", 0x22f0: "AVTP",
            0x8035: "RARP", 0x8137: "IPX", 0x809b: "AppleTalk", 0x8847: "MPLS", 0x8863: "PPPoE discovery",
            0x8864: "PPPoE session"}

def classify_arp(pkt):
    """ARP: who-has / is-at. This is how silent devices are discovered."""
    from scapy.layers.l2 import ARP
    a = pkt[ARP]
    psrc, pdst, hwsrc = str(a.psrc), str(a.pdst), str(a.hwsrc).lower()
    op = int(a.op)
    if op not in (1, 2):
        return None
    if op == 1 and psrc == THIS_PC_IP:
        return None                          # this PC's own ARP sweep is not shown as traffic
    dev = psrc if (psrc != "0.0.0.0" and in_lan(psrc)) else mac_ip.get(hwsrc)
    if not dev or not in_lan(dev):
        return None
    now = time.time()
    if op == 1:
        ptype, rr = "ARP REQUEST", "REQUEST"
        text = f"ARP: who has {pdst}? tell {psrc if psrc != '0.0.0.0' else hwsrc}"
        peer, peer_kind = pdst, "bcast"
    else:
        ptype, rr = "ARP REPLY", "RESPONSE"
        text = f"ARP: {psrc} is at {hwsrc}"
        peer, peer_kind = pdst, ip_kind(pdst)
    mac = ip_mac.get(dev, hwsrc)
    return {
        "id": f"{now:.6f}-{next(packet_counter)}", "ts": now,
        "time": datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3],
        "src": dev, "dst": peer, "sport": None, "dport": None, "proto": "ARP",
        "bytes": int(len(pkt)), "payload_bytes": 0, "flags": "", "direction": "LAN",
        "device_ip": dev, "device_name": device_name(dev), "device_mac": mac,
        "device_vendor": vendor_of(mac), "device_port": None,
        "peer_ip": peer, "peer_name": device_name(peer) if in_lan(peer) else "", "peer_port": None,
        "remote_host": "", "service": "ARP", "site_app": "", "search": "",
        "src_kind": ip_kind(dev), "dst_kind": peer_kind, "ip_version": 0,
        "packet_type": ptype, "request_response": rr, "detail": text, "request": text,
        "summary": f"{dev} → {peer} (ARP)"
    }

def classify_l2(pkt):
    """Non-IP Ethernet frames (LLDP, STP, EAPOL, VLAN control, WoL, PPPoE, ...).
    They are attached to a device through the MAC address (learned from ARP / DHCP / IP)."""
    from scapy.layers.l2 import Ether, Dot3
    eth = pkt.getlayer(Ether)
    if eth is None:
        eth = pkt.getlayer(Dot3)
    if eth is None:
        return None
    src_mac, dst_mac = str(eth.src).lower(), str(eth.dst).lower()
    dev, outbound = mac_ip.get(src_mac), True
    if dev is None:
        dev, outbound = mac_ip.get(dst_mac), False
    if dev is None or not in_lan(dev):
        return None
    if pkt.getlayer(Ether) is not None:
        etype = int(eth.type)
        name = L2_TYPES.get(etype, f"EtherType 0x{etype:04x}")
    else:                                                    # IEEE 802.3 + LLC frames
        name = "STP (spanning tree)" if dst_mac.startswith("01:80:c2:00:00") else "802.3 / LLC"
    peer_mac = dst_mac if outbound else src_mac
    peer = mac_ip.get(peer_mac) or peer_mac
    peer_kind = ip_kind(peer) if peer in ip_mac else "bcast"
    now = time.time()
    text = f"Ethernet frame: {name} ({src_mac} → {dst_mac})"
    return {
        "id": f"{now:.6f}-{next(packet_counter)}", "ts": now,
        "time": datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3],
        "src": dev if outbound else peer, "dst": peer if outbound else dev,
        "sport": None, "dport": None, "proto": "L2",
        "bytes": int(len(pkt)), "payload_bytes": 0, "flags": "", "direction": "LAN",
        "device_ip": dev, "device_name": device_name(dev), "device_mac": ip_mac.get(dev, ""),
        "device_vendor": vendor_of(ip_mac.get(dev, "")), "device_port": None,
        "peer_ip": peer, "peer_name": device_name(peer) if in_lan(peer) else "", "peer_port": None,
        "remote_host": "", "service": name, "site_app": "", "search": "",
        "src_kind": ip_kind(dev) if outbound else peer_kind,
        "dst_kind": peer_kind if outbound else ip_kind(dev), "ip_version": 0,
        "packet_type": name.upper(), "request_response": "OTHER", "detail": text, "request": text,
        "summary": f"{src_mac} → {dst_mac} ({name})"
    }

def lookup_host(client, remote):
    """Domain a device resolved for `remote` (own DNS answer first, then any device's)."""
    return dns_dev_cache.get((client, remote)) or dns_cache.get(remote, "")

# ------------------------------------------------------------
# Packet classification
# ------------------------------------------------------------
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ",
                b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE ")
PORT_NAMES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    139: "SMB", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    554: "RTSP", 587: "SMTP", 993: "IMAPS", 1883: "MQTT", 1900: "SSDP/UPnP",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8883: "MQTT-TLS",
}
packet_counter = itertools.count(1)
flows = {}  # TCP connection state: who is the client, which host (SNI/Host)

def get_flow(src, sport, dst, dport, flags, now):
    key = tuple(sorted(((src, sport), (dst, dport))))
    flow = flows.get(key)
    if flow is None:
        if len(flows) > 5000:
            cutoff = now - FLOW_TTL
            for k in [k for k, v in flows.items() if v["ts"] < cutoff]:
                flows.pop(k, None)
            if len(flows) > 20000:
                flows.clear()
        flow = {"client": None, "host": "", "tls": False, "http": False, "ts": now}
        flows[key] = flow
    flow["ts"] = now
    if (flags & 0x02) and not (flags & 0x10):
        flow["client"] = (src, sport)          # SYN sender = client
    elif flow["client"] is None:
        # Capture started mid-connection: assume the lower port is the server.
        flow["client"] = (src, sport) if sport > dport else (dst, dport)
    return key, flow

def http_host(payload):
    for line in payload.split(b"\r\n")[1:40]:
        if not line:
            break
        if line[:5].lower() == b"host:":
            return line[5:].strip().decode("latin-1", errors="replace")
    return ""

def parse_sni(p):
    """Extract the server name from a TLS ClientHello."""
    try:
        i = 5 + 4 + 2 + 32                      # record + handshake hdr + version + random
        i += 1 + p[i]                           # session id
        i += 2 + int.from_bytes(p[i:i + 2], "big")   # cipher suites
        i += 1 + p[i]                           # compression methods
        end = min(i + 2 + int.from_bytes(p[i:i + 2], "big"), len(p))
        i += 2
        while i + 4 <= end:
            etype = int.from_bytes(p[i:i + 2], "big")
            elen = int.from_bytes(p[i + 2:i + 4], "big")
            i += 4
            if etype == 0:                      # server_name extension
                nlen = int.from_bytes(p[i + 3:i + 5], "big")
                return p[i + 5:i + 5 + nlen].decode("ascii", errors="ignore")
            i += elen
    except Exception:
        pass
    return ""

def _first(x):
    if isinstance(x, (list, tuple)):
        return x[0] if x else None
    return x

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}

def dns_question(d):
    try:
        q = _first(d.qd)
        if q is not None and hasattr(q, "qname"):
            return _name(q.qname), int(getattr(q, "qtype", 0) or 0)
    except Exception:
        pass
    return "", 0

def dns_info(d, client=""):
    qname, _ = dns_question(d)
    if d.qr == 0:
        return "DNS QUERY", "REQUEST", f"Query: {qname}", qname
    answers = dns_answers(d)
    ips = [a["rdata"] for a in answers if a["type"] in (1, 28)]
    if ips and qname:
        if len(dns_cache) > 30000:
            dns_cache.clear()
        if len(dns_dev_cache) > 60000:
            dns_dev_cache.clear()
        for ipaddr in ips:
            dns_cache[ipaddr] = qname
            if client:
                dns_dev_cache[(client, ipaddr)] = qname
    if ips:
        return "DNS RESPONSE", "RESPONSE", f"{qname} → {', '.join(ips[:4])}", qname
    return "DNS RESPONSE", "RESPONSE", f"{qname} → no address (rcode {d.rcode})", qname

def classify_packet(pkt):
    """Classify packets of every LAN device into requests / responses."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    from scapy.layers.l2 import ARP
    from scapy.layers.inet6 import IPv6

    ip = pkt.getlayer(IP)
    v6 = None
    if ip is None:
        if pkt.haslayer(ARP):
            return classify_arp(pkt)
        v6 = pkt.getlayer(IPv6)
        if v6 is None:
            return classify_l2(pkt)            # LLDP, STP, EAPOL ... (non-IP frames)
        dev6, outbound = v6_device(pkt)
        if dev6 is None:
            return None                       # IPv6 from a device we have not matched to a MAC yet
        real_src, real_dst = str(v6.src), str(v6.dst)
        # the LAN side is represented by the device's IPv4 so one device = one road
        src, dst = (dev6, real_dst) if outbound else (real_src, dev6)
    else:
        src, dst = str(ip.src), str(ip.dst)
        real_src, real_dst = src, dst
    src_lan, dst_lan = in_lan(src), in_lan(dst)
    if not (src_lan or dst_lan):
        return None

    now = time.time()
    remote = src if (dst_lan and not src_lan) else dst
    lan_client = src if src_lan else dst
    proto, sport, dport, flags = "IP", None, None, ""
    packet_type, detail, rr, req_text = "NETWORK DATA", "", "OTHER", ""
    remote_host, service, search_term = "", "", ""
    payload_len = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto, sport, dport, flags = "TCP", int(tcp.sport), int(tcp.dport), str(tcp.flags)
        f = int(tcp.flags)
        raw = tcp.getlayer(Raw)                 # ignores Ethernet padding
        payload = bytes(raw.load) if raw is not None else b""
        payload_len = len(payload)
        service = PORT_NAMES.get(sport) or PORT_NAMES.get(dport) or ""
        key, flow = get_flow(src, sport, dst, dport, f, now)
        from_client = flow["client"] == (src, sport)
        remote_host = flow["host"] or lookup_host(lan_client, remote)

        if f & 0x04:
            packet_type, rr, detail = "TCP RESET", "CONNECTION", "Connection reset"
            flows.pop(key, None)
        elif (f & 0x12) == 0x12:
            packet_type, rr, detail = "TCP SYN-ACK", "CONNECTION", "Connection accepted"
        elif f & 0x02:
            packet_type, rr, detail = "TCP SYN", "CONNECTION", "Connection initiation"
        elif payload:
            line = payload.split(b"\r\n", 1)[0][:300]
            upper = line.upper()
            if upper.startswith(HTTP_METHODS):
                flow["http"] = True
                host = http_host(payload)
                if host:
                    flow["host"] = remote_host = host
                line_r = redact(line).decode("latin-1", errors="replace")
                parts = line_r.split(" ")
                target = parts[1] if len(parts) > 1 else ""
                packet_type, rr, detail = "HTTP REQUEST", "REQUEST", line_r
                req_text = f"{parts[0]} http://{host}{target}" if host and target.startswith("/") else line_r
                search_term = extract_search(host or remote_host, target)
                if search_term:
                    req_text = f'🔎 Search "{search_term}" · {req_text}'
            elif upper.startswith(b"HTTP/"):
                flow["http"] = True
                line_r = redact(line).decode("latin-1", errors="replace")
                status = " ".join(line_r.split(" ")[1:])
                packet_type, rr, detail = "HTTP RESPONSE", "RESPONSE", line_r
                req_text = f"{status} ← {remote_host or remote}"
            elif len(payload) >= 6 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03 and payload[2] <= 4:
                flow["tls"] = True
                ctype = payload[0]
                if ctype == 0x16:
                    hs = payload[5]
                    rr = "CONNECTION"
                    if hs == 1:
                        sni = parse_sni(payload)
                        if sni:
                            flow["host"] = remote_host = sni
                        packet_type = "TLS CLIENT HELLO"
                        detail = f"SNI: {sni}" if sni else "TLS handshake start (no SNI)"
                        req_text = f"HTTPS connect → {remote_host or remote}"
                    elif hs == 2:
                        packet_type = "TLS SERVER HELLO"
                        detail = remote_host or remote
                    else:
                        packet_type = "TLS HANDSHAKE"
                        detail = remote_host or remote
                elif ctype == 0x17:
                    packet_type = "HTTPS REQUEST" if from_client else "HTTPS RESPONSE"
                    rr = "REQUEST" if from_client else "RESPONSE"
                    detail = f"{remote_host or remote} · encrypted · {payload_len} bytes"
                    req_text = f"HTTPS {'→' if from_client else '←'} {remote_host or remote} ({payload_len} B)"
                elif ctype == 0x15:
                    packet_type, rr, detail = "TLS ALERT", "CONNECTION", remote_host or remote
                else:
                    packet_type, rr, detail = "TLS HANDSHAKE", "CONNECTION", remote_host or remote
            elif flow["tls"] or 443 in (sport, dport):
                # Continuation segment of a bigger TLS record
                packet_type = "HTTPS REQUEST" if from_client else "HTTPS RESPONSE"
                rr = "REQUEST" if from_client else "RESPONSE"
                detail = f"{remote_host or remote} · encrypted (continued) · {payload_len} bytes"
                req_text = f"HTTPS {'→' if from_client else '←'} {remote_host or remote} ({payload_len} B)"
            elif flow["http"]:
                packet_type = "HTTP DATA"
                rr = "REQUEST" if from_client else "RESPONSE"
                detail = f"{remote_host or remote} · {payload_len} bytes (body/continued)"
                req_text = f"HTTP {'→' if from_client else '←'} {remote_host or remote} ({payload_len} B)"
            else:
                packet_type = "TCP DATA"
                detail = f"{service + ' · ' if service else ''}{payload_len} payload bytes"
        elif f & 0x01:
            packet_type, rr, detail = "TCP FIN", "CONNECTION", "Connection closing"
        else:
            if not SHOW_PURE_ACK:
                return None
            packet_type, detail = "TCP ACK/CONTROL", "TCP control/acknowledgement"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto, sport, dport = "UDP", int(udp.sport), int(udp.dport)
        payload_len = max(0, int(udp.len or 8) - 8)
        service = PORT_NAMES.get(sport) or PORT_NAMES.get(dport) or ""
        packet_type = service if service in ("mDNS", "SSDP/UPnP", "NetBIOS", "LLMNR", "NTP") else "UDP DATA"
        detail = f"{payload_len} payload bytes"
        remote_host = lookup_host(lan_client, remote)
        if (sport == 53 or dport == 53) and pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            packet_type, rr, detail, qname = dns_info(dns_layer, dst if dns_layer.qr else src)
            remote_host = qname
            req_text = f"DNS lookup {qname}" if rr == "REQUEST" else detail
        elif sport == 53 or dport == 53:
            packet_type, detail = "DNS", "DNS query/response traffic"
        elif 443 in (sport, dport):
            packet_type = "QUIC / HTTP3"
            rr = "REQUEST" if src_lan else "RESPONSE"
            detail = f"Encrypted QUIC datagram · {payload_len} bytes"
            req_text = f"QUIC/HTTP3 {'→' if rr == 'REQUEST' else '←'} {remote_host or remote}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        itype = int(pkt[ICMP].type)
        packet_type, detail = "ICMP", f"ICMP {ICMP_TYPES.get(itype, f'type {itype}')}"
        if itype == 8:
            packet_type, rr, detail = "ICMP PING", "REQUEST", "Echo request"
            req_text = f"Ping → {remote}"
        elif itype == 0:
            packet_type, rr, detail = "ICMP PING REPLY", "RESPONSE", "Echo reply"
            req_text = f"Ping reply ← {remote}"
    elif v6 is not None:
        body = bytes(v6.payload)
        if int(v6.nh) == 58 and body:
            proto = "ICMPv6"
            t6 = body[0]
            label = ICMP6_TYPES.get(t6, f"type {t6}")
            packet_type, detail = "ICMPv6", label
            if t6 == 128:
                packet_type, rr, req_text = "ICMP PING", "REQUEST", f"Ping6 → {remote}"
            elif t6 == 129:
                packet_type, rr, req_text = "ICMP PING REPLY", "RESPONSE", f"Ping6 reply ← {remote}"
            elif t6 == 135:
                rr, req_text = "REQUEST", "IPv6 neighbor discovery: who is there?"
            elif t6 == 136:
                rr, req_text = "RESPONSE", "IPv6 neighbor discovery: I am here"
        else:
            proto, packet_type = "IPv6", "IPv6 DATA"
            detail = f"IPv6 next-header {int(v6.nh)} · {len(body)} bytes"
    elif ip is not None:
        # IGMP, GRE, ESP, AH, SCTP, OSPF, VRRP, IP fragments ... (any other IPv4 protocol)
        pnum = int(ip.proto)
        pname = IP_PROTOS.get(pnum, f"IP/{pnum}")
        if int(ip.frag or 0) > 0:
            proto, packet_type = "IP", "IP FRAGMENT"
            detail = f"Fragment of a {pname} packet · {len(ip.payload)} bytes"
        else:
            proto, packet_type = pname, pname
            detail = f"IP protocol {pnum} ({pname}) · {len(ip.payload)} bytes"
        service = pname

    # Decide which side is the "device": the LAN client for requests,
    # the LAN receiver for responses.
    if src_lan and dst_lan:
        direction = "LAN"
        dev, peer = (dst, src) if rr == "RESPONSE" else (src, dst)
    elif src_lan:
        direction, dev, peer = "OUT", src, dst
    else:
        direction, dev, peer = "IN", dst, src
    dev_port, peer_port = (sport, dport) if dev == src else (dport, sport)

    peer_is_lan = in_lan(peer)
    peer_name = device_name(peer) if peer_is_lan else ""
    if peer_is_lan:
        remote_host = remote_host or peer_name
    elif not remote_host:
        remote_host = lookup_host(dev, peer)
    request_rdns(dev, now)
    if peer_is_lan:
        request_rdns(peer, now)

    dev_mac = ip_mac.get(dev, "")
    return {
        "id": f"{now:.6f}-{next(packet_counter)}",
        "ts": now,
        "time": datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3],
        "src": src, "dst": dst, "sport": sport, "dport": dport,
        "proto": proto, "bytes": int(len(pkt)), "payload_bytes": payload_len,
        "flags": flags, "direction": direction,
        "device_ip": dev, "device_name": device_name(dev), "device_mac": dev_mac,
        "device_vendor": vendor_of(dev_mac), "device_port": dev_port,
        "peer_ip": peer, "peer_name": peer_name, "peer_port": peer_port,
        "remote_host": remote_host, "service": service,
        "site_app": site_app(remote_host) if remote_host else "", "search": search_term,
        "src_kind": ip_kind(src), "dst_kind": ip_kind(dst),
        "ip_version": 6 if v6 is not None else 4,
        "packet_type": packet_type, "request_response": rr, "detail": detail,
        "request": req_text or detail,
        "summary": f"{real_src}:{sport if sport is not None else '*'} → {real_dst}:{dport if dport is not None else '*'}"
    }

# ------------------------------------------------------------
# Detailed decode (used by /api/packet/<id>)
# ------------------------------------------------------------
TLS_RECORD = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
TLS_VERSION = {(3, 0): "SSL 3.0", (3, 1): "TLS 1.0", (3, 2): "TLS 1.1", (3, 3): "TLS 1.2 / 1.3"}
TLS_HANDSHAKE = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
                 11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange", 20: "Finished"}

def parse_tls(p):
    if len(p) < 6 or p[0] not in TLS_RECORD or p[1] != 3:
        return {}
    info = {
        "record_type": TLS_RECORD[p[0]],
        "record_version": TLS_VERSION.get((p[1], p[2]), f"{p[1]}.{p[2]}"),
        "record_length": int.from_bytes(p[3:5], "big"),
    }
    if p[0] == 22:
        info["handshake_type"] = TLS_HANDSHAKE.get(p[5], str(p[5]))
        if p[5] == 1:
            sni = parse_sni(p)
            info["server_names"] = [sni] if sni else []
    return info

def parse_http(p):
    head, _, body = p.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    first = lines[0].decode("latin-1", errors="replace")
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.decode("latin-1").strip()] = v.decode("latin-1").strip()
    out = {"headers": headers, "header_text": head.decode("latin-1", errors="replace"),
           "host": headers.get("Host") or headers.get("host"),
           "content_type": headers.get("Content-Type"), "content_length_header": headers.get("Content-Length"),
           "body_bytes_in_packet": len(body),
           "body_preview": "".join(chr(x) if 32 <= x < 127 or x in (9, 10, 13) else "." for x in body[:2000])}
    if first.upper().startswith("HTTP/"):
        parts = first.split(" ", 2)
        out.update({"kind": "HTTP Response", "http_version": parts[0],
                    "status_code": parts[1] if len(parts) > 1 else "",
                    "status_text": parts[2] if len(parts) > 2 else ""})
    else:
        parts = first.split(" ")
        target = parts[1] if len(parts) > 1 else ""
        host = out["host"]
        out.update({"kind": "HTTP Request", "method": parts[0], "request_target": target,
                    "http_version": parts[2] if len(parts) > 2 else "",
                    "url": f"http://{host}{target}" if host and target.startswith("/") else target})
    return out

def hexdump(b):
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hx = " ".join(f"{x:02x}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{i:04x}  {hx:<47}  {asc}")
    return "\n".join(lines)

def build_details(pkt, rec):
    from scapy.layers.l2 import Ether, Dot3
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS

    from scapy.layers.l2 import ARP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw

    d = dict(rec)
    ip = pkt.getlayer(IP)
    v6 = pkt.getlayer(IPv6)
    arp = pkt.getlayer(ARP)
    eth = pkt.getlayer(Ether)
    if eth is None:
        eth = pkt.getlayer(Dot3)
    tcp = pkt.getlayer(TCP)
    udp = pkt.getlayer(UDP)

    layers, layer = [], pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        layers.append(layer.__class__.__name__)
        layer = layer.payload

    payload = b""
    ip_fields = {"ip_version": None, "ip_len": None, "ttl_hop_limit": None, "ip_id": None}
    if ip is not None:
        raw = getattr(pkt, "original", None) or bytes(pkt)
        ip_off = len(raw) - len(bytes(ip))
        total = int(ip.len or 0)
        if total <= 0 or ip_off + total > len(raw):
            total = len(raw) - ip_off
        l4 = raw[ip_off + int(ip.ihl or 5) * 4: ip_off + total]
        if tcp is not None:
            payload = l4[int(tcp.dataofs or 5) * 4:]
        elif udp is not None:
            payload = l4[8:]
        else:
            payload = l4                      # ICMP / IGMP / GRE / ESP / SCTP ... : everything after the IP header
        ip_fields = {"ip_version": 4, "ip_len": ip.len, "ttl_hop_limit": int(ip.ttl), "ip_id": int(ip.id)}
    elif v6 is not None:
        l4p = tcp if tcp is not None else udp
        r = l4p.getlayer(Raw) if l4p is not None else None
        payload = bytes(r.load) if r is not None else b""
        ip_fields = {"ip_version": 6, "ip_len": int(v6.plen or 0), "ttl_hop_limit": int(v6.hlim or 0), "ip_id": None,
                     "ipv6_source": str(v6.src), "ipv6_destination": str(v6.dst)}
    elif arp is not None:
        payload = bytes(pkt)[:128]            # the whole (small) ARP frame
        ip_fields = {"ip_version": "ARP", "arp_operation": "who-has (request)" if int(arp.op) == 1 else "is-at (reply)",
                     "arp_sender_mac": str(arp.hwsrc), "arp_sender_ip": str(arp.psrc),
                     "arp_target_mac": str(arp.hwdst), "arp_target_ip": str(arp.pdst)}
    elif eth is not None:
        payload = bytes(pkt)[14:]             # non-IP Ethernet frame (LLDP, STP, EAPOL ...)
        ip_fields = {"ip_version": "L2", "ip_len": None, "ttl_hop_limit": None, "ip_id": None}

    d.update(ip_fields)
    d.update({
        "ether_src": eth.src if eth is not None else None,
        "ether_dst": eth.dst if eth is not None else None,
        "layers": " / ".join(layers),
        "tcp_flags": str(tcp.flags) if tcp is not None else None,
        "tcp_seq": int(tcp.seq) if tcp is not None else None,
        "tcp_ack": int(tcp.ack) if tcp is not None else None,
        "tcp_window": int(tcp.window) if tcp is not None else None,
        "payload_length": len(payload),
    })

    shown = redact(payload[:4096])
    d["payload_truncated"] = len(payload) > 4096
    d["payload_text"] = "".join(chr(x) if 32 <= x < 127 or x in (9, 10, 13) else "." for x in shown)
    d["payload_hex"] = hexdump(shown)
    d["payload_base64"] = base64.b64encode(shown).decode("ascii")

    http, dns, tls = {}, {}, {}
    note = ""
    ptype = rec["packet_type"]
    if tcp is not None and payload:
        if ptype.startswith("HTTP"):
            if ptype in ("HTTP REQUEST", "HTTP RESPONSE"):
                http = parse_http(shown)
            note = "Plain-text HTTP (not encrypted)."
            if REDACT_SECRETS:
                note += " Authorization/cookie/password/token values are redacted in this preview."
        elif ptype.startswith(("HTTPS", "TLS")):
            tls = parse_tls(payload)
            note = "Encrypted TLS record: only host name (SNI), size and direction are visible."
    if udp is not None and pkt.haslayer(DNS) and (rec["sport"] == 53 or rec["dport"] == 53):
        dd = pkt[DNS]
        qname, qtype = dns_question(dd)
        dns = {"message_type": "Response" if dd.qr else "Query", "id": int(dd.id), "question_name": qname,
               "question_type": QTYPES.get(qtype, str(qtype)), "rcode": int(dd.rcode),
               "answers": dns_answers(dd)}
    if ptype == "QUIC / HTTP3":
        note = "QUIC/HTTP3 is encrypted. Host name comes from earlier DNS answers when known."
    if http:
        d["http"] = http
    if dns:
        d["dns"] = dns
    if tls:
        d["tls"] = tls

    if http:
        d["application"] = "HTTP (plain text)"
    elif ptype.startswith(("HTTPS", "TLS")):
        d["application"] = "HTTPS / TLS (encrypted)"
    elif dns:
        d["application"] = "DNS"
    elif ptype == "QUIC / HTTP3":
        d["application"] = "QUIC / HTTP3 (encrypted)"
    else:
        d["application"] = rec.get("service") or rec["proto"]
    d["payload_note"] = note
    return d

# ------------------------------------------------------------
# Websites per device (which device opened which domain, search activity)
# ------------------------------------------------------------
def site_hits(s):
    return max(s["dns"], s["conns"])

def track_site(rec):
    host = useful_host(rec.get("remote_host"))
    if not host:
        return
    ptype = rec["packet_type"]
    if not (rec["direction"] in ("OUT", "IN") or ptype.startswith("DNS")):
        return
    ip, ts = rec["device_ip"], rec["ts"]
    sites = device_sites.get(ip)
    if sites is None:
        sites = device_sites[ip] = OrderedDict()
    s = sites.get(host)
    if s is None:
        if len(sites) >= MAX_SITES_PER_DEVICE:
            sites.popitem(last=False)
        s = sites[host] = {"host": host, "app": site_app(host), "dns": 0, "conns": 0,
                           "packets": 0, "bytes": 0, "first": ts, "last": ts,
                           "kinds": [], "last_dns": 0.0}
    else:
        sites.move_to_end(host)          # most recent host stays last
    s["last"] = ts
    s["packets"] += 1
    s["bytes"] += rec["bytes"]
    kind = ("DNS" if ptype.startswith("DNS") else "HTTPS" if ptype.startswith(("TLS", "HTTPS"))
            else "HTTP" if ptype.startswith("HTTP") else "QUIC" if ptype.startswith("QUIC") else "")
    if kind and kind not in s["kinds"]:
        s["kinds"].append(kind)
    if ptype == "DNS QUERY":
        if ts - s["last_dns"] > 3:       # A + AAAA lookups of one visit count once
            s["dns"] += 1
        s["last_dns"] = ts
    elif ptype in ("TLS CLIENT HELLO", "HTTP REQUEST"):
        s["conns"] += 1

    term = rec.get("search")
    visit = ptype in ("DNS QUERY", "TLS CLIENT HELLO", "HTTP REQUEST")
    if term:
        search_log.appendleft({"ts": ts, "time": rec["time"], "device_ip": ip, "host": host,
                               "app": s["app"], "kind": "term", "term": term})
    elif visit and s["app"] in SEARCH_ENGINES:
        key = (ip, host)
        if ts - search_seen.get(key, 0) > 20:
            if len(search_seen) > 5000:
                search_seen.clear()
            search_seen[key] = ts
            search_log.appendleft({"ts": ts, "time": rec["time"], "device_ip": ip, "host": host,
                                   "app": s["app"], "kind": "engine", "term": ""})

def top_sites_of(ip, n=5):
    sites = device_sites.get(ip)
    if not sites:
        return []
    return [{"host": s["host"], "app": s["app"], "hits": site_hits(s)}
            for s in reversed(list(sites.values())[-n:])]

def aggregate_sites(device="", limit=200):
    """All websites (optionally of one device) with the devices that used them."""
    agg = {}
    for ip, sites in device_sites.items():
        if device and ip != device:
            continue
        for host, s in sites.items():
            a = agg.get(host)
            if a is None:
                a = agg[host] = {"host": host, "app": s["app"], "hits": 0, "packets": 0,
                                 "bytes": 0, "last": 0, "kinds": [], "devices": []}
            a["hits"] += site_hits(s)
            a["packets"] += s["packets"]
            a["bytes"] += s["bytes"]
            a["last"] = max(a["last"], s["last"])
            a["devices"].append({"ip": ip, "name": device_name(ip), "hits": site_hits(s)})
            for k in s["kinds"]:
                if k not in a["kinds"]:
                    a["kinds"].append(k)
    ordered = sorted(agg.values(), key=lambda x: x["last"], reverse=True)
    return ordered[:limit], len(ordered)

def search_view(device="", limit=80):
    out = []
    for item in search_log:
        if device and item["device_ip"] != device:
            continue
        row = dict(item)
        row["device_name"] = device_name(item["device_ip"])
        out.append(row)
        if len(out) >= limit:
            break
    return out

# ------------------------------------------------------------
# Device counters
# ------------------------------------------------------------
def touch_device(rec):
    ip, ts = rec["device_ip"], rec["ts"]
    dev = ensure_device(ip, ts, "traffic")
    dev["last_seen"] = ts
    dev["packets"] += 1
    proto = rec["proto"]
    dev["protocols"][proto] = dev["protocols"].get(proto, 0) + 1
    ptype = rec["packet_type"]
    dev["packet_types"][ptype] = dev["packet_types"].get(ptype, 0) + 1
    svc = rec.get("service")
    if svc:
        dev["services"][svc] = dev["services"].get(svc, 0) + 1
    if rec["src"] == ip:
        dev["bytes_out"] += rec["bytes"]
    else:
        dev["bytes_in"] += rec["bytes"]
    if rec["request_response"] == "REQUEST":
        dev["requests"] += 1
    elif rec["request_response"] == "RESPONSE":
        dev["responses"] += 1
    if rec["packet_type"] in ("HTTP REQUEST", "TLS CLIENT HELLO", "DNS QUERY"):
        dev["last_request"] = rec["request"]
        dev["last_request_ts"] = ts
        host = rec["remote_host"]
        if host:
            hosts = dev["recent_hosts"]
            if host in hosts:
                hosts.remove(host)
            hosts.insert(0, host)
            del hosts[8:]
    track_site(rec)

def device_view(dev):
    ip = dev["ip"]
    mac = ip_mac.get(ip, "")
    out = dict(dev)
    now = time.time()
    out.update({"name": device_name(ip), "mac": mac, "vendor": vendor_of(mac),
                "is_gateway": ip == LAN_HOST, "is_this_pc": ip in MY_IPS,
                "online": now - dev["last_seen"] <= ONLINE_SECONDS,
                "top_sites": top_sites_of(ip), "site_count": len(device_sites.get(ip, ())),
                "history": len(device_events.get(ip, ()))})
    return out

def packet_callback(pkt):
    try:
        with lock:
            learn_passive(pkt)
            record = classify_packet(pkt)
            if record is None:
                return
            events.appendleft(record)
            hist = device_events.get(record["device_ip"])
            if hist is None:
                hist = device_events[record["device_ip"]] = deque(maxlen=DEVICE_HISTORY)
            hist.appendleft(record)
            packet_store[record["id"]] = (pkt, record)
            while len(packet_store) > PACKET_STORE_MAX:
                packet_store.popitem(last=False)
            stats["packets"] += 1
            stats["bytes"] += record["bytes"]
            stats["last_packet_at"] = record["ts"]
            if record["proto"] == "TCP":
                stats["tcp"] += 1
            elif record["proto"] == "UDP":
                stats["udp"] += 1
            elif record["proto"] == "ICMP":
                stats["icmp"] += 1
            else:
                stats["other"] += 1
            ptype = record["packet_type"]
            if ptype in ("HTTP REQUEST", "HTTPS REQUEST"):
                stats["requests"] += 1
            elif ptype in ("HTTP RESPONSE", "HTTPS RESPONSE"):
                stats["responses"] += 1
            elif ptype == "DNS QUERY":
                stats["dns"] += 1
            elif ptype == "TCP SYN":
                stats["connections"] += 1
            if record["src"] not in MY_IPS and record["dst"] not in MY_IPS \
                    and not is_multicast_or_broadcast(record["dst"]):
                stats["third_party"] += 1
            touch_device(record)
    except Exception as exc:
        print(f"[PACKET WARNING] {exc}")

def resolve_interface():
    from scapy.all import conf, get_if_list, get_if_addr
    if LAN_INTERFACE:
        if LAN_INTERFACE not in get_if_list():
            raise RuntimeError(f"LAN_INTERFACE not found: {LAN_INTERFACE}")
        return LAN_INTERFACE

    # Best match: interface that has an address inside the monitored subnet.
    for iface in get_if_list():
        try:
            if in_lan(get_if_addr(iface)):
                return iface
        except Exception:
            continue

    try:
        route = conf.route.route(LAN_HOST)
        if route and route[0]:
            return route[0]
    except Exception:
        pass

    return getattr(conf.iface, "name", str(conf.iface))

def arp_sweep_worker():
    """Ask every address of the subnet 'who has x.x.x.x?' (like arp-scan) so silent devices
    show up too. The replies come back to this PC and are learned by the normal capture."""
    if not ARP_SWEEP:
        return
    time.sleep(3)                                  # let the capture start first
    while True:
        try:
            from scapy.all import Ether, ARP, sendp, conf
            if os.name == "nt":
                conf.use_pcap = True
            with lock:
                iface = stats["interface"]
            hosts = [str(h) for h in LAN_NET.hosts()][:1024]
            frames = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=h, psrc=THIS_PC_IP) for h in hosts]
            sendp(frames, iface=iface if iface not in ("detecting", "") else None,
                  inter=0.004, verbose=False)
        except Exception as exc:
            print(f"[ARP SWEEP WARNING] {exc}")
        time.sleep(max(30, ARP_SWEEP_EVERY))

def capture_worker():
    try:
        from scapy.all import conf, sniff

        # Tell Scapy to use its libpcap/Npcap backend on Windows.
        if os.name == "nt":
            conf.use_pcap = True

        iface = resolve_interface()
        with lock:
            stats["interface"] = str(iface)
            stats["capture_status"] = "starting"
            stats["capture_error"] = ""

        print("=" * 60)
        print("LAN 3D TRAFFIC OBSERVATORY")
        print(f"Switch / gateway: {LAN_HOST}   Monitored subnet: {LAN_NET}")
        print(f"This PC: {THIS_PC_IP}   Interface: {iface}")
        print(f"Capture filter: {CAPTURE_FILTER}")
        print(f"Promiscuous: {PROMISCUOUS}   Scapy use_pcap: {getattr(conf, 'use_pcap', False)}")
        print("=" * 60)

        # If Npcap is absent/broken, sniff raises an actionable error.
        with lock:
            stats["capture_status"] = "running"

        sniff(
            iface=iface,
            filter=CAPTURE_FILTER,
            prn=packet_callback,
            store=False,
            promisc=PROMISCUOUS
        )
        with lock:
            stats["capture_status"] = "stopped"
    except Exception as exc:
        message = str(exc)
        if os.name == "nt":
            message += (
                "\n\nWindows capture checklist:\n"
                "1. Install/repair Npcap from https://npcap.com/#download\n"
                "2. Enable WinPcap API-compatible mode if offered.\n"
                "3. Restart Windows if prompted.\n"
                "4. Run this app as Administrator.\n"
                "5. Test: python -c \"from scapy.all import conf; conf.use_pcap=True; print(conf.use_pcap)\""
            )
        else:
            message += "\n\nOn Linux/macOS run with sudo: sudo python3 app.py"
        with lock:
            stats["capture_status"] = "error"
            stats["capture_error"] = message
        print("[CAPTURE ERROR]", message)

# ------------------------------------------------------------
# Web API
# ------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/snapshot")
def snapshot():
    now = time.time()
    view = flask_request.args.get("view", "all")         # all = everything, rr = requests & responses only
    proto = flask_request.args.get("proto", "ALL")
    device = flask_request.args.get("device", "").strip()
    query = flask_request.args.get("q", "").strip().lower()
    try:
        limit = max(10, min(3000, int(flask_request.args.get("limit", "300"))))
    except ValueError:
        limit = 300

    with lock:
        copied = list(events)
        # a selected device is read from its OWN history: busy devices cannot push it out
        source = list(device_events.get(device, ())) if device else copied
        current = dict(stats)
        device_list = [device_view(x) for x in devices.values()]
        site_list, site_total = aggregate_sites(device)
        search_list = search_view(device)
        current["site_count"] = len({h for sites in device_sites.values() for h in sites})

    recent = [e for e in copied if now - e["ts"] <= WINDOW_SECONDS]
    shown = []
    has_more = False
    for e in source:
        if view != "all" and e["request_response"] not in ("REQUEST", "RESPONSE"):
            continue
        if proto != "ALL" and e["proto"] != proto:
            continue
        if device and e["device_ip"] != device:
            continue
        if query:
            blob = " ".join(str(e.get(k, "")) for k in (
                "device_ip", "device_name", "peer_ip", "peer_name", "remote_host",
                "request", "packet_type", "device_mac")).lower()
            if query not in blob:
                continue
        if len(shown) >= limit:
            has_more = True
            break
        shown.append(e)

    device_list.sort(key=lambda x: x["last_seen"], reverse=True)
    current["online_count"] = sum(1 for x in device_list if x["online"])
    current["has_more"] = has_more
    current["shown"] = len(shown)
    current["bps"] = round(sum(e["bytes"] for e in recent) * 8 / WINDOW_SECONDS, 1)
    current["pps"] = round(len(recent) / WINDOW_SECONDS, 2)
    current["uptime"] = int(now - current["started_at"])
    current["local_addresses"] = LOCAL_ADDRESSES
    current["target_ip"] = LAN_HOST
    current["this_pc"] = THIS_PC_IP
    current["subnet"] = str(LAN_NET)
    current["promisc"] = PROMISCUOUS
    current["filter"] = CAPTURE_FILTER
    current["event_count"] = len(copied)
    current["window_seconds"] = WINDOW_SECONDS
    hint = ""
    if current["capture_status"] == "running" and current["uptime"] > 60 and current["third_party"] == 0:
        hint = ("Only this PC's own traffic and broadcasts are visible. To see other devices, set up "
                "port mirroring (SPAN) on the switch with this PC's port as the destination.")
    current["visibility_hint"] = hint
    current["device_count"] = len(device_list)
    current["server_time"] = now
    current["gateway_name"] = device_name(LAN_HOST)
    # the 3D scene always gets the unfiltered live feed, whatever the table filters are
    live = [e for e in copied[:300] if now - e["ts"] < 6]
    return jsonify({"stats": current, "events": shown, "live": live, "devices": device_list[:1000],
                    "sites": site_list, "searches": search_list})

@app.route("/api/sites")
def sites_api():
    device = flask_request.args.get("device", "").strip()
    with lock:
        site_list, total = aggregate_sites(device, limit=1000)
    return jsonify({"total": total, "sites": site_list})

@app.route("/api/device/<ip>")
def device_api(ip):
    with lock:
        dev = devices.get(ip)
        if dev is None:
            return jsonify({"error": "Unknown device"}), 404
        view = device_view(dev)
        sites = sorted(device_sites.get(ip, {}).values(), key=lambda x: x["last"], reverse=True)
        view["sites"] = [dict(s, hits=site_hits(s)) for s in sites]
        view["searches"] = search_view(ip, limit=200)
        view["recent_requests"] = [
            {k: e[k] for k in ("id", "time", "ts", "packet_type", "request", "remote_host", "peer_ip", "bytes")}
            for e in list(device_events.get(ip, ()))
            if e["request_response"] == "REQUEST"][:30]
    return jsonify(view)

@app.route("/api/devices")
def devices_api():
    with lock:
        device_list = [device_view(x) for x in devices.values()]
    device_list.sort(key=lambda x: x["last_seen"], reverse=True)
    return jsonify(device_list)

@app.route("/api/packet/<pid>")
def packet_detail(pid):
    with lock:
        item = packet_store.get(pid)
    if item is None:
        return jsonify({"error": "This packet is no longer kept in memory."}), 404
    pkt, rec = item
    try:
        return jsonify(build_details(pkt, rec))
    except Exception as exc:
        return jsonify({"error": f"Could not decode packet: {exc}"}), 500

@app.route("/api/alias", methods=["POST"])
def set_alias():
    data = flask_request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    name = str(data.get("name", "")).strip()[:60]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP"}), 400
    with lock:
        if name:
            DEVICE_ALIASES[ip] = name
        else:
            DEVICE_ALIASES.pop(ip, None)
        save_aliases()
    return jsonify({"success": True})

@app.route("/api/health")
def health():
    with lock:
        return jsonify({
            "status": stats["capture_status"],
            "error": stats["capture_error"],
            "interface": stats["interface"],
            "target_ip": LAN_HOST,
            "subnet": str(LAN_NET)
        })

@app.route("/api/interfaces")
def interfaces():
    from scapy.all import get_if_list, get_if_addr
    result = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "unknown"
        result.append({"name": iface, "ipv4": ip, "in_monitored_subnet": in_lan(ip)})
    return jsonify({
        "gateway_ip": LAN_HOST,
        "subnet": str(LAN_NET),
        "system_adapters": {
            name: [a.address for a in addresses if a.family == socket.AF_INET]
            for name, addresses in psutil.net_if_addrs().items()
        },
        "scapy_interfaces": result
    })

@app.route("/api/reset", methods=["POST"])
def reset_stats():
    with lock:
        events.clear()
        packet_store.clear()
        device_events.clear()
        devices.clear()
        for known_ip in list(ip_mac):          # keep the device list: re-register what ARP/DHCP already told us
            ensure_device(known_ip, time.time(), "arp")
        device_sites.clear()
        search_log.clear()
        search_seen.clear()
        for key in ("packets", "bytes", "tcp", "udp", "icmp", "other",
                    "requests", "responses", "connections", "dns", "third_party"):
            stats[key] = 0
        stats["started_at"] = time.time()
        stats["last_packet_at"] = None
    return jsonify({"success": True})

if __name__ == "__main__":
    print(f"Dashboard: http://127.0.0.1:{PORT}")
    print(f"Monitoring subnet {LAN_NET} (switch/gateway {LAN_HOST}), this PC {THIS_PC_IP}")
    for _ in range(3):
        threading.Thread(target=rdns_worker, daemon=True, name="rdns").start()
    with lock:                                     # the gateway and this PC are always in the list
        ensure_device(LAN_HOST, time.time(), "config")
        if in_lan(THIS_PC_IP):
            ensure_device(THIS_PC_IP, time.time(), "config")
    threading.Thread(target=capture_worker, daemon=True, name="packet-capture").start()
    threading.Thread(target=arp_sweep_worker, daemon=True, name="arp-sweep").start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)
