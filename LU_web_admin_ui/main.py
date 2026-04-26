"""
QuantClaw 网络扫描服务
扫描当前网段设备，并尽可能识别 Quant 设备
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import json
import os
import platform
import re
import socket
import subprocess
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
PI_PREFIXES = ("B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1", "2C:CF:67", "8C:1F:64")

app = FastAPI(title="QuantClaw Network Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


class Device(BaseModel):
    ip: str
    mac: str
    hostname: Optional[str] = None
    name: Optional[str] = None
    is_quant: bool = False
    web_port: Optional[int] = None
    web_url: Optional[str] = None


class ScanResult(BaseModel):
    devices: List[Device]
    quant_device: Optional[Device] = None
    total: int
    gateway: str


class QuantFoundResult(BaseModel):
    found: bool
    devices: List[Device] = []
    message: str = ""


class USBDevice(BaseModel):
    interface: str
    local_ip: str
    ip: str
    gateway: str
    reachable: bool = False
    web_accessible: bool = False
    hostname: Optional[str] = None
    mdns_ip: Optional[str] = None
    url: Optional[str] = None
    mac_address: Optional[str] = None


class USBScanResult(BaseModel):
    usb_devices: List[USBDevice]
    connected: bool
    ready: bool
    message: str
    level: str = "none"
    troubleshooting_hints: List[str] = []


class USBProvisionRequest(BaseModel):
    ssid: str
    password: str = ""
    security: str = "WPA2"
    hidden: bool = False
    country: Optional[str] = None


class USBProvisionResult(BaseModel):
    success: bool
    message: str
    target_url: Optional[str] = None
    device_url: Optional[str] = None
    detail: Optional[dict] = None


class ConnectionLevel(str, Enum):
    NONE = "none"
    INTERFACE = "interface"
    IP = "ip"
    REACHABLE = "reachable"
    READY = "ready"


class USBInterfaceInfo(BaseModel):
    name: str
    mac: str
    ip: Optional[str] = None
    has_ip: bool = False


class USBShareRequest(BaseModel):
    enable: bool = True


class USBShareResult(BaseModel):
    success: bool
    message: str
    wan_interface: Optional[str] = None
    usb_interface: Optional[str] = None


GADGET_SUBNET = "9.9.9"
GADGET_HOST = "9.9.9.1"
GADGET_MDNS = "quantclaw.local"
GADGET_PORT = 80
USB_PROVISION_PORT = 8081
USB_PROVISION_ENDPOINTS = (
    "/api/provision/wifi",
    "/api/provision/network",
    "/api/network/configure",
)
SIMULATE_USB = os.environ.get("QUANTCLAW_SIMULATE_USB", "").lower() in {"1", "true", "yes"}
SIMULATED_DEVICE_URL = os.environ.get("QUANTCLAW_SIMULATED_DEVICE_URL", "http://127.0.0.1:8090")
SIMULATED_DEVICE_HOSTNAME = os.environ.get("QUANTCLAW_SIMULATED_DEVICE_HOSTNAME", GADGET_MDNS)


def build_http_url(host: str, port: int = 80) -> str:
    """构造 HTTP URL。"""
    return f"http://{host}" if port == 80 else f"http://{host}:{port}"


def join_url(base: str, path: str) -> str:
    """拼接基础 URL 和路径。"""
    return base.rstrip("/") + path


def run_command(command: List[str], timeout: int = 5) -> str:
    """运行命令并返回标准输出，失败时返回空字符串。"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except Exception:
        return ""


def get_gateway() -> str:
    """获取默认网关。"""
    try:
        if IS_WINDOWS:
            output = run_command(["powershell", "-Command", "ipconfig"], timeout=5)
            for line in output.splitlines():
                if "Default Gateway" in line or "默认网关" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        return match.group(1)
        elif IS_MACOS:
            output = run_command(["route", "-n", "get", "default"], timeout=5)
            match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
        else:
            output = run_command(["ip", "route", "show", "default"], timeout=5)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
    except Exception:
        pass

    try:
        local_ip = get_local_ip()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except Exception:
        return "192.168.1.1"


def get_local_ip() -> str:
    """获取本机 IPv4 地址。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_prefix() -> str:
    """按当前 IPv4 推断 /24 网段前缀。"""
    local_ip = get_local_ip()
    parts = local_ip.split(".")
    if len(parts) != 4:
        return "192.168.1"
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def normalize_mac(mac: str) -> str:
    """将 MAC 标准化为 AA:BB:CC:DD:EE:FF。"""
    cleaned = mac.strip().replace("-", ":").upper()
    parts = [part.zfill(2) for part in cleaned.split(":") if part]
    if len(parts) == 6:
        return ":".join(parts)
    return cleaned


def classify_device(ip: str, mac: str, hostname: Optional[str]) -> Device:
    """统一设备识别逻辑。"""
    normalized_mac = normalize_mac(mac) if mac else "UNKNOWN"
    hostname_value = hostname or None
    name = None
    is_quant = False
    check_str = " ".join(filter(None, [hostname_value, normalized_mac])).lower()

    if "quant" in check_str:
        name = hostname_value or "QuantClaw Device"
        is_quant = True
    elif any(normalized_mac.startswith(prefix) for prefix in PI_PREFIXES):
        name = "Raspberry Pi (possible quant)"
        is_quant = True

    return Device(
        ip=ip,
        mac=normalized_mac,
        hostname=hostname_value,
        name=name,
        is_quant=is_quant,
    )


def parse_arp_table() -> Dict[str, str]:
    """读取系统 ARP 表，返回 IP -> MAC。"""
    arp_map: Dict[str, str] = {}

    if IS_WINDOWS:
        output = run_command(["powershell", "-Command", "arp -a"], timeout=5)
        pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})\s+(\S+)",
            re.IGNORECASE,
        )
        for line in output.splitlines():
            match = pattern.search(line.strip())
            if not match:
                continue
            ip, mac_raw, entry_type = match.groups()
            mac = normalize_mac(mac_raw)
            if entry_type.lower() not in ("dynamic", "动态"):
                continue
            if mac == "FF:FF:FF:FF:FF:FF":
                continue
            arp_map[ip] = mac
        return arp_map

    output = run_command(["arp", "-an"], timeout=5)
    pattern = re.compile(
        r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:.-]+|\(incomplete\))",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.search(line.strip())
        if not match:
            continue
        ip, mac_raw = match.groups()
        if mac_raw.lower() == "(incomplete)":
            continue
        mac = normalize_mac(mac_raw)
        if mac == "FF:FF:FF:FF:FF:FF":
            continue
        arp_map[ip] = mac

    return arp_map


def ping_host(ip: str) -> None:
    """触发邻居表更新，不关心返回值。"""
    try:
        if IS_WINDOWS:
            subprocess.run(
                ["ping", "-n", "1", "-w", "250", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
        else:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1000", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
    except Exception:
        pass


def warm_up_neighbors(network_prefix: str) -> None:
    """轻量触发局域网邻居发现。"""
    targets = [f"{network_prefix}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(ping_host, ip) for ip in targets]
        for future in as_completed(futures):
            future.result()


def scan_with_nmap() -> Tuple[List[str], Dict[str, str]]:
    """用 nmap 扫描在线 IP，并尽量提取 nmap 已知的主机名。"""
    if not run_command(["which", "nmap"], timeout=2).strip():
        return [], {}

    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return [], {}

    network = f"{get_network_prefix()}.0/24"
    output = run_command(["nmap", "-sn", "-PR", network], timeout=45)

    live_hosts: List[str] = []
    hostnames: Dict[str, str] = {}
    seen: Set[str] = set()
    for line in output.splitlines():
        if "Nmap scan report" not in line:
            continue
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not match:
            continue
        ip = match.group(1)
        if ip in seen:
            continue
        seen.add(ip)
        host_match = re.search(r"Nmap scan report for (.+) \((\d+\.\d+\.\d+\.\d+)\)", line)
        if host_match:
            hostname = host_match.group(1).strip()
            if hostname and hostname != ip:
                hostnames[ip] = hostname
        live_hosts.append(ip)

    return live_hosts, hostnames


def scan_with_arp() -> List[str]:
    """通过 ping 预热 + ARP 表发现在线 IP。"""
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return []

    warm_up_neighbors(get_network_prefix())
    arp_map = parse_arp_table()
    live_hosts = sorted(arp_map.keys(), key=lambda value: tuple(int(part) for part in value.split(".")))
    return live_hosts


def build_devices(ips: List[str], hostnames: Optional[Dict[str, str]] = None) -> List[Device]:
    """根据 IP 列表补全 MAC/主机名并构建设备对象。"""
    arp_map = parse_arp_table()
    devices: List[Device] = []
    seen: Set[str] = set()
    hostnames = hostnames or {}

    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        hostname = hostnames.get(ip)
        mac = arp_map.get(ip, "")
        devices.append(classify_device(ip=ip, mac=mac, hostname=hostname))

    devices.sort(key=lambda item: tuple(int(part) for part in item.ip.split(".")))
    return devices


def discover_devices() -> List[Device]:
    """优先用 nmap 扫描，再回退到 ARP 发现。"""
    live_hosts, hostnames = scan_with_nmap()
    if not live_hosts:
        live_hosts = scan_with_arp()
        hostnames = {}

    if not live_hosts:
        return []

    return build_devices(live_hosts, hostnames)


def get_quant_device(devices: List[Device]) -> Optional[Device]:
    """找出 Quant 设备。"""
    for device in devices:
        if device.is_quant:
            return device
    return None


def probe_quant_http(ip: str, ports: Tuple[int, ...] = (80, 7681, 8080)) -> Optional[int]:
    """探测 IP 的 HTTP 端口，返回第一个可达端口号，否则 None。"""
    for port in ports:
        if check_http(ip, port, timeout=1.5):
            return port
    return None


def is_quantclaw_response(ip: str, port: int) -> bool:
    """验证 HTTP 响应是否来自 QuantClaw 设备。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        sock.sendall(f"GET /api/info HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
        resp = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    break
            except socket.timeout:
                break
        sock.close()
        return b"QuantClaw" in resp
    except Exception:
        return False


def quick_find_quant() -> QuantFoundResult:
    """快速发现局域网中的 QuantClaw 设备：ARP 扫描 + HTTP 端口确认。"""
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return QuantFoundResult(found=False, message="未连接到网络")

    network_prefix = get_network_prefix()
    warm_up_neighbors(network_prefix)

    arp_map = parse_arp_table()
    results: List[Device] = []
    checked: Set[str] = set()

    for ip, mac in arp_map.items():
        device = classify_device(ip=ip, mac=mac, hostname=None)
        if not device.is_quant:
            continue
        checked.add(ip)
        web_port = probe_quant_http(ip)
        if web_port and is_quantclaw_response(ip, web_port):
            device.web_port = web_port
            device.web_url = f"http://{ip}" if web_port == 80 else f"http://{ip}:{web_port}"
        else:
            device.web_port = None
            device.is_quant = False
            continue
        results.append(device)

    for ip in arp_map:
        if ip in checked:
            continue
        web_port = probe_quant_http(ip, ports=(80, 7681, 8080))
        if not web_port or not is_quantclaw_response(ip, web_port):
            continue
        try:
            mac = arp_map.get(ip, "UNKNOWN")
            hostname = socket.getfqdn(ip) if ip != local_ip else None
            if hostname == ip:
                hostname = None
            device = Device(ip=ip, mac=normalize_mac(mac), hostname=hostname, is_quant=True, web_port=web_port, web_url=f"http://{ip}" if web_port == 80 else f"http://{ip}:{web_port}", name="QuantClaw Device")
            results.append(device)
        except Exception:
            pass

    if results:
        q_names = ", ".join(d.ip for d in results)
        return QuantFoundResult(found=True, devices=results, message=f"发现 {len(results)} 台 QuantClaw: {q_names}")

    return QuantFoundResult(found=False, message="当前局域网未发现 QuantClaw 设备")


def get_network_interfaces() -> Dict[str, Dict[str, str]]:
    """获取所有网络接口及 IP 地址。"""
    interfaces: Dict[str, Dict[str, str]] = {}
    if IS_MACOS:
        output = run_command(["ifconfig"], timeout=5)
        current_iface = ""
        for line in output.splitlines():
            iface_match = re.match(r"^(\S+):\s+flags=", line)
            if iface_match:
                current_iface = iface_match.group(1).rstrip(":")
                interfaces[current_iface] = {"name": current_iface}
            if current_iface and "inet " in line:
                ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    interfaces[current_iface]["ip"] = ip_match.group(1)
            if current_iface and "ether " in line:
                mac_match = re.search(r"ether\s+([0-9a-fA-F:]+)", line)
                if mac_match:
                    interfaces[current_iface]["mac"] = mac_match.group(1)
    elif IS_WINDOWS:
        output = run_command(["powershell", "-Command", "ipconfig"], timeout=5)
        current_iface = ""
        for line in output.splitlines():
            if line and not line.startswith(" ") and ":" in line:
                current_iface = line.strip().rstrip(":")
            if current_iface and "IPv4" in line:
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    interfaces[current_iface] = {"name": current_iface, "ip": ip_match.group(1)}
    else:
        output = run_command(["ip", "-4", "addr", "show"], timeout=5)
        current_iface = ""
        for line in output.splitlines():
            iface_match = re.match(r"^\d+:\s+(\S+):", line)
            if iface_match:
                current_iface = iface_match.group(1)
                interfaces[current_iface] = {"name": current_iface}
            if current_iface and "inet " in line:
                ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    interfaces[current_iface]["ip"] = ip_match.group(1)
    return interfaces


GADGET_MAC_PREFIXES = ("9a:9b:9c:9d:9e", "9A:9B:9C:9D:9E")


def get_usb_gadget_interfaces() -> List[USBInterfaceInfo]:
    """通过 MAC 地址前缀识别 USB Gadget 虚拟网卡接口。"""
    interfaces = get_network_interfaces()
    results: List[USBInterfaceInfo] = []

    for iface_name, info in interfaces.items():
        if iface_name == "lo":
            continue
        mac = info.get("mac", "")
        if not mac:
            continue
        if any(mac.startswith(prefix) for prefix in GADGET_MAC_PREFIXES):
            ip_val = info.get("ip")
            results.append(USBInterfaceInfo(
                name=iface_name,
                mac=mac,
                ip=ip_val,
                has_ip=bool(ip_val),
            ))

    return results


def assign_static_ip_to_usb(iface_name: str, ip_octet: int = 10) -> Tuple[bool, str]:
    """为 USB 接口分配静态 9.9.9.x 地址。"""
    static_ip = f"{GADGET_SUBNET}.{ip_octet}"

    if IS_MACOS:
        command = ["ifconfig", iface_name, "inet", static_ip, "netmask", "255.255.255.0", "up"]
    elif IS_WINDOWS:
        command = ["netsh", "interface", "ip", "set", "address", iface_name, "static", static_ip, "255.255.255.0"]
    else:
        command = ["ip", "addr", "replace", f"{static_ip}/24", "dev", iface_name]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, f"已分配静态 IP {static_ip} 到接口 {iface_name}"
        return False, f"分配静态 IP 失败: {result.stderr.strip()}"
    except Exception as exc:
        return False, f"分配静态 IP 异常: {exc}"


def enable_internet_sharing(usb_iface: str, enable: bool = True) -> USBShareResult:
    """为 USB 接口启用/禁用互联网共享 (NAT)。"""
    if not enable:
        return USBShareResult(success=False, message="禁用网络共享功能暂未实现，请手动关闭")

    wan_iface = get_wan_interface()
    if not wan_iface:
        return USBShareResult(success=False, message="未检测到有效的上行网络接口")

    if IS_MACOS:
        try:
            subprocess.run(
                ["sysctl", "-w", "net.inet.ip.forwarding=1"],
                capture_output=True, text=True, timeout=5,
            )
            nat_rules = (
                f"nat on {wan_iface} from 9.9.9.0/24 to any -> ({wan_iface})\n"
                f"pass in on {usb_iface} all\n"
                f"pass out on {usb_iface} all\n"
            )
            conf_path = "/tmp/quantclaw_nat.conf"
            with open(conf_path, "w") as fh:
                fh.write(nat_rules)
            subprocess.run(
                ["pfctl", "-e"], capture_output=True, text=True, timeout=5,
            )
            subprocess.run(
                ["pfctl", "-f", conf_path], capture_output=True, text=True, timeout=5,
            )
            return USBShareResult(
                success=True,
                message=f"已启用网络共享: {usb_iface} → {wan_iface}",
                wan_interface=wan_iface,
                usb_interface=usb_iface,
            )
        except Exception as exc:
            return USBShareResult(success=False, message=f"macOS NAT 配置失败: {exc}")
    else:
        try:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                capture_output=True, text=True, timeout=5,
            )
            subprocess.run(
                ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", wan_iface, "-j", "MASQUERADE"],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan_iface, "-j", "MASQUERADE"],
                capture_output=True, text=True, timeout=5,
            )
        try:
            subprocess.run(
                ["iptables", "-C", "FORWARD", "-i", usb_iface, "-o", wan_iface, "-j", "ACCEPT"],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", usb_iface, "-o", wan_iface, "-j", "ACCEPT"],
                capture_output=True, text=True, timeout=5,
            )
        return USBShareResult(
            success=True,
            message=f"已启用网络共享: {usb_iface} → {wan_iface}",
            wan_interface=wan_iface,
            usb_interface=usb_iface,
        )


def get_wan_interface() -> Optional[str]:
    """获取默认路由对应的上行接口名。"""
    try:
        if IS_MACOS:
            output = run_command(["route", "-n", "get", "default"], timeout=5)
            match = re.search(r"interface:\s*(\S+)", output)
            if match:
                return match.group(1)
        elif IS_WINDOWS:
            output = run_command(["powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).InterfaceAlias"], timeout=5)
            iface = output.strip()
            if iface:
                return iface
        else:
            output = run_command(["ip", "route", "show", "default"], timeout=5)
            match = re.search(r"dev\s+(\S+)", output)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def is_usb_gadget_interface(iface_name: str) -> bool:
    """判断网络接口是否为 USB Gadget 虚拟网卡。"""
    if re.match(r"^usb\d+$", iface_name, re.IGNORECASE):
        return True
    if IS_MACOS:
        return False
    if re.match(r"^en\d+$", iface_name):
        return True
    return False


def probe_mdns(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """通过 mDNS 解析主机名获取 IP。"""
    try:
        result = socket.getaddrinfo(hostname, 80, socket.AF_INET, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in result:
            return sockaddr[0]
    except (socket.gaierror, OSError):
        pass

    timeout_seconds = max(1, int(timeout))
    if IS_MACOS:
        output = run_command(["dscacheutil", "-q", "host", "-a", "name", hostname], timeout=timeout_seconds)
        ip_match = re.search(r"ip_address:\s*(\d+\.\d+\.\d+\.\d+)", output)
        if ip_match:
            return ip_match.group(1)
    elif not IS_WINDOWS:
        output = run_command(["getent", "ahostsv4", hostname], timeout=timeout_seconds)
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", output)
        if ip_match:
            return ip_match.group(1)

    return None


def check_http(ip: str, port: int = 80, timeout: float = 2.0) -> bool:
    """检查 HTTP 服务是否可达。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def fetch_http_content(host: str, path: str = "/", port: int = 80, timeout: float = 2.0) -> Optional[Tuple[int, str]]:
    """读取 HTTP 响应状态码和正文片段。"""
    request = Request(build_http_url(host, port) + path, headers={"User-Agent": "QuantClawScanner/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read(2048).decode("utf-8", errors="ignore")
    except HTTPError as exc:
        try:
            body = exc.read(2048).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return exc.code, body
    except (URLError, OSError, ValueError):
        return None


def probe_web_service(host: str, port: int = 80, timeout: float = 2.0) -> bool:
    """确认目标主机上存在可访问的 Web 服务。"""
    for path in ("/api/info", "/"):
        response = fetch_http_content(host, path=path, port=port, timeout=timeout)
        if not response:
            continue
        status_code, body = response
        if 200 <= status_code < 400:
            if path == "/":
                return True
            body_lower = body.lower()
            if not body or "quant" in body_lower or "hostname" in body_lower or "local_ip" in body_lower:
                return True
    return False


def post_json(url: str, payload: dict, timeout: float = 8.0) -> Optional[Tuple[int, dict]]:
    """向目标 URL 发送 JSON POST 请求。"""
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "User-Agent": "QuantClawScanner/1.0",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="ignore")
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="ignore")
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {"message": str(exc)}
        return exc.code, body
    except (URLError, OSError, ValueError):
        return None


def get_usb_candidate_urls(device: USBDevice) -> List[str]:
    """为 USB 设备生成候选访问地址，优先 mDNS。"""
    candidates: List[str] = []

    for url in [device.url]:
        if url and url not in candidates:
            candidates.append(url)

    if device.hostname:
        hostname_url = build_http_url(device.hostname, GADGET_PORT)
        if hostname_url not in candidates:
            candidates.append(hostname_url)

    if device.mdns_ip:
        mdns_url = build_http_url(device.mdns_ip, GADGET_PORT)
        if mdns_url not in candidates:
            candidates.append(mdns_url)

    direct_url = build_http_url(device.ip, GADGET_PORT)
    if direct_url not in candidates:
        candidates.append(direct_url)

    return candidates


def get_usb_provision_candidate_urls(device: USBDevice) -> List[str]:
    """为 USB 配网接口生成候选基础地址。"""
    candidates = get_usb_candidate_urls(device)

    extras = []
    if device.hostname:
        extras.append(build_http_url(device.hostname, USB_PROVISION_PORT))
    if device.mdns_ip:
        extras.append(build_http_url(device.mdns_ip, USB_PROVISION_PORT))
    extras.append(build_http_url(device.ip, USB_PROVISION_PORT))

    for url in extras:
        if url not in candidates:
            candidates.append(url)

    return candidates


def get_usb_devices() -> List[USBDevice]:
    """获取 USB 设备列表，支持开发态模拟设备。"""
    if SIMULATE_USB:
        return [
            USBDevice(
                interface="usb-sim0",
                local_ip="9.9.9.10",
                ip=GADGET_HOST,
                gateway=GADGET_HOST,
                reachable=True,
                web_accessible=True,
                hostname=SIMULATED_DEVICE_HOSTNAME,
                mdns_ip="127.0.0.1",
                url=SIMULATED_DEVICE_URL,
                mac_address="9a:9b:9c:9d:9e:01",
            )
        ]
    return detect_usb_gadget_devices()


def provision_usb_device(request: USBProvisionRequest) -> USBProvisionResult:
    """通过 USB 直连向设备提交 Wi-Fi 配网请求。"""
    ssid = request.ssid.strip()
    if not ssid:
        return USBProvisionResult(success=False, message="SSID 不能为空")

    usb_devices = get_usb_devices()
    if not usb_devices:
        return USBProvisionResult(success=False, message="未检测到 USB 直连设备")

    payload = {
        "ssid": ssid,
        "password": request.password,
        "security": request.security,
        "hidden": request.hidden,
        "country": request.country,
    }

    attempted_urls: List[str] = []
    for device in usb_devices:
        for base_url in get_usb_provision_candidate_urls(device):
            for endpoint in USB_PROVISION_ENDPOINTS:
                target_url = join_url(base_url, endpoint)
                attempted_urls.append(target_url)
                response = post_json(target_url, payload, timeout=10.0)
                if not response:
                    continue

                status_code, body = response
                if 200 <= status_code < 300:
                    message = body.get("message") or "Wi-Fi 配网请求已发送到设备"
                    return USBProvisionResult(
                        success=True,
                        message=message,
                        target_url=target_url,
                        device_url=base_url,
                        detail=body,
                    )

    attempted = "；".join(attempted_urls[:4])
    return USBProvisionResult(
        success=False,
        message="设备已连接，但未找到可用的配网接口",
        detail={"attempted": attempted_urls, "preview": attempted},
    )


def _make_usb_device(iface_name: str, local_ip: str, mac: str = "") -> USBDevice:
    """从接口信息构建 USBDevice 对象。"""
    if local_ip and local_ip.startswith(f"{GADGET_SUBNET}."):
        try:
            parts = local_ip.split(".")
            gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except Exception:
            gateway = GADGET_HOST
    else:
        gateway = GADGET_HOST

    reachable = check_http(GADGET_HOST)
    web_accessible = False
    hostname = None
    mdns_ip = None
    url = None

    if reachable:
        web_accessible = probe_web_service(GADGET_HOST, GADGET_PORT, timeout=2.0)
        if web_accessible:
            url = build_http_url(GADGET_HOST, GADGET_PORT)

    mdns_ip = probe_mdns(GADGET_MDNS)
    if mdns_ip:
        hostname = GADGET_MDNS
        if not reachable:
            reachable = check_http(mdns_ip, GADGET_PORT, timeout=2.0)
        if probe_web_service(mdns_ip, GADGET_PORT, timeout=2.0):
            web_accessible = True
            url = build_http_url(GADGET_MDNS, GADGET_PORT)
        elif not url:
            url = build_http_url(mdns_ip, GADGET_PORT)

    return USBDevice(
        interface=iface_name,
        local_ip=local_ip or "0.0.0.0",
        ip=GADGET_HOST,
        gateway=gateway,
        reachable=reachable,
        web_accessible=web_accessible,
        hostname=hostname,
        mdns_ip=mdns_ip,
        url=url,
        mac_address=mac or None,
    )


def _detect_usb_via_mac() -> List[USBDevice]:
    """通过 MAC 地址前缀 9a:9b:9c:9d:9e 识别 USB Gadget 接口。"""
    devices: List[USBDevice] = []
    seen_ips: Set[str] = set()

    for ginfo in get_usb_gadget_interfaces():
        local_ip = ginfo.ip or ""
        if local_ip and local_ip in seen_ips:
            continue
        if local_ip:
            seen_ips.add(local_ip)
        devices.append(_make_usb_device(ginfo.name, local_ip, ginfo.mac))

    return devices


def _detect_usb_via_ip() -> List[USBDevice]:
    """回退方案: 通过 IP 前缀 9.9.9. 识别 USB Gadget 接口。"""
    devices: List[USBDevice] = []
    seen_ips: Set[str] = set()
    interfaces = get_network_interfaces()

    for iface_name, info in interfaces.items():
        local_ip = info.get("ip", "")
        if not local_ip or iface_name == "lo":
            continue
        if not local_ip.startswith(f"{GADGET_SUBNET}."):
            continue
        if local_ip in seen_ips:
            continue
        seen_ips.add(local_ip)
        mac = info.get("mac", "")
        devices.append(_make_usb_device(iface_name, local_ip, mac))

    return devices


def _detect_usb_via_hardware_port() -> List[USBDevice]:
    """最终回退: 通过 networksetup 找出 USB 以太网接口 (macOS only)。

    macOS 不保留 gadget host_addr 且 DHCP 未分配 IP 时的兜底方案。
    找到所有硬件端口名含 'USB' 的接口，若尚未被前面方案识别则加入。
    """
    devices: List[USBDevice] = []
    if not IS_MACOS:
        return devices

    known_names: Set[str] = set()
    for dev in _detect_usb_via_mac():
        known_names.add(dev.interface)
    for dev in _detect_usb_via_ip():
        known_names.add(dev.interface)

    output = run_command(["networksetup", "-listallhardwareports"], timeout=5)
    current_port = ""
    current_device = ""
    for line in output.splitlines():
        port_match = re.match(r"^Hardware Port:\s*(.+)", line)
        if port_match:
            current_port = port_match.group(1).strip()
            continue
        dev_match = re.match(r"^Device:\s*(\S+)", line)
        if dev_match:
            current_device = dev_match.group(1)
            if current_port and current_device and "USB" in current_port.upper():
                if current_device not in known_names:
                    known_names.add(current_device)
                    interfaces = get_network_interfaces()
                    info = interfaces.get(current_device, {})
                    local_ip = info.get("ip", "")
                    mac = info.get("mac", "")
                    devices.append(_make_usb_device(current_device, local_ip, mac))

    return devices


def _detect_usb_via_raw_probe() -> List[USBDevice]:
    """绝杀回退: 直接探测 9.9.9.1 和 quantclaw.local。

    如果前面所有方案都找不到接口，但设备实际在线上，此方法兜底。
    """
    reachable = check_http(GADGET_HOST, GADGET_PORT, timeout=2.0)
    mdns_ip = probe_mdns(GADGET_MDNS, timeout=3.0)

    if not reachable and not mdns_ip:
        return []

    interface_name = "usb-raw"
    local_ip = GADGET_SUBNET + ".10"
    mac = ""

    if mdns_ip:
        mac = ""
        if check_http(mdns_ip, GADGET_PORT, timeout=2.0):
            reachable = True
    if reachable and probe_web_service(GADGET_HOST, GADGET_PORT, timeout=2.0):
        return [_make_usb_device(interface_name, local_ip, mac)]

    usb_dev = _make_usb_device(interface_name, local_ip, mac)
    usb_dev.reachable = reachable
    if mdns_ip:
        usb_dev.hostname = GADGET_MDNS
        usb_dev.mdns_ip = mdns_ip
        if reachable:
            usb_dev.web_accessible = probe_web_service(mdns_ip, GADGET_PORT, timeout=2.0)
    if usb_dev.web_accessible:
        usb_dev.url = build_http_url(GADGET_MDNS, GADGET_PORT) if mdns_ip else build_http_url(GADGET_HOST, GADGET_PORT)

    return [usb_dev]


def detect_usb_gadget_devices() -> List[USBDevice]:
    """检测通过 USB Gadget 连接的 QuantClaw 设备。

    四检测策略 (依次回退):
    1. MAC 前缀 9a:9b:9c:9d:9e 匹配 (macOS 保留 host_addr 时生效)
    2. IP 前缀 9.9.9. 匹配 (DHCP 已分配 IP 时生效)
    3. networksetup 硬件端口匹配 (macOS 仅, USB 端口兜底)
    4. 直接探测 9.9.9.1 / quantclaw.local (终极兜底)
    """
    for detector in (_detect_usb_via_mac, _detect_usb_via_ip, _detect_usb_via_hardware_port, _detect_usb_via_raw_probe):
        devices = detector()
        if devices:
            return devices

    return []


def determine_connection_level(usb_devices: List[USBDevice]) -> str:
    """根据 USB 设备列表确定连接级别。"""
    if not usb_devices:
        return ConnectionLevel.NONE.value

    has_ip = any(d.local_ip not in ("", "0.0.0.0") and not d.local_ip.startswith("127.") for d in usb_devices)
    has_reachable = any(d.reachable for d in usb_devices)
    has_ready = any(d.web_accessible for d in usb_devices)

    if has_ready:
        return ConnectionLevel.READY.value
    if has_reachable:
        return ConnectionLevel.REACHABLE.value
    if has_ip:
        return ConnectionLevel.IP.value
    return ConnectionLevel.INTERFACE.value


def get_troubleshooting_hints(level: str) -> List[str]:
    """根据连接级别生成排查建议。"""
    hints: List[str] = []

    if level == ConnectionLevel.NONE.value:
        hints = [
            "请确认 USB 数据线支持数据传输（非仅充电线）",
            "请确认 RPi 已运行: sudo bash deploy/usb-gadget-setup.sh",
            "请确认 RPi 使用支持 OTG/Peripheral 的 USB 口",
            "在 RPi 上运行自检: sudo bash deploy/usb-gadget-check.sh",
        ]
    elif level == ConnectionLevel.INTERFACE.value:
        hints = [
            "USB 网卡已识别，正在等待 IP 分配...",
            "如持续无 IP，可点击「分配静态 IP」按钮手动配置",
            "请确认 RPi 端 dnsmasq DHCP 服务正常运行",
        ]
    elif level == ConnectionLevel.IP.value:
        hints = [
            "已获取 IP 地址，但无法访问 9.9.9.1",
            "请确认 RPi 端 usb0 接口已配置 9.9.9.1",
            "在 RPi 上运行自检: sudo bash deploy/usb-gadget-check.sh",
        ]
    elif level == ConnectionLevel.REACHABLE.value:
        hints = [
            "9.9.9.1 网络可达，等待 QuantClaw Web 服务上线...",
            "请确认 RPi 端 QuantClaw Web 服务已启动",
            "可尝试通过 USB 配网表单直接提交 Wi-Fi 信息",
        ]
    elif level == ConnectionLevel.READY.value:
        hints = [
            "设备完全就绪，可点击「连接设备」进入 QuantClaw 页面",
        ]

    return hints


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    """返回前端页面。"""
    with open("templates/index.html", "r", encoding="utf-8") as file:
        return file.read()


@app.get("/api/scan", response_model=ScanResult)
async def scan_network() -> ScanResult:
    """扫描网络设备。"""
    devices = discover_devices()
    return ScanResult(
        devices=devices,
        quant_device=get_quant_device(devices),
        total=len(devices),
        gateway=get_gateway(),
    )


@app.get("/api/info")
async def get_info() -> dict:
    """获取本机信息。"""
    return {
        "local_ip": get_local_ip(),
        "gateway": get_gateway(),
        "hostname": socket.gethostname(),
    }


@app.get("/api/usb-detect", response_model=USBScanResult)
async def detect_usb() -> USBScanResult:
    """检测通过 USB Gadget 连接的 QuantClaw 设备。"""
    usb_devices = get_usb_devices()
    connected = len(usb_devices) > 0
    ready = any(device.web_accessible for device in usb_devices)
    level = determine_connection_level(usb_devices)
    hints = get_troubleshooting_hints(level)

    if ready:
        message = "USB 直连已就绪，可直接打开 QuantClaw 设备页面"
    elif level == ConnectionLevel.REACHABLE.value:
        message = "USB 网络已连通，等待 QuantClaw Web 服务上线"
    elif level == ConnectionLevel.IP.value:
        message = "已获取 IP 地址，但无法访问设备，请检查 RPi 端配置"
    elif level == ConnectionLevel.INTERFACE.value:
        message = "已检测到 USB 网卡，正在等待 IP 分配..."
    else:
        message = "未检测到 USB 直连设备，请确认 USB 已连接且 RPi 已配置 USB Gadget"

    return USBScanResult(
        usb_devices=usb_devices,
        connected=connected,
        ready=ready,
        message=message,
        level=level,
        troubleshooting_hints=hints,
    )


@app.post("/api/usb-provision", response_model=USBProvisionResult)
async def usb_provision(request: USBProvisionRequest) -> USBProvisionResult:
    """通过 USB 直连向 QuantClaw 提交 Wi-Fi 配置。"""
    return provision_usb_device(request)


@app.post("/api/usb-static-ip")
async def usb_static_ip() -> dict:
    """手动触发静态 IP 分配。"""
    gadget_ifaces = get_usb_gadget_interfaces()
    if not gadget_ifaces:
        return {"success": False, "message": "未检测到 USB Gadget 网卡接口"}

    for ginfo in gadget_ifaces:
        if not ginfo.has_ip:
            success, msg = assign_static_ip_to_usb(ginfo.name)
            return {"success": success, "message": msg, "interface": ginfo.name}

    return {"success": True, "message": "所有 USB Gadget 接口已拥有 IP 地址"}


@app.post("/api/usb-share", response_model=USBShareResult)
async def usb_share(request: USBShareRequest) -> USBShareResult:
    """启用/禁用 USB 网络共享。"""
    usb_devices = get_usb_devices()
    if not usb_devices:
        return USBShareResult(success=False, message="未检测到 USB 直连设备")

    usb_iface = usb_devices[0].interface
    return enable_internet_sharing(usb_iface, enable=request.enable)


@app.get("/api/usb-diagnostics")
async def usb_diagnostics() -> dict:
    """诊断: 返回 macOS 侧网络接口和 USB 端口原始信息。"""
    ifconfig_output = run_command(["ifconfig"], timeout=5)
    networksetup_output = run_command(["networksetup", "-listallhardwareports"], timeout=5)
    arp_output = run_command(["arp", "-an"], timeout=5)

    interfaces = get_network_interfaces()

    all_usb_ports = []
    if IS_MACOS:
        current_port = ""
        current_device = ""
        for line in networksetup_output.splitlines():
            port_match = re.match(r"^Hardware Port:\s*(.+)", line)
            if port_match:
                current_port = port_match.group(1).strip()
                continue
            dev_match = re.match(r"^Device:\s*(\S+)", line)
            if dev_match:
                current_device = dev_match.group(1)
                if "USB" in current_port.upper():
                    info = interfaces.get(current_device, {})
                    all_usb_ports.append({
                        "port": current_port,
                        "device": current_device,
                        "ip": info.get("ip", ""),
                        "mac": info.get("mac", ""),
                    })

    def _filter_ifconfig(output: str) -> list:
        relevant = []
        current = ""
        for line in output.splitlines():
            iface_match = re.match(r"^(\S+):\s+flags=", line)
            if iface_match:
                current = iface_match.group(1)
                relevant.append(line)
            elif current and (line.startswith("\t") or line.startswith(" ")):
                relevant.append(line)
            else:
                current = ""
        return relevant

    filtered_ifconfig = _filter_ifconfig(ifconfig_output)

    return {
        "interfaces": {k: v for k, v in interfaces.items()},
        "usb_hardware_ports": all_usb_ports,
        "ifconfig_relevant": filtered_ifconfig[:60],
        "arp_table": [line.strip() for line in arp_output.splitlines() if line.strip()][:30],
    }


@app.get("/api/probe")
async def probe_device() -> dict:
    """快速探测量子设备 (mDNS + HTTP)。"""
    mdns_ip = probe_mdns(GADGET_MDNS, timeout=2.0)
    if mdns_ip and check_http(mdns_ip, GADGET_PORT, timeout=2.0):
        return {
            "found": True,
            "method": "mdns",
            "hostname": GADGET_MDNS,
            "ip": mdns_ip,
            "url": f"http://{GADGET_MDNS}",
        }
    if check_http(GADGET_HOST, GADGET_PORT, timeout=2.0):
        return {
            "found": True,
            "method": "direct",
            "hostname": GADGET_HOST,
            "ip": GADGET_HOST,
            "url": f"http://{GADGET_HOST}",
        }
    return {"found": False, "message": "未发现 QuantClaw 设备"}


@app.get("/api/auto-detect", response_model=QuantFoundResult)
async def auto_detect() -> QuantFoundResult:
    """自动发现 WiFi 局域网中的 QuantClaw 设备（ARP + HTTP 端口确认）。"""
    return quick_find_quant()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
