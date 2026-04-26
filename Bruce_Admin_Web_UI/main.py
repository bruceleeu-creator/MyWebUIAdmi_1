"""
QuantClaw 网络扫描服务 v2.0
优化版本：异步扫描 + 端口分组 + 清晰的代码结构
"""
import asyncio
import os
import re
import socket
import struct
import subprocess
import platform
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

IS_WINDOWS = platform.system().lower() in ('windows', 'windows_nt')
IS_MACOS = platform.system().lower() == 'darwin'

app = FastAPI(title="QuantClaw Network Scanner v2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

executor = ThreadPoolExecutor(max_workers=100)



class DeviceType(Enum):
    QUANT = "quant"
    RASPBERRY_PI = "raspberry_pi"
    ROUTER = "router"
    UNKNOWN = "unknown"


@dataclass
class Device:
    ip: str
    mac: str
    hostname: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    open_ports: list = field(default_factory=list)
    is_online: bool = True

    @property
    def is_quant(self) -> bool:
        return self.device_type == DeviceType.QUANT

    @property
    def name(self) -> Optional[str]:
        if self.hostname:
            return self.hostname
        if self.device_type == DeviceType.QUANT:
            return self.hostname or "QuantClaw Device"
        if self.device_type == DeviceType.RASPBERRY_PI:
            return self.hostname or "Raspberry Pi"
        if self.device_type == DeviceType.ROUTER:
            return "Router/Gateway"
        
        mac_upper = self.mac.upper().replace('-', ':')
        for vendor, prefixes in VENDOR_PREFIXES.items():
            if any(mac_upper.startswith(p) for p in prefixes):
                return f"{vendor} Device"
        
        if self.is_online:
            return f"Device ({self.ip})"
        return f"Offline Device ({self.ip})"

    @property
    def ssh_host(self) -> Optional[str]:
        if self.device_type == DeviceType.QUANT:
            last_octet = self.ip.rsplit('.', 1)[-1]
            return f"quant-{last_octet}"
        if self.device_type == DeviceType.RASPBERRY_PI:
            last_octet = self.ip.rsplit('.', 1)[-1]
            return f"rpi-{last_octet}"
        return None

    @property
    def ssh_config_entry(self) -> Optional[str]:
        host = self.ssh_host
        if not host:
            return None
        lines = [
            f"Host {host}",
            f"    HostName {self.ip}",
            f"    User pi",
            f"    Port 22",
            f"    StrictHostKeyChecking no",
            f"    UserKnownHostsFile /dev/null",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "name": self.name,
            "is_quant": self.is_quant,
            "device_type": self.device_type.value,
            "open_ports": self.open_ports,
            "ssh_host": self.ssh_host
        }


SCANNED_DEVICES: list = []


class ScanResult(BaseModel):
    devices: list
    quant_device: Optional[dict] = None
    total: int
    gateway: str
    scan_time_ms: float


QUANT_KEYWORDS = ['quant', 'quantclaw', 'quantum', 'ttyd', 'raspberry', 'raspberrypi', 'rpi', 'pi']
PI_MAC_PREFIXES = [
    "B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1", "2C:CF:67", "D8:3A:DD",
    "E8:4E:06",
]
QUANTCLAW_BODY_KEYWORDS = ['quantclaw', 'quant claw', 'ttyd', 'libwebsockets']
COMMON_PORTS = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 7681: 'QuantClaw'}

VENDOR_PREFIXES = {
    "Apple": ["AC:87", "A8:60", "3C:15", "00:1C:B3", "F0:18", "D0:25", "A4:5C", "FC:25", "F8:FF", "64:A3", "B8:09", "BC:92", "9C:35", "CC:08", "F8:1E", "00:F7", "9C:20", "A4:5E"],
    "Intel": ["00:1B", "00:1C", "00:1D", "00:1E", "00:1F", "00:20", "3C:97", "A4:4E", "DC:53", "00:02", "00:04", "00:0A", "00:0B", "00:11", "00:13", "00:15", "18:3D", "34:13", "3C:97", "18:D0", "00:1F", "00:20", "00:24", "00:26", "00:28", "00:29", "00:2A", "00:2B", "00:2C", "00:2D"],
    "Samsung": ["00:16:32", "00:17:C9", "00:1D", "B4:79", "94:35", "74:45", "8C:F5", "7C:0B", "7C:62", "88:C9", "9C:02", "A0:07", "A4:07", "B4:6D", "B8:D5", "BC:44", "C0:97", "CC:07", "D0:22", "E4:92", "E8:4E", "E8:03", "F0:25", "F4:09", "F8:77", "FC:19"],
    "Xiaomi": ["34:80", "64:09", "68:DF", "98:FA", "34:CE", "04:CF", "F0:B4", "00:9E", "28:6C", "38:A4", "4C:63", "58:44", "74:23", "78:02", "7C:1D", "84:F3", "9C:99", "A4:77", "B0:E2", "C4:0B", "C8:D7", "DC:D9", "EC:0D", "F4:F5", "FC:64"],
    "Huawei": ["00:18:82", "00:25", "34:00", "00:1E", "F8:01", "2C:AB", "20:F3", "00:46", "00:9A", "00:E0", "04:02", "04:25", "04:33", "04:BD", "04:C0", "04:FD", "04:FE", "08:19", "08:63", "08:7A", "0C:37", "0C:96", "10:1B", "10:44", "14:B9", "18:C5", "1C:1D", "24:09", "24:69", "28:31", "34:29", "34:6A", "38:37", "38:D1", "3C:47", "3C:DF", "40:4D", "40:CB", "44:55", "48:62", "4C:1F", "4C:8B", "50:A2", "50:D2", "54:39", "58:2A", "58:60", "5C:4C", "5C:7D", "60:DE", "64:16", "68:A4", "68:89", "6C:B7", "70:54", "70:72", "74:59", "7C:60", "80:71", "80:B6", "84:46", "88:3D", "8C:25", "90:17", "94:04", "98:01", "9C:37", "9C:A2", "A0:08", "A4:71", "A8:02", "A8:C8", "AC:4E", "AC:61", "B0:5B", "B0:7F", "B4:30", "B4:62", "B4:7C", "B4:CD", "BC:62", "BC:76", "C4:05", "C4:06", "C8:0A", "CC:53", "D0:2D", "D0:65", "D4:61", "D4:6A", "D8:49", "DC:20", "E0:19", "E0:24", "E0:5F", "E4:35", "E4:68", "E8:08", "E8:CD", "EC:23", "EC:38", "F0:43", "F4:55", "F4:8B", "F4:C9", "F8:34", "F8:4A", "F8:7B", "F8:E8", "FC:48", "FC:64", "FC:73"],
    "TP-Link": ["14:CC", "14:CF", "1C:3B", "30:B5", "50:C7", "54:C8", "B0:BE", "64:66", "00:27", "00:4F", "00:5F", "04:27", "04:A0", "04:E5", "04:F9", "06:9F", "08:60", "08:95", "0C:89", "0C:A6", "10:47", "10:FE", "14:E6", "14:F6", "18:A6", "18:D6", "1C:5A", "1C:6F", "20:DC", "28:EE", "28:F0", "2C:56", "30:D9", "30:F3", "34:E8", "38:83", "3C:84", "40:16", "44:33", "48:8A", "4C:5E", "50:3E", "50:5E", "58:EF", "5C:63", "5C:89", "60:E3", "60:FE", "64:70", "64:B9", "68:FF", "6C:B3", "70:4F", "70:7B", "74:DA", "78:A1", "78:44", "7C:B5", "7C:D2", "80:89", "80:AD", "84:16", "88:C3", "88:E3", "8C:21", "90:F6", "94:D9", "98:DA", "98:DE", "9C:21", "9C:8E", "A0:F3", "A4:2B", "A4:E9", "A8:57", "AC:84", "B0:4A", "B0:95", "B4:B0", "B4:E9", "B4:F3", "BC:46", "C0:25", "C0:4A", "C0:4E", "C4:6E", "C8:3A", "C8:5B", "CC:32", "D0:5F", "D0:79", "D4:6E", "D8:07", "D8:47", "DC:FE", "E0:05", "E0:24", "E4:D3", "E8:94", "EC:08", "EC:17", "F0:F3", "F4:EC", "F4:F2", "F8:1A", "F8:D1", "FC:34", "FC:E8"],
    "Dell": ["00:06", "00:0D", "00:12", "00:14", "00:18", "00:1A", "14:FE", "18:A9", "00:01", "00:04", "00:11", "00:13", "00:15", "00:16", "00:19", "00:1B", "00:1C", "00:1D", "00:1E", "00:1F", "00:21", "00:22", "00:23", "00:24", "00:25", "08:00", "14:18", "14:77", "14:B4", "18:03", "18:66", "1C:40", "1C:4D", "24:6E", "24:B6", "28:F0", "34:17", "34:E6", "34:FC", "38:2C", "44:A8", "48:4D", "4C:76", "4C:9E", "50:9A", "54:9F", "5C:26", "5C:F9", "64:00", "68:05", "6C:3E", "70:10", "74:86", "74:E6", "78:2B", "78:45", "78:AC", "7C:51", "80:18", "80:CE", "84:7B", "84:8F", "84:AE", "88:88", "8C:EC", "90:B1", "90:F1", "94:00", "98:90", "98:9E", "98:DE", "9C:8E", "A4:1F", "A4:BA", "A4:C0", "B0:83", "B4:99", "B4:B5", "B4:E9", "B8:2A", "B8:6A", "B8:AC", "BC:30", "BC:76", "C0:1A", "C0:25", "C0:4A", "C0:B6", "C8:1F", "C8:BC", "C8:F7", "CC:2F", "D0:67", "D4:81", "D4:BE", "D4:90", "D8:9E", "D8:FE", "E0:DB", "E4:43", "E4:A4", "E8:2A", "E8:B2", "EC:0D", "EC:F4", "F0:1F", "F0:22", "F0:2F", "F4:8E", "F4:9F", "F8:BC", "F8:B1", "F8:CA", "F8:DB", "FC:F1", "FC:34"],
    "HP": ["00:0E", "00:0F", "00:11", "00:14", "00:17", "00:1B", "38:63", "2C:44", "00:01", "00:02", "00:0E", "00:0F", "00:10", "00:11", "00:12", "00:13", "00:14", "00:15", "00:16", "00:17", "00:18", "00:19", "00:1A", "00:1B", "00:1C", "00:1D", "00:1E", "00:1F", "00:20", "00:21", "00:22", "00:23", "00:24", "00:25", "00:26", "00:27", "00:28", "00:29", "00:30", "00:50", "00:80", "00:A0", "00:C0", "00:D0", "08:00", "10:1F", "10:60", "10:7B", "10:E7", "10:F0", "10:FB", "14:02", "14:57", "14:63", "14:9F", "14:C2", "14:DD", "18:A9", "1C:39", "1C:98", "1C:C1", "20:67", "24:BE", "28:80", "28:92", "28:96", "28:C0", "28:E0", "2C:27", "2C:41", "2C:44", "2C:59", "2C:76", "2C:9D", "30:8D", "30:E1", "34:64", "34:A2", "38:63", "3C:4A", "3C:52", "3C:D9", "40:16", "40:A9", "40:B0", "44:1E", "44:31", "44:5A", "44:EA", "48:0F", "48:43", "48:7A", "4C:39", "4C:80", "4C:E9", "50:65", "50:9A", "50:A6", "50:C5", "50:E5", "50:F0", "54:9F", "58:20", "58:A8", "5C:B9", "5C:E9", "60:45", "60:9F", "64:51", "68:B5", "68:D9", "6C:3B", "6C:C2", "70:10", "70:5A", "70:85", "70:B5", "70:C2", "70:DE", "74:03", "74:46", "74:7D", "74:E5", "78:AC", "78:DD", "78:E3", "78:E7", "7C:D3", "80:1F", "80:A1", "80:C1", "80:CE", "84:34", "84:88", "84:8F", "84:9F", "88:51", "88:88", "88:8E", "88:91", "8C:DC", "90:4C", "90:B1", "90:E6", "90:F2", "94:57", "94:9F", "94:A9", "94:B2", "98:4B", "98:90", "98:E7", "9C:8E", "9C:B6", "A0:1D", "A0:2B", "A0:48", "A0:8C", "A0:B3", "A0:D3", "A0:D4", "A0:F1", "A4:5D", "A4:9A", "A4:BE", "A4:C0", "A8:9D", "A8:BD", "A8:BE", "AC:16", "AC:3D", "AC:81", "AC:9E", "AC:B3", "AC:CB", "B0:5A", "B0:8D", "B0:91", "B0:B1", "B0:C7", "B4:39", "B4:99", "B4:B5", "B4:E9", "B8:AF", "B8:CC", "B8:DB", "BC:EA", "C0:1D", "C0:91", "C0:97", "C0:B4", "C0:D3", "C0:DB", "C4:34", "C4:6E", "C8:5B", "C8:B5", "C8:CB", "C8:DF", "C8:F7", "CC:2F", "CC:3E", "CC:4F", "CC:5E", "CC:6D", "CC:78", "CC:8E", "CC:9F", "D0:7E", "D0:BF", "D0:C5", "D0:C7", "D0:E7", "D4:85", "D4:C9", "D4:DF", "D4:E5", "D8:9E", "D8:C7", "D8:D3", "D8:FE", "DC:4A", "DC:53", "DC:7B", "DC:B9", "E0:07", "E0:1C", "E0:28", "E0:DB", "E4:11", "E4:1D", "E4:40", "E4:90", "E4:A7", "E4:B3", "E4:C7", "E8:39", "E8:4A", "E8:6B", "E8:B2", "E8:F2", "EC:8E", "EC:9A", "EC:B1", "EC:ED", "F0:03", "F0:1F", "F0:25", "F0:62", "F0:92", "F0:B1", "F0:C7", "F0:C8", "F0:D1", "F0:D2", "F0:D4", "F0:F2", "F4:03", "F4:39", "F4:43", "F4:8E", "F4:96", "F4:B5", "F4:B9", "F4:CE", "F8:33", "F8:38", "F8:62", "F8:8F", "F8:9F", "F8:B1", "F8:CA", "F8:CB", "FC:15", "FC:3F", "FC:48", "FC:77", "FC:8F", "FC:9F", "FC:A1", "FC:B1", "FC:C7", "FC:D4", "FC:F8"],
    "VMware": ["00:50:56", "00:0C:29", "00:05:69"],
    "Raspberry": ["B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1", "2C:CF:67", "D8:3A:DD"],
    "Realtek": ["00:E0:4C", "52:54:00", "AC:BC", "2C:F0:EE", "00:1A", "00:1C", "00:1E", "08:00", "20:CF", "28:D2", "2C:F0", "30:F3", "34:97", "3C:5A", "40:62", "48:60", "4C:ED", "50:3E", "50:5F", "50:67", "54:27", "54:EE", "5C:83", "60:52", "68:05", "6C:33", "6C:63", "70:85", "78:24", "78:AC", "7C:DD", "80:26", "84:D8", "88:53", "88:C3", "90:EF", "94:D9", "98:DA", "98:DE", "9C:8E", "A0:2B", "A4:C4", "A8:F9", "B0:57", "B4:2D", "B8:5A", "BC:EF", "C0:25", "C4:8E", "C8:69", "CC:68", "D0:37", "D4:5C", "D4:A0", "D8:50", "D8:96", "DC:EF", "E0:4C", "E4:65", "E8:99", "E8:DF", "EC:0D", "EC:EF", "F0:18", "F0:79", "F4:06", "F8:1E", "F8:32", "F8:A0", "FC:34", "FC:D7"],
    "Microsoft": ["00:03:FF", "00:0D:3A", "00:12:5A", "00:15:5D", "00:17:FA", "00:1D:D8", "28:18", "3C:83", "50:1A", "50:6A", "58:82", "5C:BA", "60:45", "64:4B", "68:82", "70:B1", "7C:1E", "7C:ED", "84:EF", "8C:CE", "98:5F", "98:6B", "A0:3F", "A4:7B", "A4:C3", "B4:0E", "B8:31", "BC:77", "C4:36", "C8:3A", "CC:78", "D0:22", "D4:3D", "DC:B4", "E4:8B", "E4:C0", "EC:83", "F0:19", "F4:8E", "F8:27", "FC:A8"],
    "Netgear": ["00:14", "00:1B", "00:1F", "00:22", "00:24", "00:26", "20:0C", "28:C6", "2C:B0", "30:46", "38:94", "44:94", "4C:60", "54:B8", "6C:B0", "80:37", "84:1B", "9C:3D", "9C:D3", "A0:21", "A0:40", "A4:2B", "B0:7F", "C0:FF", "C4:04", "C4:15", "CC:40", "DC:EF", "E0:46", "E0:91", "E4:F4", "E8:FC", "F8:73"],
    "ASUS": ["00:0C", "00:0E", "00:11", "00:13", "00:15", "00:17", "00:18", "00:1A", "00:1B", "00:1C", "00:1D", "00:1E", "00:1F", "00:22", "00:23", "00:24", "00:25", "00:26", "00:27", "00:28", "00:29", "2C:4D", "2C:56", "2C:4D", "30:5A", "30:85", "38:D5", "3C:97", "48:5B", "4C:ED", "50:46", "54:04", "54:A0", "60:45", "60:A4", "74:D0", "88:D7", "8C:89", "90:E6", "9C:5C", "A8:5E", "AC:22", "AC:9E", "B0:6E", "B0:C7", "BC:AE", "C8:60", "D4:5D", "D8:50", "E0:3F", "E0:CB", "F0:79", "F4:6D", "F8:32", "FC:C8"],
    "Linksys": ["00:06", "00:0C", "00:0E", "00:12", "00:14", "00:16", "00:18", "00:1A", "00:1C", "00:1E", "00:21", "00:23", "00:25", "00:27", "58:6D", "68:7E", "88:36", "8C:C8", "94:10", "98:FC", "A0:88", "BC:EA", "C0:C1", "C8:3A", "C8:69", "CC:55", "E8:9F", "F0:82", "F4:E9"],
    "D-Link": ["00:05", "00:0B", "00:0D", "00:0F", "00:11", "00:13", "00:15", "00:17", "00:19", "00:1B", "00:1D", "00:1F", "00:21", "00:23", "00:25", "00:26", "00:50", "1C:7E", "28:10", "34:08", "3C:1E", "50:FF", "5C:D9", "78:32", "78:54", "84:C9", "88:E9", "90:94", "9C:D6", "A0:AB", "AC:F1", "B8:A3", "C0:A5", "C4:A8", "C8:BE", "CC:B2", "D4:AE", "DC:53", "E0:1C", "E0:46", "E0:5F", "EC:22", "F0:24", "FC:75", "00:26", "00:50", "00:80", "00:90"],
    "Cisco": ["00:00", "00:01", "00:02", "00:03", "00:04", "00:05", "00:06", "00:07", "00:08", "00:09", "00:0A", "00:0B", "00:0C", "00:0D", "00:0E", "00:0F", "00:10", "00:11", "00:12", "00:13", "00:14", "00:15", "00:16", "00:17", "00:18", "00:19", "00:1A", "00:1B", "00:1C", "00:1D", "00:1E", "00:1F", "00:20", "00:21", "00:22", "00:23", "00:24", "00:25", "00:26", "00:27", "00:28", "00:29", "00:2A", "00:2B", "00:2C", "00:2D", "00:2E", "00:2F", "00:30", "00:31", "00:32", "00:33", "00:34", "00:35", "00:36", "00:37", "00:38", "00:39", "00:3A", "00:3B", "00:3C", "00:3D", "00:3E", "00:3F", "00:40", "00:41", "00:42", "00:43", "00:44", "00:45", "00:46", "00:47", "00:48", "00:49", "00:4A", "00:4B", "00:4C", "00:4D", "00:4E", "00:4F", "00:50", "00:51", "00:52", "00:53", "00:54", "00:55", "00:56", "00:57", "00:58", "00:59", "00:5A", "00:5B", "00:5C", "00:5D", "00:5E", "00:5F", "00:60", "00:61", "00:62", "00:63", "00:64", "00:65", "00:66", "00:67", "00:68", "00:69", "00:6A", "00:6B", "00:6C", "00:6D", "00:6E", "00:6F", "00:70", "00:71", "00:72", "00:73", "00:74", "00:75", "00:76", "00:77", "04:4B", "04:6D", "04:C0", "08:00", "08:2E", "08:5D", "08:63", "08:6D", "08:7E", "08:8F", "08:A0", "08:CC", "0C:8D", "10:1F", "10:3D", "10:57", "10:7B", "10:A7", "10:B9", "10:D7", "10:FE", "14:1F", "14:49", "14:8F", "14:B1", "14:DD", "18:2A", "18:47", "18:80", "18:B4", "18:C5", "18:E7", "18:E8", "18:EF", "1C:1D", "1C:6A", "1C:7B", "1C:AB", "1C:B0", "1C:C7", "1C:EA", "20:0A", "20:37", "20:4E", "20:67", "20:72", "20:9F", "24:01", "24:0A", "24:14", "24:18", "24:1F", "24:33", "24:4B", "24:5C", "24:6E", "24:7F", "24:98", "24:A9", "24:B1", "24:C0", "24:E9", "24:F0", "24:F6", "28:28", "28:5F", "28:6D", "28:7A", "28:94", "28:9F", "28:C7", "28:C8", "28:C9", "28:CA", "28:CB", "28:CC", "28:CD", "28:CE", "28:CF", "28:D0", "28:D1", "28:D2", "28:D3", "28:D4", "28:D5", "28:D6", "28:D7", "28:D8", "28:D9", "28:DA", "28:DB", "28:DC", "28:DD", "28:DE", "28:DF", "28:E0", "28:E1", "28:E2", "28:E3", "28:E4", "28:E5", "28:E6", "28:E7", "28:E8", "28:E9", "28:EA", "28:EB", "28:EC", "28:ED", "28:EE", "28:EF", "28:F0", "28:F1", "28:F2", "28:F3", "28:F4", "28:F5", "28:F6", "28:F7", "28:F8", "28:F9", "28:FA", "28:FB", "28:FC", "28:FD", "28:FE", "28:FF", "2C:33", "2C:36", "2C:37", "2C:38", "2C:39", "2C:3A", "2C:3B", "2C:3C", "2C:3D", "2C:3E", "2C:3F", "2C:40", "2C:41", "2C:42", "2C:43", "2C:44", "2C:45", "2C:46", "2C:47", "2C:48", "2C:49", "2C:4A", "2C:4B", "2C:4C", "2C:4D", "2C:4E", "2C:4F", "2C:50", "2C:51", "2C:52", "2C:53", "2C:54", "2C:55", "2C:56", "2C:57", "2C:58", "2C:59", "2C:5A", "2C:5B", "2C:5C", "2C:5D", "2C:5E", "2C:5F", "2C:60", "2C:61", "2C:62", "2C:63", "2C:64", "2C:65", "2C:66", "2C:67", "2C:68", "2C:69", "2C:6A", "2C:6B", "2C:6C", "2C:6D", "2C:6E", "2C:6F", "2C:70", "2C:71", "2C:72", "2C:73", "2C:74", "2C:75", "2C:76", "2C:77", "2C:78", "2C:79", "2C:7A", "2C:7B", "2C:7C", "2C:7D", "2C:7E", "2C:7F", "2C:80", "2C:81", "2C:82", "2C:83", "2C:84", "2C:85", "2C:86", "2C:87", "2C:88", "2C:89", "2C:8A", "2C:8B", "2C:8C", "2C:8D", "2C:8E", "2C:8F", "2C:90", "2C:91", "2C:92", "2C:93", "2C:94", "2C:95", "2C:96", "2C:97", "2C:98", "2C:99", "2C:9A", "2C:9B", "2C:9C", "2C:9D", "2C:9E", "2C:9F", "2C:A0", "2C:A1", "2C:A2", "2C:A3", "2C:A4", "2C:A5", "2C:A6", "2C:A7", "2C:A8", "2C:A9", "2C:AA", "2C:AB", "2C:AC", "2C:AD", "2C:AE", "2C:AF", "2C:B0", "2C:B1", "2C:B2", "2C:B3", "2C:B4", "2C:B5", "2C:B6", "2C:B7", "2C:B8", "2C:B9", "2C:BA", "2C:BB", "2C:BC", "2C:BD", "2C:BE", "2C:BF", "2C:C0", "2C:C1", "2C:C2", "2C:C3", "2C:C4", "2C:C5", "2C:C6", "2C:C7", "2C:C8", "2C:C9", "2C:CA", "2C:CB", "2C:CC", "2C:CD", "2C:CE", "2C:CF", "2C:D0", "2C:D1", "2C:D2", "2C:D3", "2C:D4", "2C:D5", "2C:D6", "2C:D7", "2C:D8", "2C:D9", "2C:DA", "2C:DB", "2C:DC", "2C:DD", "2C:DE", "2C:DF", "2C:E0", "2C:E1", "2C:E2", "2C:E3", "2C:E4", "2C:E5", "2C:E6", "2C:E7", "2C:E8", "2C:E9", "2C:EA", "2C:EB", "2C:EC", "2C:ED", "2C:EE", "2C:EF", "2C:F0", "2C:F1", "2C:F2", "2C:F3", "2C:F4", "2C:F5", "2C:F6", "2C:F7", "2C:F8", "2C:F9", "2C:FA", "2C:FB", "2C:FC", "2C:FD", "2C:FE", "2C:FF", "30:00", "30:84", "30:94", "30:9A", "30:84"],
    "Google": ["00:1A", "08:9E", "0C:74", "10:6C", "1C:F2", "20:DF", "24:0F", "3C:5A", "40:B3", "44:07", "54:60", "54:09", "5C:7D", "6C:3E", "70:EE", "78:4B", "94:EB", "9C:04", "A4:77", "D4:F5", "F4:F5", "F8:8F"],
    "Amazon": ["00:BB", "0C:47", "10:AE", "14:91", "18:74", "1C:CA", "24:DB", "28:ED", "34:D2", "34:71", "38:F7", "40:B4", "44:65", "48:8A", "4C:EF", "50:DC", "50:F5", "58:4F", "68:37", "68:54", "6C:56", "6C:83", "74:75", "78:E1", "78:7B", "7C:50", "80:2A", "84:D6", "88:C9", "8C:F5", "90:B7", "94:D9", "98:D6", "9C:2A", "9C:E3", "A0:02", "A4:34", "A8:3D", "AC:63", "B0:FC", "B4:7C", "B4:9E", "BC:30", "C0:06", "C4:C9", "C8:3E", "CC:9E", "D0:25", "D4:79", "D8:74", "E0:5F", "E4:67", "E8:3B", "F0:27", "F0:81", "F0:D2", "F4:1F", "F4:8B", "F8:8E", "FC:A6", "FC:65", "FC:A1"],
    "MediaTek": ["00:1A", "00:22", "00:E0", "04:18", "04:4B", "04:C9", "08:6A", "0C:1D", "0C:74", "10:0C", "10:68", "14:35", "14:97", "18:86", "1C:8E", "20:07", "24:0A", "28:08", "2C:89", "30:6A", "34:F6", "38:AD", "3C:77", "40:B0", "44:1E", "48:3C", "4C:0A", "50:00", "54:2A", "58:C3", "5C:8D", "60:A4", "64:5A", "68:9E", "6C:72", "70:3C", "74:5F", "78:6A", "7C:5C", "80:2E", "84:89", "88:32", "8C:78", "90:4D", "94:63", "98:C4", "9C:8F", "A0:92", "A4:63", "A8:62", "AC:4D", "B0:28", "B4:47", "B8:0E", "BC:5F", "C0:5E", "C4:09", "C8:7E", "CC:5D", "D0:5E", "D4:01", "D8:8F", "DC:09", "E0:3D", "E4:1E", "E8:6B", "EC:1A", "F0:78", "F4:63", "F8:3D", "FC:7C"]
}


def run_command(cmd: list, timeout: int = 5) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return None


def get_gateway() -> str:
    if IS_WINDOWS:
        output = run_command(["powershell", "-Command", "ipconfig"])
        if output:
            for line in output.split('\n'):
                if 'Default Gateway' in line or '默认网关' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
    elif IS_MACOS:
        output = run_command(["netstat", "-rn"])
        if output:
            for line in output.split('\n'):
                if 'default' in line and 'UG' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    else:
        output = run_command(["ip", "route", "show", "default"])
        if output:
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return f"{ip.rsplit('.', 1)[0]}.1"
    except Exception:
        return "192.168.1.1"


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_subnet_info() -> tuple:
    local_ip = get_local_ip()
    ip_parts = local_ip.split(".")
    network_prefix = ".".join(ip_parts[:3])
    cidr = 24
    
    if IS_WINDOWS:
        output = run_command(["powershell", "-Command", "ipconfig"])
        if output:
            for line in output.split('\n'):
                if 'Subnet Mask' in line or '子网掩码' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        mask_int = struct.unpack("!I", socket.inet_aton(match.group(1)))[0]
                        cidr = bin(mask_int).count("1")
                        break
    elif IS_MACOS:
        output = run_command(["ifconfig"])
        if output:
            for line in output.split('\n'):
                if 'inet ' in line and local_ip in line:
                    match = re.search(r'netmask\s+(0x[0-9a-f]+)', line)
                    if match:
                        mask_int = int(match.group(1), 16)
                        cidr = bin(mask_int & 0xffffffff).count("1")
                        break
    
    return local_ip, network_prefix, cidr


def identify_device(mac: str, hostname: str = "") -> tuple[DeviceType, str]:
    mac_upper = mac.upper().replace('-', ':')
    hostname_lower = hostname.lower() if hostname else ""
    
    if any(kw in hostname_lower for kw in QUANT_KEYWORDS):
        return (DeviceType.QUANT, hostname)
    
    all_pi_prefixes = list(set(PI_MAC_PREFIXES + VENDOR_PREFIXES.get("Raspberry", [])))
    if any(mac_upper.startswith(p) for p in all_pi_prefixes):
        return (DeviceType.RASPBERRY_PI, hostname or "Raspberry Pi")
    
    if any(mac_upper.startswith(p) for p in VENDOR_PREFIXES.get("VMware", [])):
        return (DeviceType.UNKNOWN, hostname or "VMware Virtual Machine")
    
    for vendor, prefixes in VENDOR_PREFIXES.items():
        if vendor == "Raspberry":
            continue
        if any(mac_upper.startswith(p) for p in prefixes):
            return (DeviceType.UNKNOWN, hostname or f"{vendor} Device")
    
    return (DeviceType.UNKNOWN, hostname)


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_hostname_windows(ip: str) -> str:
    output = run_command(["nbtstat", "-A", ip], timeout=3)
    if output:
        for line in output.split('\n'):
            if '<HOST NAME>' in line.upper():
                return line.split('<')[0].strip()
    return ""


async def ping_host_async(ip: str) -> bool:
    loop = asyncio.get_event_loop()
    try:
        cmd = ["ping", "-n", "1", "-w", "200", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
        result = await loop.run_in_executor(executor, run_command, cmd, 2)
        if result is None:
            return False
        result_lower = result.lower()
        return "ttl=" in result_lower or "bytes from" in result_lower or "来自" in result or "time=" in result_lower
    except Exception:
        return False


async def icmp_sweep(network_prefix: str, cidr: int = 24) -> list[str]:
    host_count = 2 ** (32 - cidr) - 2
    if host_count > 510:
        host_count = 254
    
    loop = asyncio.get_event_loop()
    ping_tasks = []
    
    for i in range(1, host_count + 1):
        ip = f"{network_prefix}.{i}"
        ping_tasks.append(ping_host_async(ip))
    
    results = await asyncio.gather(*ping_tasks)
    live_hosts = []
    for i, is_alive in enumerate(results, 1):
        if is_alive:
            live_hosts.append(f"{network_prefix}.{i}")
    
    return live_hosts


async def scan_port_async(ip: str, port: int) -> Optional[int]:
    loop = asyncio.get_event_loop()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = await loop.run_in_executor(executor, sock.connect_ex, (ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


DETECT_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    7681: 'QuantClaw',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt'
}


async def get_ssh_banner(ip: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 22))
        if result != 0:
            sock.close()
            return None
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()
        banner_lower = banner.lower()
        if any(kw in banner_lower for kw in ['ssh', 'raspberrypi', 'raspberry', 'linux']):
            return banner
        return None
    except Exception:
        return None


async def probe_quantclaw(ip: str, port: int = 7681) -> tuple:
    import http.client
    import socket
    
    socket.setdefaulttimeout(2)
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=2)
        try:
            conn.request("GET", "/")
            response = conn.getresponse()
            
            headers = dict(response.getheaders())
            server_header = headers.get('server', '') or headers.get('Server', '')
            server_lower = server_header.lower()
            
            hostname = ""
            is_quant = False
            
            if 'ttyd' in server_lower or 'libwebsockets' in server_lower:
                is_quant = True
                hostname = f"{ip} (ttyd)"
            
            if response.status == 200:
                content = response.read().decode('utf-8', errors='ignore')
                content_lower = content.lower()
                
                for kw in QUANTCLAW_BODY_KEYWORDS:
                    if kw in content_lower:
                        is_quant = True
                        hostname = hostname or f"{ip} (QuantClaw)"
                        break
                
                title_match = re.search(r'<title>([^<]+)</title>', content, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                    if title and not is_quant:
                        hostname = title
                    elif title and not hostname.endswith(title):
                        hostname = title
            
            return (is_quant, hostname, server_lower)
        finally:
            conn.close()
    except Exception:
        return (False, "", "")


async def scan_device_fast(ip: str, mac: str) -> Optional[Device]:
    if not mac or mac == "Unknown":
        return None
    
    hostname = ""
    device_type = DeviceType.UNKNOWN
    open_ports = []
    
    port_tasks = [scan_port_async(ip, port) for port in DETECT_PORTS]
    port_results = await asyncio.gather(*port_tasks)
    open_ports = [r for r in port_results if r is not None]
    
    if 7681 in open_ports:
        is_quant, quant_hostname, server_info = await probe_quantclaw(ip)
        if is_quant:
            hostname = quant_hostname
            device_type = DeviceType.QUANT
        elif quant_hostname:
            hostname = quant_hostname
    
    if 80 in open_ports and device_type == DeviceType.UNKNOWN:
        try:
            import http.client
            socket.setdefaulttimeout(2)
            conn = http.client.HTTPConnection(ip, 80, timeout=2)
            try:
                conn.request("GET", "/")
                response = conn.getresponse()
                if response.status == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    title_match = re.search(r'<title>([^<]+)</title>', content, re.IGNORECASE)
                    if title_match:
                        hostname = hostname or title_match.group(1).strip()
                    
                    content_lower = content.lower()
                    for kw in QUANT_KEYWORDS:
                        if kw in content_lower:
                            device_type = DeviceType.QUANT
                            hostname = hostname or f"{ip} (QuantClaw)"
                            break
            finally:
                conn.close()
        except Exception:
            pass
    
    if 443 in open_ports and not hostname and device_type == DeviceType.UNKNOWN:
        try:
            import ssl
            import http.client
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            socket.setdefaulttimeout(2)
            conn = http.client.HTTPSConnection(ip, 443, timeout=2, context=ctx)
            try:
                conn.request("GET", "/")
                response = conn.getresponse()
                content = response.read().decode('utf-8', errors='ignore')
                title_match = re.search(r'<title>([^<]+)</title>', content, re.IGNORECASE)
                if title_match:
                    hostname = title_match.group(1).strip()
            finally:
                conn.close()
        except Exception:
            pass
    
    if 22 in open_ports and not hostname:
        try:
            banner = await get_ssh_banner(ip)
            if banner:
                parts = banner.split()
                for part in parts:
                    part_clean = part.strip(':\r\n,')
                    if any(kw in part_clean.lower() for kw in QUANT_KEYWORDS):
                        hostname = part_clean
                        break
        except Exception:
            pass
    
    if device_type == DeviceType.UNKNOWN:
        try:
            dns_hostname = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(executor, get_hostname, ip),
                timeout=0.5
            )
            if dns_hostname:
                hostname = hostname or dns_hostname
        except Exception:
            pass
        
        detected_type, _ = identify_device(mac, hostname)
        
        if detected_type == DeviceType.RASPBERRY_PI and 7681 in open_ports:
            device_type = DeviceType.QUANT
            hostname = hostname or f"{ip} (QuantClaw)"
        else:
            device_type = detected_type
    
    return Device(
        ip=ip, 
        mac=mac, 
        hostname=hostname or None, 
        device_type=device_type,
        open_ports=open_ports
    )


async def scan_device_deep(device: Device) -> Device:
    critical_ports = [7681]
    port_tasks = [scan_port_async(device.ip, port) for port in critical_ports]
    results = await asyncio.gather(*port_tasks)
    device.open_ports = [r for r in results if r is not None]
    return device


async def fast_scan_network() -> dict[str, str]:
    arp_cache = {}
    
    _, network_prefix, cidr = get_subnet_info()
    
    live_hosts = await icmp_sweep(network_prefix, cidr)
    
    if live_hosts:
        await asyncio.sleep(0.3)
    
    if IS_WINDOWS:
        output = run_command(["powershell", "-Command", "arp -a"])
        if output:
            for line in output.split('\n'):
                line = line.strip()
                if not line or 'Interface' in line or 'Internet' in line:
                    continue
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\S+)', line, re.IGNORECASE)
                if match:
                    ip, mac_raw, entry_type = match.groups()
                    mac = mac_raw.replace('-', ':').upper()
                    if entry_type.lower() in ('dynamic', '动态') and mac != "FF:FF:FF:FF:FF:FF":
                        arp_cache[ip] = mac
    elif IS_MACOS:
        output = run_command(["arp", "-n", "-a"])
        if output:
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})', line.lower())
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    if mac != "FF:FF:FF:FF:FF:FF" and not ip.startswith("224.") and not ip.startswith("239."):
                        arp_cache[ip] = mac
    else:
        output = run_command(["ip", "neigh", "show"])
        if output:
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    for p in parts:
                        if re.match(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', p.lower()):
                            if p.upper() != "FF:FF:FF:FF:FF:FF":
                                arp_cache[ip] = p.upper()
                            break
    
    for ip in live_hosts:
        if ip not in arp_cache:
            arp_cache[ip] = "Unknown"
    
    return arp_cache


@app.get("/", response_class=HTMLResponse)
async def root():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/scan")
async def scan_network():
    import time
    start_time = time.time()
    
    t1 = time.time()
    arp_cache = await fast_scan_network()
    t2 = time.time()
    
    device_tasks = [scan_device_fast(ip, mac) for ip, mac in arp_cache.items()]
    raw_devices = await asyncio.gather(*device_tasks)
    devices = [d for d in raw_devices if d is not None]
    t3 = time.time()
    
    quant_devices = [d for d in devices if d.is_quant]
    if quant_devices:
        deep_tasks = [scan_device_deep(d) for d in quant_devices]
        await asyncio.gather(*deep_tasks)
    t4 = time.time()
    
    all_devices = sorted(devices, key=lambda d: (not d.is_quant, d.ip))
    quant_device = next((d for d in all_devices if d.is_quant), None)
    
    global SCANNED_DEVICES
    SCANNED_DEVICES = all_devices
    
    total_time = int((time.time() - start_time) * 1000)
    arp_items = len(arp_cache)
    ping_reachable = len([d for d in devices if d.is_online])
    print(f"扫描完成: ARP={int((t2-t1)*1000)}ms|探测={int((t3-t2)*1000)}ms|端口={int((t4-t3)*1000)}ms|总计={total_time}ms|"
          f"ARP条目={arp_items}|Ping在线={ping_reachable}|总设备={len(all_devices)}")
    
    return ScanResult(
        devices=[d.to_dict() for d in all_devices],
        quant_device=quant_device.to_dict() if quant_device else None,
        total=len(all_devices),
        gateway=get_gateway(),
        scan_time_ms=total_time
    )


@app.get("/api/info")
async def get_info():
    local_ip, network_prefix, cidr = get_subnet_info()
    return {
        "local_ip": local_ip,
        "gateway": get_gateway(),
        "hostname": socket.gethostname(),
        "subnet": f"{network_prefix}.0/{cidr}",
        "platform": platform.system()
    }


SSH_CONFIG_MARKER_START = "# === QuantClaw Auto-Generated SSH Hosts ==="
SSH_CONFIG_MARKER_END   = "# === End QuantClaw SSH Hosts ==="


def get_ssh_config_path() -> str:
    return os.path.expanduser("~/.ssh/config")


def build_ssh_config_block(devices: list) -> str:
    lines = [SSH_CONFIG_MARKER_START]
    for d in devices:
        entry = d.ssh_config_entry
        if entry:
            lines.append("")
            lines.append(entry)
    lines.append("")
    lines.append(SSH_CONFIG_MARKER_END)
    return "\n".join(lines)


@app.get("/api/quant/ssh-hosts")
async def list_ssh_hosts():
    from pathlib import Path
    config_path = get_ssh_config_path()
    installed = False
    if Path(config_path).exists():
        content = Path(config_path).read_text()
        installed = SSH_CONFIG_MARKER_START in content
    return {
        "config_path": config_path,
        "installed": installed,
        "ssh_hosts": [
            {"ip": d.ip, "hostname": d.hostname, "ssh_host": d.ssh_host}
            for d in SCANNED_DEVICES
            if d.ssh_host
        ]
    }


@app.get("/api/quant/ssh-config")
async def get_ssh_config():
    return {
        "ssh_config": build_ssh_config_block(SCANNED_DEVICES),
        "config_path": get_ssh_config_path(),
        "install_command": f"cat >> {get_ssh_config_path()}",
        "host_count": len([d for d in SCANNED_DEVICES if d.ssh_host]),
        "usage": [
            {"host": d.ssh_host, "ip": d.ip, "command": f"ssh {d.ssh_host}"}
            for d in SCANNED_DEVICES
            if d.ssh_host
        ]
    }


@app.post("/api/quant/install-ssh-config")
async def install_ssh_config():
    from pathlib import Path
    config_path = get_ssh_config_path()
    config_dir = Path(config_path).parent
    config_dir.mkdir(parents=True, exist_ok=True)
    
    existing = ""
    if Path(config_path).exists():
        existing = Path(config_path).read_text()
    
    marker_start_idx = existing.find(SSH_CONFIG_MARKER_START)
    marker_end_idx = existing.find(SSH_CONFIG_MARKER_END)
    
    new_block = build_ssh_config_block(SCANNED_DEVICES)
    
    if marker_start_idx != -1 and marker_end_idx != -1:
        before = existing[:marker_start_idx]
        after = existing[marker_end_idx + len(SSH_CONFIG_MARKER_END):]
        updated = before.rstrip() + "\n\n" + new_block + "\n" + after.lstrip()
    else:
        if existing.strip():
            updated = existing.rstrip() + "\n\n" + new_block + "\n"
        else:
            updated = new_block + "\n"
    
    try:
        Path(config_path).write_text(updated)
        return {
            "status": "ok",
            "config_path": str(config_path),
            "entries_written": len([d for d in SCANNED_DEVICES if d.ssh_host]),
            "message": f"SSH config written to {config_path}"
        }
    except PermissionError:
        return {
            "status": "permission_denied",
            "config_path": str(config_path),
            "entries_written": 0,
            "message": f"Cannot write to {config_path} automatically",
            "manual_instructions": f"Please run the following command in your terminal:\n\nmkdir -p ~/.ssh && cat >> ~/.ssh/config << 'EOF'\n\n{new_block}\nEOF",
            "ssh_config": new_block
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
