#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import errno
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, asdict
from typing import List, Optional, Set

# ----------------------------
# Config & fingerprints
# ----------------------------
DEFAULT_TIMEOUT = 1.0  # seconds
DEFAULT_WORKERS = 500
BANNER_BYTES = 128
BANNER_PROBE = b"\r\n"

TOP_PORTS_100 = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 80, 81, 88, 110, 111, 113, 119, 123,
    135, 137, 139, 143, 161, 179, 199, 389, 427, 443, 445, 465, 500, 512, 513,
    514, 515, 520, 554, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1433, 1434, 1521, 1723, 1900, 2049, 2082, 2083,
    2121, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3478, 3479, 3632, 3690,
    4000, 4040, 4369, 4444, 4500, 4567, 5000, 5060, 5432, 5672, 5900, 5985,
    5986, 6379, 6443, 6667, 7001, 7002, 7077, 7199, 8000, 8008, 8080, 8081,
    8088, 8161, 8333, 8443, 8530, 8531, 8888, 9000, 9092, 9200, 9300, 11211,
]

COMMON_SERVICES = {
    20: "FTP‑data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS‑NS",
    139: "NetBIOS‑SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    515: "LPD",
    554: "RTSP",
    587: "Submission",
    631: "IPP/Printing",
    636: "LDAPS",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2379: "etcd",
    27017: "MongoDB",
    3000: "Dev HTTP",
    3128: "Proxy",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    5000: "API/Flask",
    5060: "SIP",
    5432: "Postgres",
    5672: "AMQP/RabbitMQ",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM(SSL)",
    6379: "Redis",
    6443: "K8s API",
    8000: "Alt HTTP",
    8080: "HTTP‑proxy",
    8081: "Alt HTTP",
    8443: "Alt HTTPS",
    8888: "Dev UI",
    9000: "Alt API",
    9092: "Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
}

# ----------------------------
# Data types
# ----------------------------
@dataclass
class ScanResult:
    port: int
    status: str  # "open" | "closed" | "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None


# ----------------------------
# Helpers
# ----------------------------
PORT_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def parse_ports(spec: Optional[str], top_n: Optional[int]) -> List[int]:
    if spec and top_n:
        raise ValueError("Choose either --ports or --top, not both")

    if not spec:
        if top_n:
            if top_n <= 0:
                raise ValueError("--top must be > 0")
            return sorted(set(TOP_PORTS_100[: top_n]))
        return list(range(1, 1025))

    parts = [p.strip() for p in spec.split(",") if p.strip()]
    ports: Set[int] = set()
    for part in parts:
        m = PORT_RE.match(part)
        if not m:
            raise ValueError(f"Invalid port token: {part}")
        start = int(m.group(1))
        end = int(m.group(2) or start)
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError(f"Port out of range: {part}")
        for p in range(start, end + 1):
            ports.add(p)
    return sorted(ports)


def resolve_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target {target}: {e}")


def scan_port(ip: str, port: int, timeout: float, grab_banner: bool) -> ScanResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        status = "open"
        banner = None
        if grab_banner:
            try:
                sock.sendall(BANNER_PROBE)
                banner_bytes = sock.recv(BANNER_BYTES)
                banner = banner_bytes.decode(errors="ignore").strip()
            except socket.timeout:
                banner = None
            except Exception:
                banner = None
        service = COMMON_SERVICES.get(port)
        return ScanResult(port=port, status=status, service=service, banner=banner)
    except socket.timeout:
        return ScanResult(port=port, status="filtered")
    except ConnectionRefusedError:
        return ScanResult(port=port, status="closed")
    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            return ScanResult(port=port, status="closed")
        elif e.errno == errno.EHOSTUNREACH:
            return ScanResult(port=port, status="filtered")
        else:
            return ScanResult(port=port, status="filtered")
    finally:
        sock.close()


def scan_ports(
    ip: str,
    ports: List[int],
    timeout: float,
    workers: int,
    grab_banner: bool,
) -> List[ScanResult]:
    results: List[ScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab_banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)

    results.sort(key=lambda r: r.port)
    return results


def save_results_json(results: List[ScanResult], filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)