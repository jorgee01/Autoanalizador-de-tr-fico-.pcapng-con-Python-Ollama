# Funciones auxiliares para los módulos de análisis.

from __future__ import annotations
from ipaddress import ip_address
from typing import Any


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        text = str(value).strip()
        return text if text else default
    except Exception:
        return default

############################################ Funciones para: Top puertos, IPs, protocolos y Top sesiones.
def increment_counter(counter: dict, key: Any, amount: int = 1) -> None:
    counter[key] = counter.get(key, 0) + amount


def top_n(counter: dict, n: int = 10) -> list[tuple[Any, int]]:
    return sorted(counter.items(), key=lambda item: item[1], reverse=True)[:n]

############################################

def get_layer(packet: Any, layer_name: str) -> Any:
    try:
        return getattr(packet, layer_name)
    except AttributeError:
        return None
    except Exception:
        return None


def get_field(packet: Any, layer_name: str, field_name: str, default: Any = None) -> Any:
    layer = get_layer(packet, layer_name)
    if layer is None:
        return default
    try:
        value = getattr(layer, field_name)
        return value if value is not None else default
    except AttributeError:
        return default
    except Exception:
        return default


def has_layer(packet: Any, layer_name: str) -> bool:
    try:
        return layer_name in packet
    except Exception:
        return False


def get_ip_pair(packet: Any) -> tuple[str, str]:
    src = safe_str(get_field(packet, "ip", "src"))
    dst = safe_str(get_field(packet, "ip", "dst"))
    return src, dst


def get_transport_protocol(packet: Any) -> str:
    if has_layer(packet, "tcp"):
        return "TCP"
    if has_layer(packet, "udp"):
        return "UDP"
    return "OTHER"


def get_ports(packet: Any) -> tuple[int, int]:
    if has_layer(packet, "tcp"):
        src = safe_int(get_field(packet, "tcp", "srcport"))
        dst = safe_int(get_field(packet, "tcp", "dstport"))
        return src, dst
    if has_layer(packet, "udp"):
        src = safe_int(get_field(packet, "udp", "srcport"))
        dst = safe_int(get_field(packet, "udp", "dstport"))
        return src, dst
    return 0, 0


def tcp_flags(packet: Any) -> dict[str, bool]:
    flags_value = safe_str(get_field(packet, "tcp", "flags"))
    flags = {
        "syn": False,
        "ack": False,
        "fin": False,
        "rst": False,
        "psh": False,
        "urg": False,
    }
    if not flags_value:
        return flags
    try:
        if flags_value.startswith("0x"):
            n = int(flags_value, 16)
        else:
            n = int(flags_value)
        flags["fin"] = bool(n & 0x01)
        flags["syn"] = bool(n & 0x02)
        flags["rst"] = bool(n & 0x04)
        flags["psh"] = bool(n & 0x08)
        flags["ack"] = bool(n & 0x10)
        flags["urg"] = bool(n & 0x20)
        return flags
    except Exception:
        pass
    text = flags_value.lower()
    flags["syn"] = "syn" in text
    flags["ack"] = "ack" in text
    flags["fin"] = "fin" in text
    flags["rst"] = "rst" in text
    flags["psh"] = "psh" in text
    flags["urg"] = "urg" in text
    return flags


def is_private_ip(addr: str) -> bool:
    try:
        return ip_address(addr).is_private
    except Exception:
        return False


def is_tcp_syn(flags: dict[str, bool]) -> bool:
    return bool(flags.get("syn")) and not bool(flags.get("ack"))


def is_tcp_syn_ack(flags: dict[str, bool]) -> bool:
    return bool(flags.get("syn")) and bool(flags.get("ack"))


def is_tcp_fin(flags: dict[str, bool]) -> bool:
    return bool(flags.get("fin"))


def is_tcp_rst(flags: dict[str, bool]) -> bool:
    return bool(flags.get("rst"))


def packet_length(packet: Any) -> int:
    for layer_name, field_name in (
        ("frame_info", "len"),
        ("frame", "len"),
        ("frame", "cap_len"),
    ):
        value = get_field(packet, layer_name, field_name)
        if value is not None:
            return safe_int(value)
    try:
        return safe_int(packet.length)
    except Exception:
        return 0


def packet_time(packet: Any) -> float | None:
    try:
        if hasattr(packet, "sniff_timestamp"):
            return float(packet.sniff_timestamp)
    except Exception:
        pass
    return None


def normalize_protocol_name(name: str) -> str:
    return safe_str(name).upper()


def guess_app_protocol_by_port(port: int, proto: str = "TCP") -> str:
    proto = proto.upper()
    if proto == "TCP":
        mapping = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS/TLS", 445: "SMB",
            587: "SMTP", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT",
        }
    else:
        mapping = {
            53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
            123: "NTP", 161: "SNMP", 500: "IKE", 514: "SYSLOG",
            546: "DHCPv6", 547: "DHCPv6", 1194: "OpenVPN",
            1900: "SSDP", 443: "QUIC/HTTPS", 5353: "mDNS",
        }
    return mapping.get(port, "UNKNOWN")