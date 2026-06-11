# app/app_classification.py

from __future__ import annotations

from collections import Counter
from typing import Any

from utils import (
    get_field,
    get_ports,
    guess_app_protocol_by_port,
    has_layer,
    increment_counter,
    safe_str,
    top_n,
)


def _get_ip_pair_any(packet: Any) -> tuple[str, str]:
    if has_layer(packet, "ip"):
        return (
            safe_str(get_field(packet, "ip", "src")),
            safe_str(get_field(packet, "ip", "dst")),
        )

    if has_layer(packet, "ipv6"):
        return (
            safe_str(get_field(packet, "ipv6", "src")),
            safe_str(get_field(packet, "ipv6", "dst")),
        )

    return "", ""


def _classify_by_layers(packet: Any) -> str | None:
    if has_layer(packet, "http"):
        return "HTTP"
    if has_layer(packet, "tls"):
        return "TLS/HTTPS"
    if has_layer(packet, "ssl"):
        return "TLS/HTTPS"
    if has_layer(packet, "dns"):
        return "DNS"
    if has_layer(packet, "ssh"):
        return "SSH"
    if has_layer(packet, "ftp"):
        return "FTP"
    if has_layer(packet, "dhcp"):
        return "DHCP"
    if has_layer(packet, "ntp"):
        return "NTP"
    if has_layer(packet, "quic"):
        return "QUIC"
    if has_layer(packet, "mdns"):
        return "mDNS"
    return None


def _protocol_from_ports(protocol: str, src_port: int, dst_port: int) -> str:
    dst_guess = guess_app_protocol_by_port(dst_port, protocol)
    src_guess = guess_app_protocol_by_port(src_port, protocol)

    if dst_guess != "UNKNOWN":
        return dst_guess
    if src_guess != "UNKNOWN":
        return src_guess
    return "UNKNOWN"


def _flow_key(protocol: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        return f"{protocol}|{left[0]}:{left[1]}<->{right[0]}:{right[1]}"
    return f"{protocol}|{right[0]}:{right[1]}<->{left[0]}:{left[1]}"


def analyze_application(packets: list[Any]) -> dict[str, Any]:
    """
    Clasifica tráfico de capa superior usando:
    - puertos conocidos
    - presencia de capas de Wireshark/TShark
    - contadores por flujo
    """

    flow_map: dict[str, dict[str, Any]] = {}
    protocol_counter: Counter[str] = Counter()
    tcp_protocol_counter: Counter[str] = Counter()
    udp_protocol_counter: Counter[str] = Counter()

    for packet in packets:
        if not (has_layer(packet, "tcp") or has_layer(packet, "udp")):
            continue

        protocol = "TCP" if has_layer(packet, "tcp") else "UDP"
        src_ip, dst_ip = _get_ip_pair_any(packet)
        src_port, dst_port = get_ports(packet)

        if not src_ip or not dst_ip or src_port == 0 or dst_port == 0:
            continue

        key = _flow_key(protocol, src_ip, src_port, dst_ip, dst_port)

        if key not in flow_map:
            flow_map[key] = {
                "flow_id": key,
                "transport": protocol,
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "packets": 0,
                "bytes": 0,
                "protocol_guess": "UNKNOWN",
                "evidence": [],
            }

        flow = flow_map[key]
        flow["packets"] += 1

        layer_guess = _classify_by_layers(packet)
        port_guess = _protocol_from_ports(protocol, src_port, dst_port)

        if layer_guess and layer_guess != "UNKNOWN":
            flow["protocol_guess"] = layer_guess
            increment_counter(protocol_counter, layer_guess)
            if protocol == "TCP":
                increment_counter(tcp_protocol_counter, layer_guess)
            else:
                increment_counter(udp_protocol_counter, layer_guess)
            continue

        if port_guess != "UNKNOWN":
            flow["protocol_guess"] = port_guess
            increment_counter(protocol_counter, port_guess)
            if protocol == "TCP":
                increment_counter(tcp_protocol_counter, port_guess)
            else:
                increment_counter(udp_protocol_counter, port_guess)
        else:
            increment_counter(protocol_counter, "UNKNOWN")
            if protocol == "TCP":
                increment_counter(tcp_protocol_counter, "UNKNOWN")
            else:
                increment_counter(udp_protocol_counter, "UNKNOWN")

    top_protocols = [
        {"protocol": proto, "count": count}
        for proto, count in top_n(dict(protocol_counter), 15)
    ]

    top_tcp_protocols = [
        {"protocol": proto, "count": count}
        for proto, count in top_n(dict(tcp_protocol_counter), 10)
    ]

    top_udp_protocols = [
        {"protocol": proto, "count": count}
        for proto, count in top_n(dict(udp_protocol_counter), 10)
    ]

    flows = list(flow_map.values())
    flows.sort(key=lambda x: (x["packets"], x["flow_id"]), reverse=True)

    return {
        "detected_protocols": top_protocols,
        "tcp_protocols": top_tcp_protocols,
        "udp_protocols": top_udp_protocols,
        "flows": flows,
        "top_flows": flows[:10],
        "total_flows": len(flows),
    }