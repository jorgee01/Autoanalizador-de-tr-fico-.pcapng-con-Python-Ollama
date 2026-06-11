#Lectura de todos los paquetes del tráfico UDP y estadísticas.

from __future__ import annotations

from collections import Counter
from typing import Any

from utils import (
    get_field,
    get_ports,
    guess_app_protocol_by_port,
    has_layer,
    increment_counter,
    packet_length,
    packet_time,
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


def _flow_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> str:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)

    if left <= right:
        return f"{left[0]}:{left[1]}<->{right[0]}:{right[1]}"

    return f"{right[0]}:{right[1]}<->{left[0]}:{left[1]}"


def analyze_udp(packets: list[Any]) -> dict:
    flows = {}          #Diccionario de conversaciones

    dst_port_counter = Counter()
    src_port_counter = Counter()
    protocol_counter = Counter()

    total_packets = 0
    total_bytes = 0

    for packet in packets:

        if not has_layer(packet, "udp"):
            continue

        total_packets += 1
        total_bytes += packet_length(packet)

        src_ip, dst_ip = _get_ip_pair_any(packet)
        src_port, dst_port = get_ports(packet)

        if not src_ip or not dst_ip:
            continue

        key = _flow_key(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        )

        if key not in flows:

            flows[key] = {
                "flow": key,
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "packets": 0,
                "bytes": 0,
                "first_seen": packet_time(packet),
                "last_seen": packet_time(packet),
                "protocol_guess": guess_app_protocol_by_port(
                    dst_port,
                    "UDP",
                ),
            }

        flow = flows[key]

        flow["packets"] += 1
        flow["bytes"] += packet_length(packet)

        ts = packet_time(packet)

        if ts is not None:

            if (
                flow["first_seen"] is None
                or ts < flow["first_seen"]
            ):
                flow["first_seen"] = ts

            if (
                flow["last_seen"] is None
                or ts > flow["last_seen"]
            ):
                flow["last_seen"] = ts

        increment_counter(dst_port_counter, dst_port)
        increment_counter(src_port_counter, src_port)

        proto = guess_app_protocol_by_port(
            dst_port,
            "UDP",
        )

        if proto != "UNKNOWN":
            increment_counter(protocol_counter, proto)

    top_flows = sorted(
        flows.values(),
        key=lambda x: (
            x["bytes"],
            x["packets"],
        ),
        reverse=True,
    )[:10]

    return {

        "transport": "UDP",

        "udp_datagrams": total_packets,

        "udp_sessions": len(flows),

        "total_bytes": total_bytes,

        "top_destination_ports": [
            {
                "port": p,
                "count": c,
                "protocol_guess": guess_app_protocol_by_port(
                    p,
                    "UDP",
                ),
            }
            for p, c in top_n(
                dict(dst_port_counter),
                10,
            )
        ],

        "top_source_ports": [
            {
                "port": p,
                "count": c,
            }
            for p, c in top_n(
                dict(src_port_counter),
                10,
            )
        ],

        "top_protocols": [
            {
                "protocol": p,
                "count": c,
            }
            for p, c in top_n(
                dict(protocol_counter),
                10,
            )
        ],

        "top_flows": top_flows,

        "flows": list(flows.values()),
    }
