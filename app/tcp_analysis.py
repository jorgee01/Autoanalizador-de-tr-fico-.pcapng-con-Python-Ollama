# app/tcp_analysis.py

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from utils import (
    get_field,
    get_ports,
    get_transport_protocol,
    guess_app_protocol_by_port,
    has_layer,
    increment_counter,
    is_tcp_fin,
    is_tcp_rst,
    is_tcp_syn,
    is_tcp_syn_ack,
    packet_length,
    packet_time,
    safe_int,
    safe_str,
    tcp_flags,
    top_n,
)


def _get_ip_pair_any(packet: Any) -> tuple[str, str]:
    """
    Obtiene IP origen / destino tanto para IPv4 como IPv6.
    """
    if has_layer(packet, "ip"):
        src = safe_str(get_field(packet, "ip", "src"))
        dst = safe_str(get_field(packet, "ip", "dst"))
        return src, dst

    if has_layer(packet, "ipv6"):
        src = safe_str(get_field(packet, "ipv6", "src"))
        dst = safe_str(get_field(packet, "ipv6", "dst"))
        return src, dst

    return "", ""


def _endpoint(ip: str, port: int) -> str:
    return f"{ip}:{port}"


def _session_key(packet: Any, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """
    Si Wireshark/TShark expone tcp.stream, usamos ese valor porque representa
    mejor una conversación TCP real que solo agrupar por 5-tupla.
    """
    stream = safe_str(get_field(packet, "tcp", "stream"))
    if stream:
        return f"stream:{stream}"

    # Fallback: normaliza la conversación para agrupar ida/vuelta.
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        return f"flow:{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
    return f"flow:{dst_ip}:{dst_port}<->{src_ip}:{src_port}"


def analyze_tcp(packets: list[Any]) -> dict[str, Any]:
    """
    Analiza tráfico TCP y devuelve un resumen estructurado.

    Resultados principales:
    - sesiones TCP
    - handshakes completos
    - conexiones incompletas
    - cierres FIN
    - cierres RST
    - top puertos y top conversaciones

    La función usa heurísticas simples y robustas, apropiadas para una
    captura real sin depender de que todos los paquetes vengan perfectos.
    """
    sessions: dict[str, dict[str, Any]] = {}
    dst_port_counter: Counter[int] = Counter()
    src_port_counter: Counter[int] = Counter()
    app_hint_counter: Counter[str] = Counter()

    total_tcp_packets = 0
    total_tcp_bytes = 0

    syn_packets = 0
    syn_ack_packets = 0
    ack_packets = 0
    fin_packets = 0
    rst_packets = 0

    for packet in packets:
        if not has_layer(packet, "tcp"):
            continue

        total_tcp_packets += 1
        total_tcp_bytes += packet_length(packet)

        src_ip, dst_ip = _get_ip_pair_any(packet)
        src_port, dst_port = get_ports(packet)

        if not src_ip or not dst_ip or src_port == 0 or dst_port == 0:
            # Si no podemos identificar extremos, aún contamos el paquete,
            # pero no intentamos reconstruir sesión.
            continue

        key = _session_key(packet, src_ip, src_port, dst_ip, dst_port)
        flags = tcp_flags(packet)
        ts = packet_time(packet)

        if key not in sessions:
            sessions[key] = {
                "session_id": key,
                "src": _endpoint(src_ip, src_port),
                "dst": _endpoint(dst_ip, dst_port),
                "packets": 0,
                "bytes": 0,
                "first_seen": ts,
                "last_seen": ts,
                "syn_seen": False,
                "syn_ack_seen": False,
                "final_ack_seen": False,
                "handshake_complete": False,
                "handshake_complete_at": None,
                "initiator": None,
                "fin_packets": 0,
                "rst_packets": 0,
                "closed_by_fin": False,
                "closed_by_rst": False,
                "app_protocol_guess": guess_app_protocol_by_port(dst_port, "TCP"),
                "ports": {
                    "src_port": src_port,
                    "dst_port": dst_port,
                },
            }

        session = sessions[key]
        session["packets"] += 1
        session["bytes"] += packet_length(packet)

        if ts is not None:
            if session["first_seen"] is None or ts < session["first_seen"]:
                session["first_seen"] = ts
            if session["last_seen"] is None or ts > session["last_seen"]:
                session["last_seen"] = ts

        increment_counter(dst_port_counter, dst_port)
        increment_counter(src_port_counter, src_port)

        app_guess = guess_app_protocol_by_port(dst_port, "TCP")
        if app_guess != "UNKNOWN":
            increment_counter(app_hint_counter, app_guess)

        # Conteo de flags por paquete
        if is_tcp_syn(flags):
            syn_packets += 1
            session["syn_seen"] = True
            if session["initiator"] is None:
                session["initiator"] = _endpoint(src_ip, src_port)

        if is_tcp_syn_ack(flags):
            syn_ack_packets += 1
            session["syn_ack_seen"] = True

        # Un ACK puro o con datos también puede ser el ACK final del handshake.
        if bool(flags.get("ack")) and not bool(flags.get("syn")):
            ack_packets += 1
            if session["syn_seen"] and session["syn_ack_seen"]:
                if session["initiator"] is not None and session["initiator"] == _endpoint(src_ip, src_port):
                    session["final_ack_seen"] = True

        if is_tcp_fin(flags):
            fin_packets += 1
            session["fin_packets"] += 1
            session["closed_by_fin"] = True

        if is_tcp_rst(flags):
            rst_packets += 1
            session["rst_packets"] += 1
            session["closed_by_rst"] = True

        # Confirmamos handshake solo si vimos SYN, SYN-ACK y el ACK final.
        if session["syn_seen"] and session["syn_ack_seen"] and session["final_ack_seen"]:
            session["handshake_complete"] = True
            if session["handshake_complete_at"] is None:
                session["handshake_complete_at"] = ts

    # Sesiones incompletas = hubo SYN, pero no se cerró el handshake.
    complete_sessions = 0
    incomplete_sessions = 0
    closed_by_fin_sessions = 0
    closed_by_rst_sessions = 0

    for session in sessions.values():
        if session["handshake_complete"]:
            complete_sessions += 1
        elif session["syn_seen"]:
            incomplete_sessions += 1

        if session["closed_by_fin"]:
            closed_by_fin_sessions += 1
        if session["closed_by_rst"]:
            closed_by_rst_sessions += 1

    # Top conversaciones por volumen
    conversations = sorted(
        sessions.values(),
        key=lambda s: (s["bytes"], s["packets"]),
        reverse=True,
    )

    top_sessions = []
    for s in conversations[:10]:
        top_sessions.append(
            {
                "session_id": s["session_id"],
                "src": s["src"],
                "dst": s["dst"],
                "packets": s["packets"],
                "bytes": s["bytes"],
                "handshake_complete": s["handshake_complete"],
                "closed_by_fin": s["closed_by_fin"],
                "closed_by_rst": s["closed_by_rst"],
                "app_protocol_guess": s["app_protocol_guess"],
            }
        )

    top_dst_ports = [
        {"port": port, "count": count, "protocol_guess": guess_app_protocol_by_port(port, "TCP")}
        for port, count in top_n(dict(dst_port_counter), n=10)
    ]

    top_src_ports = [
        {"port": port, "count": count}
        for port, count in top_n(dict(src_port_counter), n=10)
    ]

    top_app_hints = [
        {"protocol": proto, "count": count}
        for proto, count in top_n(dict(app_hint_counter), n=10)
    ]

    sessions_list = []
    for session in sessions.values():
        sessions_list.append(
            {
                "session_id": session["session_id"],
                "src": session["src"],
                "dst": session["dst"],
                "packets": session["packets"],
                "bytes": session["bytes"],
                "first_seen": session["first_seen"],
                "last_seen": session["last_seen"],
                "initiator": session["initiator"],
                "syn_seen": session["syn_seen"],
                "syn_ack_seen": session["syn_ack_seen"],
                "final_ack_seen": session["final_ack_seen"],
                "handshake_complete": session["handshake_complete"],
                "handshake_complete_at": session["handshake_complete_at"],
                "fin_packets": session["fin_packets"],
                "rst_packets": session["rst_packets"],
                "closed_by_fin": session["closed_by_fin"],
                "closed_by_rst": session["closed_by_rst"],
                "app_protocol_guess": session["app_protocol_guess"],
                "ports": session["ports"],
            }
        )

    return {
        "transport": "TCP",
        "total_packets": total_tcp_packets,
        "total_bytes": total_tcp_bytes,
        "tcp_sessions": len(sessions),
        "tcp_sessions_with_handshake": complete_sessions,
        "tcp_sessions_incomplete": incomplete_sessions,
        "tcp_sessions_closed_by_fin": closed_by_fin_sessions,
        "tcp_sessions_closed_by_rst": closed_by_rst_sessions,
        "tcp_fin_packets": fin_packets,
        "tcp_rst_packets": rst_packets,
        "tcp_syn_packets": syn_packets,
        "tcp_syn_ack_packets": syn_ack_packets,
        "tcp_ack_packets": ack_packets,
        "top_dst_ports": top_dst_ports,
        "top_src_ports": top_src_ports,
        "top_application_hints": top_app_hints,
        "top_sessions": top_sessions,
        "sessions": sessions_list,
    }