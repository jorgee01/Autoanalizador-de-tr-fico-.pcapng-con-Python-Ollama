import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "deepseek-coder:1.3b"


def formatear_summary(summary: dict) -> str:
    tcp = summary.get("tcp", {})
    udp = summary.get("udp", {})
    app = summary.get("app", {})

    return f"""
=== TCP ===
Sesiones totales: {tcp.get("total_sessions", "N/A")}
Handshakes completos: {tcp.get("completed_handshakes", "N/A")}
Cierres FIN: {tcp.get("fin_count", "N/A")}
Cierres RST: {tcp.get("rst_count", "N/A")}
Total paquetes TCP: {tcp.get("total_packets", "N/A")}

=== UDP ===
Datagramas totales: {udp.get("udp_datagrams", "N/A")}
Flujos únicos: {udp.get("udp_sessions", "N/A")}

=== PROTOCOLOS ===
{app}
"""


def generate_report(summary: dict) -> str:
    datos = formatear_summary(summary)

    prompt = f"""Actúa como un analista de redes explicando resultados a estudiantes universitarios.
Genera un informe claro en español a partir de estas estadísticas de tráfico de red:

{datos}

Usa ÚNICAMENTE los datos anteriores. No inventes porcentajes ni datos.
Si algo no está disponible, indícalo naturalmente.

Escribe en formato Markdown. El informe debe tener estas secciones:

## Resumen General
Describe qué tipo de tráfico predomina y el comportamiento general observado.

## Análisis de TCP
- Sesiones TCP detectadas
- Conexiones con Three-Way Handshake completo
- Conexiones incompletas
- Cierres mediante FIN y su significado
- Cierres mediante RST y su significado

## Análisis de UDP
- Datagramas UDP totales
- Flujos únicos detectados
- Comportamiento observado

## Protocolos Identificados
Lista los protocolos detectados y explica brevemente la función de cada uno.

## Conclusión
Dos párrafos: qué se puede inferir y si el comportamiento parece normal.
"""

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "Eres un analista de redes. Responde SOLO con el informe en Markdown. Sin saludos ni texto extra."},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {
            "num_predict": 500,
            "temperature": 0.2,
        }
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=120)
    response.raise_for_status()
    data = response.json()
    return data["message"]["content"]