import os
from datetime import datetime
from parser_pcap import load_packets
from tcp_analysis import analyze_tcp
from udp_analysis import analyze_udp
from classification import analyze_application
from ollama_report import generate_report


def main():
    pcap_file = input("Ruta del archivo .pcapng: ").strip()

    try:
        packets = load_packets(pcap_file)
    except Exception as e:
        print(f"\nError al cargar el archivo:\n{e}")
        return

    if not packets:
        print("\nNo se encontraron paquetes para analizar.")
        return

    tcp_stats = analyze_tcp(packets)
    udp_stats = analyze_udp(packets)
    app_stats = analyze_application(packets)

    summary = {
        "tcp": tcp_stats,
        "udp": udp_stats,
        "app": app_stats,
    }

    report = generate_report(summary)

    print("\n--------- RESUMEN FINAL ---------\n")
    print(report)

    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")     #le da formato de fecha a los reportes
    nombre_archivo = f"reports/reporte_{timestamp}.md"         

    with open(nombre_archivo, "w", encoding="utf-8") as f:      
        f.write(report)

    print(f"\nReporte guardado en {nombre_archivo}")            


if __name__ == "__main__":
    main()