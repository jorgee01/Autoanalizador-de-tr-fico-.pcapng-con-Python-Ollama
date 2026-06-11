#app/parser_pcap.py es un lector que entiende un formato específico.
import pyshark


def load_packets(pcap_file: str): #recibir un texto (el archivo):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    packets = []    #vector vacío que me va a guardar packetes uno por uno.

    for packet in capture:
        packets.append(packet)

    capture.close()
    return packets