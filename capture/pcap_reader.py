from scapy.all import rdpcap, IP, TCP, UDP
import os

def read_pcap(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fisierul {filepath} nu exista.")
    
    packets = rdpcap(filepath)
    parsed = []
    
    for pkt in packets:
        parsed.append(parse_packet(pkt))
    
    return [p for p in parsed if p is not None]

def parse_packet(pkt):
    if not pkt.haslayer(IP):
        return None
    
    ip = pkt[IP]
    result = {
        "timestamp": float(pkt.time),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": ip.proto,
        "length": len(pkt),
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
    }
    
    if pkt.haslayer(TCP):
        result["src_port"] = pkt[TCP].sport
        result["dst_port"] = pkt[TCP].dport
        result["tcp_flags"] = pkt[TCP].flags
    elif pkt.haslayer(UDP):
        result["src_port"] = pkt[UDP].sport
        result["dst_port"] = pkt[UDP].dport
    
    return result
