
def parse_flags(flags):
    if flags is None:
        return {
            "SYN": 0, "ACK": 0, "FIN": 0,
            "RST": 0, "PSH": 0, "URG": 0
        }
    return {
        "SYN": 1 if flags & 0x02 else 0,
        "ACK": 1 if flags & 0x10 else 0,
        "FIN": 1 if flags & 0x01 else 0,
        "RST": 1 if flags & 0x04 else 0,
        "PSH": 1 if flags & 0x08 else 0,
        "URG": 1 if flags & 0x20 else 0,
    }

def enrich_packet(pkt):
    flags = parse_flags(pkt.get("tcp_flags"))
    pkt["SYN"] = flags["SYN"]
    pkt["ACK"] = flags["ACK"]
    pkt["FIN"] = flags["FIN"]
    pkt["RST"] = flags["RST"]
    pkt["PSH"] = flags["PSH"]
    pkt["URG"] = flags["URG"]
    return pkt

def parse_packets(packets):
    return [enrich_packet(pkt) for pkt in packets]
