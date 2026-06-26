from scapy.all import sniff, IP, TCP, UDP
import threading

class LiveCapture:
    def __init__(self, interface, packet_callback):
        self.interface = interface
        self.packet_callback = packet_callback
        self.running = False
        self._thread = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._capture, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _capture(self):
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self.running
        )

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

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

        self.packet_callback(result)
