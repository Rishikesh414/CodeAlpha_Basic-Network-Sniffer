from scapy.all import sniff, IP, TCP, UDP, Raw

captured_packets = []
sniffing = False

def packet_callback(packet):
    try:
        src = packet[IP].src if IP in packet else "N/A"
        dst = packet[IP].dst if IP in packet else "N/A"
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        # Capture raw payload
        payload = ""
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode("utf-8", errors="replace")
            except:
                payload = str(packet[Raw].load)

        captured_packets.append({
            "src": src,
            "dst": dst,
            "proto": proto,
            "payload": payload   # full payload, not truncated
        })

        # Limit stored packets to avoid memory issues
        if len(captured_packets) > 500:
            captured_packets.pop(0)

    except Exception as e:
        print("Error:", e)

def start_sniffer():
    global sniffing
    sniffing = True
    sniff(prn=packet_callback, store=False, stop_filter=lambda x: not sniffing)

def stop_sniffer():
    global sniffing
    sniffing = False
