from scapy.all import sniff, conf, IP, TCP, UDP, Raw

# Set Scapy to use Layer 3 socket (no need for Npcap if running with admin privileges)
conf.L3socket

# Function to process each captured packet
def packet_callback(packet):
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        src_ip = packet[IP].src  # Source IP
        dst_ip = packet[IP].dst  # Destination IP
        protocol = packet[IP].proto  # Protocol (numeric)

        # Initialize ports
        src_port = None
        dst_port = None

        # Check if the packet is TCP
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # Check if the packet is UDP
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Get the payload data if present
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)  # Extract the raw payload
            payload_hex = payload.hex()  # Convert payload to hexadecimal
            payload_ascii = payload.decode('utf-8', 'ignore')  # Decode to ASCII, ignoring errors

            # Print all details in a structured format
            print(f"Source IP: {src_ip} | Source Port: {src_port}")
            print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")
            print(f"Protocol: {protocol}")
            print(f"Payload (Hex): {payload_hex}")
            print(f"Payload (ASCII): {payload_ascii}\n")
        else:
            # Print details without raw data
            print(f"Source IP: {src_ip} | Source Port: {src_port}")
            print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")
            print(f"Protocol: {protocol}")
            print("Payload: No Raw Data\n")

# Sniff network traffic without a count limit
# Use "iface" to specify a particular network interface if needed (e.g., "eth0" or "Wi-Fi")
sniff(filter="ip", iface="Wi-Fi", prn=packet_callback, store=False)