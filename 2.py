from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# List to store flows
flows = []

# Function to process each packet
def process_packet(packet):
     if IP in packet:
         # Check if the protocol is TCP or UDP
         if TCP in packet or UDP in packet:
             # Extracting packet information
             src_ip = packet[IP].src
             dst_ip = packet[IP].dst
             proto = packet[IP].proto
             timestamp = packet.time

             # Initialize source and destination ports
             src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
             dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

             # Calculate packet size
             packet_size = len(packet)

             # Find a matching flow or create a new one
             for flow in flows:
                 if ((flow[0] == src_ip and flow[1] == src_port and
                      flow[2] == dst_ip and flow[3] == dst_port) or
                     (flow[0] == dst_ip and flow[1] == dst_port and
                     flow[2] == src_ip and flow[3] == src_port) and
                     flow[4] == proto):
                     # Update flow information
                     flow[5] = min(flow[5], timestamp) # Update first packet time if needed
                     flow[6] = max(flow[6], timestamp) # Update last packet time
                     flow[7] += 1 # Increment packet count
                     flow[8] += packet_size # Increment byte count
                     flow[9].append(packet) # Add packet to flow
                     return

             # If no matching flow found, create a new one
             flows.append([src_ip, src_port, dst_ip, dst_port, proto, timestamp, timestamp, 1, packet_size, [packet]])

# Read the pcap file
packets = sniff(offline='test.pcap', prn=process_packet, count=10000)

# Display the collected flow information without packet summaries
lst = []
max_c = 0
for flow in flows:
     flow_info = {
        'source_ip': flow[0],
         'source_port': flow[1],
         'destination_ip': flow[2],
         'destination_port': flow[3],
         'protocol': flow[4],
         'first_packet_time': str(flow[5].to_integral_value()),
         'last_packet_time': str(flow[6].to_integral_value()),
         'packet_count': flow[7],
         'total_bytes': flow[8]
     }
     if flow[7] > max_c:
         max_c = flow[7]
     lst.append(flow_info)

import json
with open('res2.json', 'w') as f:
    json.dump(lst, f)


print(len(flows), max_c)