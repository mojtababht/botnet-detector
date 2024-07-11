from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
from pathlib import Path
from datetime import datetime




def create_flow(pkt: Ether):
    # print(ether.sent_time)
    # print(ether.fragment())
    # print(ether.summary())
    # print(ether.type)
    # print(ether.sent_time)
    # print(list(ether))
    # print('================')
    # print(ether.layers())
    # print(dir(ether.payload))

    flow_info = {}
    # print(str(pkt))
    # Check if the packet is a TCP packet
    if pkt.haslayer('TCP'):
        flow_info['time'] = pkt.time  # Timestamp of the packet capture
        flow_info['src_ip'] = pkt[IP].src  # Source IP address
        flow_info['dst_ip'] = pkt[IP].dst  # Destination IP address
        flow_info['src_port'] = pkt[TCP].sport  # Source port number
        flow_info['dst_port'] = pkt[TCP].dport  # Destination port number
        flow_info['flags'] = pkt[TCP].flags  # TCP flags (e.g., SYN, ACK, FIN)
        flow_info['len'] = len(pkt[IP])
    # print(flow_info)
    # print(datetime.fromtimestamp(int(pkt.time.to_integral_value())))
    # if pkt.haslayer('Raw'):  # Assuming the payload is a raw layer
    #     return len(pkt[Raw])
    # print(len(pkt[TCP]))

    # print(pkt.display())

    # display
    # len

    # for i in dir(pkt):
    #     if not i.startswith('_'):
    #         print('=================')
    #         if callable(eval(f'pkt.{i}')):
    #             try:
    #                 print(f'{i}(): {eval(f'pkt.{i}()')}')
    #             except Exception as e:
    #                 print(f'{i}: except:')
    #                 print(e)
    #         else:
    #             print(f'{i}: {eval(f'pkt.{i}')}')


    return flow_info

base_dir = Path()
pcap_file = base_dir.joinpath('test.pcap')

sniff(offline=str(pcap_file), prn=create_flow, count=1, filter='tcp')