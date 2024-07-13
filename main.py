from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP, UDP
from pathlib import Path
from datetime import datetime
import json



flows = {}



def create_flow(pkt: Ether):
    if pkt.haslayer('IP'):
        if pkt.haslayer('UDP'):
            src_addr = str(pkt[IP].src) + str(pkt[UDP].sport)
            dst_addr = str(pkt[IP].dst) + str(pkt[UDP].dport)
            key = (src_addr, dst_addr, 'UDP')
            rev_key = (dst_addr, src_addr, 'UDP')
            if key in flows:
                flows[key].append(pkt)
            elif rev_key in flows:
                flows[rev_key].append(pkt)
            else:
                flows[key] = [pkt]
        elif pkt.haslayer('TCP'):
            src_addr = str(pkt[IP].src) + str(pkt[TCP].sport)
            dst_addr = str(pkt[IP].dst) + str(pkt[TCP].dport)
            key = (src_addr, dst_addr, 'TCP')
            rev_key = (dst_addr, src_addr, 'UDP')
            if key in flows:
                flows[key].append(pkt)
            elif rev_key in flows:
                flows[rev_key].append(pkt)
            else:
                flows[key] = [pkt]



base_dir = Path()
pcap_file = base_dir.joinpath('test.pcap')

s = sniff(offline=str(pcap_file), prn=create_flow, count=10000)




for key, val in flows.copy().items():
    if len(val) <= 2 and key[2] == 'TCP':  # TCP hand shake
        flows.pop(key)
    else:
        val.sort(key=lambda x: x.time)
        previous_index = 0
        previous = val[0]
        for pkt in val[1:]:
            if previous.haslayer('IP') and pkt.time - previous.time > previous[IP].ttl:
                i = val.index(pkt)
                flows.pop(key)
                key = list(key)
                key.append(int(val[previous_index].time.to_integral_value()))
                key = tuple(key)
                flows[key] = val[previous_index:i]
                previous_index = i
                key = list(key)
                key.append(int(pkt.time.to_integral_value()))
                key = tuple(key)
                flows[key] = val[i:]
            previous = pkt

flows2 = {}
max_c = 0
for key, val in flows.copy().items():
    pkts = []
    for pkt in val:
        pkts.append(str(datetime.fromtimestamp(int(pkt.time.to_integral_value()))))
    flows2[str(key)] = pkts
    if len(val) > max_c:
        max_c = len(val)

with open('res.json', 'w') as f:
    json.dump(flows2, f)


# print(flows)
print(len(flows), max_c)



#tcp con lost del
#udp loc ip loc port rem ip rem port protocol -> udp flow
# tuple start time end time difrence time pkt count in flow totall bite



