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
            src_addr = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
            dst_addr = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)
            key = (src_addr, dst_addr, 'UDP')
            rev_key = (dst_addr, src_addr, 'UDP')
            if key in flows:
                flows[key].append(pkt)
            elif rev_key in flows:
                flows[rev_key].append(pkt)
            else:
                flows[key] = [pkt]
        elif pkt.haslayer('TCP'):
            src_addr = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
            dst_addr = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
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

s = sniff(offline=str(pcap_file), prn=create_flow)



for key, val in flows.copy().items():
    if len(val) <= 2 and key[2] == 'TCP':  # TCP handshake
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
                key.append(str(val[previous_index].time.to_integral_value()))
                key = tuple(key)
                flows[key] = val[previous_index:i]
                previous_index = i
                key = list(key)
                key.append(str(pkt.time.to_integral_value()))
                key = tuple(key)
                flows[key] = val[i:]
            previous = pkt

flow_list = []
total_time = 0
total_bytes = 0
ip_list = []

for key, val in flows.copy().items():
    if len(val) <= 2 and key[2] == 'TCP':  # TCP handshake
        flows.pop(key)
    elif len(key) == 3:  # filtering rare connections
        flows.pop(key)
    else:
        packets_bytes = 0
        for pkt in val:
            packets_bytes += len(pkt)
        first_pkt_time = datetime.fromtimestamp(int(val[0].time.to_integral_value()))
        last_pkt_time = datetime.fromtimestamp(int(val[-1].time.to_integral_value()))
        diff_time = last_pkt_time - first_pkt_time
        flow_time = diff_time.total_seconds()
        total_time += flow_time
        total_bytes += packets_bytes
        flow_data = {
            'src_ip': key[0].split(':')[0],
            'src_port': key[0].split(':')[-1],
            'dst_ip': key[1].split(':')[0],
            'dst_port': key[1].split(':')[-1],
            'proto': key[2],
            'first_pkt_timestamp': int(val[0].time.to_integral_value()),
            'last_pkt_timestamp': int(val[-1].time.to_integral_value()),
            'packets_bytes': packets_bytes,
            'flow_time': flow_time,
            # 'packets': val
        }
        ip_list.append(key[0].split(':')[0])
        ip_list.append(key[1].split(':')[-1])
        flow_list.append(flow_data)

average_time = total_time / len(flow_list)
average_bytes = total_bytes / len(flow_list)

for flow in flow_list.copy():  # filtering flows by bytes and time
    if flow['packets_bytes'] > average_bytes or flow['flow_time'] > average_time:
        flow_list.remove(flow)
    elif ip_list.count(flow['src_ip']) <= 1 and ip_list.count(flow['dst_ip']) <= 1:  # filtering flows that has no
        # common ip with other flows
        flow_list.remove(flow)


flow_list.sort(key=lambda x: x['first_pkt_timestamp'])

dependent_flows = []
for i in range(len(flow_list)):
    for j in range(i, len(flow_list)):
        first_flow_ips = {flow_list[i]['src_ip'], flow_list[i]['dst_ip']}
        second_flow_ips = {flow_list[j]['src_ip'], flow_list[j]['dst_ip']}
        if (flow_list[j]['first_pkt_timestamp'] == flow_list[i]['last_pkt_timestamp'] and
                flow_list[i]['proto'] == flow_list[j]['proto']) and first_flow_ips.intersection(second_flow_ips):
            dependent_flows.append((flow_list[i], flow_list[j]))

l = []
for i in dependent_flows.copy():
    i[0].pop('packets', 1)
    i[1].pop('packets', 1)
    try:
        date = str(datetime.fromtimestamp(i[0]['first_pkt_timestamp']))
        i[0]['first_pkt_timestamp'] = date
    except:...
    try:
        date = str(datetime.fromtimestamp(i[0]['last_pkt_timestamp']))
        i[0]['last_pkt_timestamp'] = date
    except:
        ...
    try:
        date = str(datetime.fromtimestamp(i[-1]['first_pkt_timestamp']))
        i[1]['first_pkt_timestamp'] = date
    except:
        ...
    try:
        date = str(datetime.fromtimestamp(i[-1]['last_pkt_timestamp']))
        i[1]['last_pkt_timestamp'] = date
    except:
        ...
    l.append(i)

import json

with open('res.json', 'w') as f:
    json.dump(l, f)

# print(flows)



#tcp con lost del
#udp loc ip loc port rem ip rem port protocol -> udp flow
# tuple start time end time difrence time pkt count in flow totall bite



