import os
import pickle
import pprint

import numpy as np
import pyshark
from multiprocessing import Pipe

def analyze_net_log(path,pipe_conn):
    pp = pprint.PrettyPrinter(indent=4)

    # Step 1: read log file and extract values in useful fields
    network_logs = {}
    cap = pyshark.FileCapture(path,
        display_filter="(smb or smb2) and (not tcp.analysis.spurious_retransmission)")
    j = 0
    start = []
    failings = []
    packets = []
    try:
        while(True):
            pkt = cap.next()
            if 'smb' in dir(pkt):
                layer = 'smb'
            else:
                layer = 'smb2'
            cmd = pkt.__getattr__(layer).get_field_value('cmd')
            flags = pkt.__getattr__(layer).get_field_value('flags')
            try:
                nt_status = pkt.__getattr__(
                    layer).get_field_value('nt_status')
            except AttributeError:
                nt_status = None
            packets.append((cmd, flags, nt_status))
            found_start = False
            if "smb" in dir(pkt):
                if pkt.smb.cmd == str(int(b'72', 16)) and (not 'analysis_spurious_retransmission' in dir(pkt.tcp)):
                    start.append(j)
                    found_start = True
            if 'smb2' in dir(pkt):
                try:
                    if pkt.smb2.cmd == '0' and pkt.smb2.flags == '0x00000000' and (not found_start):
                        start.append(j)
                    elif pkt.smb2.nt_status == str(int('c00000bb', 16)):
                        failings.append(j)
                except:
                    pass
            j += 1
            if j % 500 == 0:
                print(j)
    except StopIteration:
        print("Read "+str(len(packets))+" packets in "+os.path.basename(path))

    cap.close()

    k = 0
    slots = []
    for ii in range(len(start)-1):
        if len(failings) == 0:
            break
        if failings[k] in range(start[ii], start[ii+1]):
            k += 1
            slots.append(range(start[ii], start[ii+1]))
            if k >= len(failings):
                break
    if len(slots) != 0:
        for ii in range(1, len(slots)+1):
            print("deleting packets from:")
            print(packets[slots[-ii].start])
            print("to:")
            print(packets[slots[-ii].stop])
            del(packets[slots[-ii].start:slots[-ii].stop])

    network_logs[os.path.basename(path)] = packets

    # Step 2: verify the existence of previous packets dictionary, then load/build the dictionary
    try:
        fi = open("packet.dict", 'rb')
    except FileNotFoundError as err1:
        pkt_dict = set()
        print(err1)
        print("dictionary not found, create a new one...")
        fi = open("packet.dict", 'wb')
        for item in network_logs:
            pkts = network_logs[item]
            ii = len(pkts)
            for pkt in pkts:
                pkt_dict.add(tuple(pkt))
                if ii % 2000 == 0:
                    print("remain: "+str(ii))
        pickle.dump(pkt_dict, fi)
        fi.close()
        fi = open("packet.dict", 'rb')

    # Step 3: convert every entry read into numbers according to the dictionary
    dict_list = list(pickle.load(fi))
    fi.close()
    seq = []
    pkts = network_logs[os.path.basename(path)]
    ii = len(pkts)
    for pkt in pkts:
        pkt = tuple(pkt)
        try:
            seq[item].append(dict_list.index(pkt))
        except ValueError as err2:
            print(err2)
            dict_list.append(pkt)
            pkt_dict = set(dict_list)
            fi = open("packet.dict", 'wb')
            pickle.dump(pkt_dict, fi)
            fi.close()
            dict_list = list(pkt_dict)
            seq[item].append(dict_list.index(pkt))
        if ii % 2000 == 0:
            print("remain: "+str(ii))

    pp.pprint(seq)
    pipe_conn.send((os.path.basename(path),seq))
