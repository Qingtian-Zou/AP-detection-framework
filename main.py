import sys
import os
import argparse
from multiprocessing import Process, Pipe
from AP_parsers import *
from data_parsers import *
from identifiers import *

FLAGS=None

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument(
        "--APs",
        type=str,
        default=".",
        help="path to the attack pattern folder"
    )
    parser.add_argument(
        "--net_logs",
        type=str,
        default=".",
        help="path to the network log folder"
    )
    parser.add_argument(
        "--proc_logs",
        type=str,
        default=".",
        help="path to the process monitor log folder"
    )
    parser.add_argument(
        "--win_logs",
        type=str,
        default=".",
        help="path to the Windows event log folder"
    )
    FLAGS,unparsed=parser.parse_known_args()
    data_parsing_jobs=[]
    identification_jobs=[]

    # TODO: for each folder above, the framework should:
    # 1) go through all the files in it and parse related files to parsers or other components.
    tmp={}
    for item in os.listdir(FLAGS.net_logs):
        if item.split(".")[-1] not in ["pcapng", "pcap"]:
            continue
        parent_conn, child_conn = Pipe()
        p=Process(target=network_log_parser.analyze_net_log,args=(os.path.join(FLAGS.net_logs,item),child_conn,))
        p.start()
        tmp[p]=parent_conn
    pkts={}
    for p in tmp:
        rec=tmp[p].recv()
        pkts[rec[0]]=rec[1]
        p.join()
    # 2) create a watchdog monitor to monitor changes. New task should be scheduled if new log/AP files are put in, or files are updated.
