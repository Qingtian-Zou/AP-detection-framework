import os
import argparse

FLAGS=None

def main():
    pass

if __name__=="__main__":
    parser=argparse.ArgumentParser()
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
    parser.add_argument(
        "--APs",
        type=str,
        default=".",
        help="path to the attack pattern folder"
    )
    FLAGS,unparsed=parser.parse_known_args()
    main()
