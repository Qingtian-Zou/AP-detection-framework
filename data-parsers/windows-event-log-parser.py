import argparse
import os
import csv
import pprint

FLAGS=None

def main():
    pp = pprint.PrettyPrinter(indent=4)
    file_list=os.listdir(FLAGS.path)
    for f in file_list:
        if f.split(".")[-1]!="csv":
            continue
        fi=open(os.path.join(FLAGS.path,f),encoding="utf-8-sig")
        reader=csv.reader(fi,delimiter=',')
        n=-1
        event_list=[]
        for row in reader:
            n+=1
            if n==0:
                continue # skip header
            event_list.append((row[3],row[5]))
        fi.close()
        pp.pprint(event_list)

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="path to the log folder"
    )
    FLAGS,unparsed=parser.parse_known_args()
    main()
