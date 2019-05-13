import agate
import argparse
import os
import pprint
import pickle

FLAGS=None

def main():
    i=0
    process_logs={}
    for item in os.listdir(FLAGS.path):
        if item.split(".")[-1] not in ['CSV','csv']:
            continue
        i+=1
        data=agate.Table.from_csv(os.path.join(FLAGS.path,item),encoding='utf-8-sig')
        process_logs[item]=data
    
    fi=open("process_logs.pickle",'wb')
    pickle.dump(process_logs,fi)
    fi.close()
    

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument(
        '--path',
        type=str,
        default=".",
        help="Path to the folder."
    )
    FLAGS,unknon=parser.parse_known_args()
    main()
