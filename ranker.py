import argparse
import os
import pickle
from operator import itemgetter
import psutil

FLAGS = None

global scoring
scoring={
    'Drive-by-download':5.3,
    "Exploit Public-Facing Application":3.7,
    "External Remote Services":3.7,
    "Spearphishing link":3.1,

    "Bypass User Account Control":5.8,
    "DLL Search Order Hijacking":9.2,
    "New service":9.2,
    "Process injection":8.5,

    "Credential dumping":6.8,
    "Account manipulation":6.0,
    "Private keys":5.8,

    "Pass the hash":4.8,
    "Logon scripts":3.2,

    "Data exfiltration":5.0,
    "Data manipulation":6.4,
    "Data destruction":6.1,
    "Endpoint denial of service":5.9
}

def calc_scores(instances,pool_stat):
    for inst in instances:
        inst['score']=1
        for node in inst['tactic_nodes']:
            try:
                if inst['tactic_nodes'][node]['name'] in ['start','end']:
                    continue
                elif inst['tactic_nodes'][node]['matched']:
                    inst['score']*=scoring[inst['tactic_nodes'][node]['name']]
                else:
                    inst['score']*=(scoring[inst['tactic_nodes'][node]['name']]*(pool_stat[inst['tactic_nodes'][node]['name']]/sum(pool_stat.values())))
            except KeyError:
                inst['score']=0
    return instances


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--tactic_instance',
        type=str,
        default='multi-multi_tactic_instances.pickle',
        help='path to tactic instances'
    )
    parser.add_argument(
        '--unmatched_pool',
        type=str,
        default='multi-multi_unmatched_pool.pickle',
        help="path to unmatched technique pool"
    )
    FLAGS, unparsed = parser.parse_known_args()
    fi = open(FLAGS.tactic_instance, 'rb')
    instances = pickle.load(fi)
    fi.close()
    fi = open(FLAGS.unmatched_pool, 'rb')
    pool = pickle.load(fi)
    fi.close()
    pool_stat={}
    for tech in pool:
        if tech[0] not in pool_stat.keys():
            pool_stat[tech[0]]=0
        pool_stat[tech[0]]+=1
    instances=calc_scores(instances,pool_stat)
    sorted_instances = sorted(instances, key=itemgetter('score'), reverse=True)
    for i in range(min([100,len(sorted_instances)])):
        print(sorted_instances[i])
    process = psutil.Process(os.getpid())
    print(process.memory_info().rss)  # in bytes 
