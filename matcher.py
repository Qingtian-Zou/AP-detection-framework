import argparse
import os
import pickle
import copy

global tactic_templates
tactic_templates = []
global pool
pool = []
global tactic_instance
tactic_instance = []
FLAGS = None


def read_AP_tactic_templates(templates_dir):
    tactic_id = 0
    for item in os.listdir(templates_dir):
        if item[-7:].lower() != ".pickle":
            continue
        tmp = {}
        tmp['tactic_name'] = item[:-7]
        tmp['tactic_id'] = tactic_id
        fi = open(os.path.join(templates_dir, item), 'rb')
        tmp['tactic_nodes'] = pickle.load(fi)
        fi.close()
        tmp['SOD']={}
        tactic_templates.append(tmp)
        tactic_id += 1


def check_SOD(tactic, node, tech, SOD):
    if 'pre' not in tactic['tactic_nodes'][node].keys():
        # no pre-requisites. directly matching into
        return True
    else:
        # check system object dependency
        tmp_SOD = {}
        i = 1
        for item in tactic['tactic_nodes'][node]['post']:
            tmp_SOD[item] = tech[i][1]
            i += 1
        tmp_SOD.update(tactic['SOD'])
        each_check_result=[]
        for dep in tactic['tactic_nodes'][node]['pre']:
            if "=>" in dep:
                keys=dep.split("=>")
                try:
                    if tmp_SOD[keys[0]]==tmp_SOD[keys[1]]:
                        each_check_result.append(True)
                    else:
                        target_SOD=(('P',tmp_SOD[keys[0]]),('P',tmp_SOD[keys[1]]))
                        if target_SOD in SOD:
                            each_check_result.append(True)
                        else:
                            each_check_result.append(False)
                except KeyError:
                    each_check_result.append(False)
            elif "->" in dep:
                keys=dep.split("->")
                try:
                    if 'F' in keys[0]:
                        target_SOD=(('F',tmp_SOD[keys[0]]),('P',tmp_SOD[keys[1]]))
                    else:
                        target_SOD=(('P',tmp_SOD[keys[0]]),('F',tmp_SOD[keys[1]]))
                    if target_SOD in SOD:
                        each_check_result.append(True)
                    else:
                        each_check_result.append(False)
                except KeyError:
                    each_check_result.append(False)
        return all(each_check_result)

# tactic_templates[0]={
#     'tactic_name': 'more001',
#     'tactic_id': 0,
#     'tactic_nodes': {
#         '1': {'name': 'start', 'choice': [], 'parallel': False, 'qualify': ['2'], 'depend': []},
#         '2': {'name': 'Drive-by-download', 'choice': [], 'parallel': False, 'qualify': ['3'], 'depend': ['1'], 'post': ['P1']},
#         '3': {'name': 'Bypass User Account Control', 'choice': [], 'parallel': False, 'qualify': ['4'], 'depend': ['2'], 'post': ['P2', 'P3'], 'pre': ['P1=>P2']},
#         '4': {'name': 'Credential dumping', 'choice': [], 'parallel': False, 'qualify': ['6'], 'depend': ['3'], 'post': ['P4'], 'pre': ['P3=>P4']},
#         '6': {'name': 'Data exfiltration', 'choice': [], 'parallel': False, 'qualify': ['7'], 'depend': ['4'], 'post': ['P6', 'F1'], 'pre': ['P5=>P6', 'F1->P6']},
#         '7': {'name': 'end', 'choice': [], 'parallel': False, 'qualify': [], 'depend': ['6']}
#         }
#     }


def match_template(tech, SOD):
    # find in templates
    matched_flag=False
    for templ in tactic_templates:
        for node in templ['tactic_nodes']:
            if (templ['tactic_nodes'][node]['name'] in ['start', 'end']) or (templ['tactic_nodes'][node]['matched']):
                continue
            if templ['tactic_nodes'][node]['name'] == tech[0]:
                # ('Drive-by Compromise', ('P', 6844))
                if check_SOD(templ, node, tech, SOD):
                    tmp = copy.deepcopy(templ) # avoid modifying templ
                    info = {}
                    i = 1
                    for item in tmp['tactic_nodes'][node]['post']:
                        info[item] = tech[i][1]
                        i += 1
                    tmp['SOD'] = info
                    tmp['tactic_nodes'][node]['matched']=True
                    if tmp not in tactic_instance:
                        tactic_instance.append(tmp)
                        matched_flag=True
    # add to pool
#    if (not matched_flag) & (tech not in pool):
    pool.append([tech,matched_flag])
    return matched_flag


def match_instance(tech, SOD):
    matched_flag=False
    # find in instances
    for inst in tactic_instance:
        for node in inst['tactic_nodes']:
            if (inst['tactic_nodes'][node]['name'] in ['start', 'end']) or (inst['tactic_nodes'][node]['matched']):
                continue
            if inst['tactic_nodes'][node]['name'] == tech[0]:
                if check_SOD(inst, node, tech, SOD):
                    tmp=copy.deepcopy(inst)
                    info = {}
                    i = 1
                    for item in inst['tactic_nodes'][node]['post']:
                        info[item] = tech[i][1]
                        i += 1
                    tmp['SOD'].update(info)
                    # inst['SOD'].update(info)
                    tmp['tactic_nodes'][node]['matched']=True
                    # inst['tactic_nodes'][node]['matched']=True
                    if tmp not in tactic_instance:
                        tactic_instance.append(tmp)
                        matched_flag=True
    return matched_flag


def count_instances(instances):
    completed = 0
    stat={}
    for inst in instances:
        match_flags = []
        for node in inst['tactic_nodes']:
            if inst['tactic_nodes'][node]['name'] not in ['start', 'end']:
                match_flags.append(inst['tactic_nodes'][node]['matched'])
        if all(match_flags):
            completed += 1
            if inst['tactic_name'] not in stat.keys():
                stat[inst['tactic_name']]=0
            stat[inst['tactic_name']]+=1
            print(inst)
    print("Fully matched instances: %d" % completed)
    print(stat)
    print("Partially matched instances: %d" % (len(instances)-completed))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--templates_dir",
        type=str,
        default="AP_parsers\\parsed_tactic"
    )
    parser.add_argument(
        "--SOD",
        type=str,
        default="multi-multi_SOD.pickle"
    )
    parser.add_argument(
        "--matched",
        type=str,
        default="multi-multi_matched.pickle"
    )
    FLAGS, unparsed = parser.parse_known_args()
    read_AP_tactic_templates(FLAGS.templates_dir)
    f1 = open(FLAGS.matched, 'rb')
    matched = pickle.load(f1)
    f1.close()
    f1 = open(FLAGS.SOD, 'rb')
    SOD = pickle.load(f1)
    f1.close()
    for tech in matched:
        match_template(tech, SOD)
    if len(pool) > 0:
        instance_change_flag=True
        while(instance_change_flag):
            flags=[]
            for tech in pool:
                single_match_flag=match_instance(tech[0], SOD)
                tech[1]=tech[1]|single_match_flag
                flags.append(single_match_flag)
            instance_change_flag=any(flags)
    fi=open("multi-multi_tactic_instances.pickle",'wb')
    pickle.dump(tactic_instance,fi)
    fi.close()
    count_instances(tactic_instance)
    unmatched_pool=[]
    for tech in pool:
        if not tech[1]:
            unmatched_pool.append(tech)
    fi=open('multi-multi_unmatched_pool.pickle','wb')
    pickle.dump(unmatched_pool,fi)
    fi.close()
