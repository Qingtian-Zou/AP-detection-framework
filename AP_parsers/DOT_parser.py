import argparse
import json
import os
import pickle

FLAGS = None

def split_info(line):
    id = line.split('[')[0].strip()
    name = line.split('label=\"')[1].split('\"')[0]
    return id, name


def mark_parallel(step_nodes,k):
    step_nodes[k]['parallel'] = True
    for kk in step_nodes[k]['qualify']:
        if step_nodes[kk]['name'] != 'X':
            step_nodes = mark_parallel(step_nodes,kk)
    return step_nodes


def initialize(AP_dir):
    for fi in os.listdir(AP_dir):
        if fi[-4:].lower() != ".dot":
            continue
        # extract pattern info from dot file
        pattern_file = open(os.path.join(AP_dir, fi), 'r')
        lines = pattern_file.readlines()
        pattern_file.close()
        flag = 0
        # flag: indicates which type of information is being read
        # flag==0: reading graph name
        # flag==1: get graph name, finding nodes
        # flag==1.25: reading nodes info
        # flag==2: got all nodes info, finding dependencies
        # flag==2.5: reading dependencies
        # flag==3: end
        nodes = {}
        step_nodes = {}
        for line in lines:
            if flag == 0 and 'digraph' in line:
                graph_name = line.split(' ')[1]
                flag = 1
                continue
            if flag == 1 and 'nodes' in line:
                flag = 1.25
                continue
            if flag > 1 and flag <= 2:
                if line.strip()=="":
                    flag = 2
                elif (flag == 1.25 and line.strip() != '') or (flag==1.5 and line[0:4]!="\t\t//" and line.strip()!=''):
                    # read node info and constract data structure
                    node_id, node_name = split_info(line)
                    nodes[node_id] = {}
                    nodes[node_id]['name'] = node_name
                    nodes[node_id]['choice'] = []
                    nodes[node_id]['parallel'] = False
                    nodes[node_id]['qualify'] = []
                    nodes[node_id]['depend'] = []
                    flag = 1.5
                elif flag==1.5 and line[0:4] == "\t\t//" and line[-3:] == "//\n":
                    nodes[node_id]['post']=line.strip().strip("/").split(";")
                    flag = 1.25
                elif flag==1.5 and line[0:4]=="\t\t//" and line[-3:]!="//\n":
                    nodes[node_id]['post']=line.strip().strip("/").split(";")
                    flag=1.75
                elif flag==1.75 and line[0:4] == "\t\t//" and line[-3:] == "//\n":
                    nodes[node_id]['pre']=line.strip().strip("/").split(";")
                    flag=1.25
            if flag == 2 and 'edges' in line:
                flag = 2.5
                continue
            if flag == 2.5:
                if line.strip() != '':
                    steps = line.strip().split('->')
                    for i in range(len(steps)):
                        steps[i] = ''.join(
                            ch for ch in steps[i] if ch.isdigit())
                    for i in range(len(steps)-1):
                        nodes[steps[len(steps)-i-1]
                              ]['depend'].append(steps[len(steps)-i-2])
                        nodes[steps[i]]['qualify'].append(steps[i+1])
                else:
                    flag = 3

        # reading finished, now processing
        # Step 01: Remove nodes in data flow.
        for k in nodes:
            if nodes[k]['depend'] == [] and nodes[k]['qualify'] == []:
                continue
            else:
                step_nodes[k] = nodes[k]
        # Step 02: Process nodes of choices
        for k in step_nodes:
            if step_nodes[k]['name'] == 'd':
                for x in step_nodes[k]['qualify']:
                    for y in step_nodes[k]['qualify']:
                        if x != y:
                            step_nodes[x]['choice'].append(y)
        # Step 03: Process nodes of parallel forking
        for k in step_nodes:
            if step_nodes[k]['name'] == '+':
                step_nodes=mark_parallel(step_nodes,k)
        # now all step node data is in step_nodes

        fi = open(os.path.join("AP_parsers", graph_name+".pickle"), 'wb')
        pickle.dump(step_nodes, fi)
        fi.close()


# Codes below are for debugging
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--AP_dir",
        type=str,
        default="..\\codes\\attack-patterns"
    )
    FLAGS, unparsed = parser.parse_known_args()
    initialize(FLAGS.AP_dir)
