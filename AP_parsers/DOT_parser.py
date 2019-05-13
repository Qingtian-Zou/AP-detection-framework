import argparse
from multiprocessing import Pipe
import json
import os
import pprint

global step_nodes
step_nodes = {}
FLAGS = None


def split_info(line):
    id = line.split('[')[0].strip()
    name = line.split('label=\"')[1].split('\"')[0]
    return id, name


def mark_parallel(k):
    step_nodes[k]['parallel'] = True
    for kk in step_nodes[k]['qualify']:
        if step_nodes[kk]['name'] != 'X':
            mark_parallel(kk)
    return


def initialize(path,pipe_conn):
    pp = pprint.PrettyPrinter(indent=4)
    graphs={}
    # extract pattern info from dot file
    step_nodes = {}
    pattern_file = open(path, 'r')
    lines = pattern_file.readlines()
    pattern_file.close()
    flag = 0
    # flag: indicates which type of information is being read
    # flag==0: reading graph name
    # flag==1: get graph name, finding nodes
    # flag==1.5: reading nodes info
    # flag==2: got all nodes info, finding dependencies
    # flag==2.5: reading dependencies
    # flag==3: end
    nodes = {}
    for line in lines:
        if flag == 0 and 'digraph' in line:
            graph_name = line.split(' ')[1]
            flag = 1
            continue
        if flag == 1 and 'nodes' in line:
            flag = 1.5
            continue
        if flag == 1.5:
            if line.strip() != '':
                # read node info and constract data structure
                node_id, node_name = split_info(line)
                nodes[node_id] = {}
                nodes[node_id]['name'] = node_name
                nodes[node_id]['choice'] = []
                nodes[node_id]['parallel'] = False
                nodes[node_id]['qualify'] = []
                nodes[node_id]['depend'] = []
            else:
                flag = 2
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
            mark_parallel(k)
    # now all step node data is in step_nodes

    pp.pprint(step_nodes)
    pipe_conn.send((graph_name,step_nodes))
