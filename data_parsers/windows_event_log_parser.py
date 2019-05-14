import argparse
import os
import csv

def analyze_windows_event_log(path,pipe_conn):
    event_list = []
    fi = open(path, encoding="utf-8-sig")
    reader = csv.reader(fi, delimiter=',')
    n = -1
    for row in reader:
        n += 1
        if n == 0:
            continue  # skip header
        event_list.append((row[3], row[5]))
    fi.close()

    pipe_conn.send((os.path.basename(path),event_list))
