import agate
import os

def analyze_process_log(path,pipe_conn):
    process_logs={}
    data=agate.Table.from_csv(path,encoding='utf-8-sig')

    pipe_conn.send((os.path.basename(path),data))
