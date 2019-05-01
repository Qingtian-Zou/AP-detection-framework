import os
import csv
import pickle

event_ids=["1116"]
event_des=["Trojan:Win64/Meterpreter","Trojan:Win32/Meterpreter"]

# Module input: event_list from windows-event-log-parser.py

def main(event_list):
    for f in event_list:
        found=[]
        n=0
        for row in event_list[f]:
            n+=1
            if any(row[0]==id for id in event_ids) and any(des in row[1] for des in event_des) :
                found.append(n)
        print("##################################")
        print("%d rows processed in file: %s"%(n,f))
        if len(found)>0:
            print("Found initial intrusion by meterpreter at: %s!"%str(found))
        else:
            print("Not found initial intrusion by meterpreter.")
        print()

if __name__=="__main__":
    fi=open('tmp.txt','rb')
    event_list=pickle.load(fi)
    fi.close()
    main(event_list)
