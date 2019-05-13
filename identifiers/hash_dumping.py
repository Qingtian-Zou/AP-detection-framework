import agate
import pickle

def main(process_logs):
    for item in process_logs:
        indicator=0
        # indicator:
        # 0 -> benign
        # 1 -> a lsass.exe thread is reading ntds.dit
        # 2 -> the thread is recently created, and exits shortly after reading
        if ("lsass.exe","ReadFile","C:\\Windows\\NTDS\\ntds.dit","SUCCESS") in zip(process_logs[item].columns['Process Name'],process_logs[item].columns['Operation'],process_logs[item].columns['Path'],process_logs[item].columns['Result']):
            indices1= [i for i, x in enumerate(zip(process_logs[item].columns['Process Name'],process_logs[item].columns['Operation'],process_logs[item].columns['Path'],process_logs[item].columns['Result'])) if x == ("lsass.exe","ReadFile","C:\\Windows\\NTDS\\ntds.dit","SUCCESS")]
            lsass_TID_set=set()
            for index in indices1:
                lsass_TID_set.add(int(process_logs[item].rows[index]['TID']))
            indicator=1
        if indicator==1:
            if ("Thread Create","SUCCESS") in zip(process_logs[item].columns['Operation'],process_logs[item].columns['Result']):
                indices2=[]
                tmp=[i for i, x in enumerate(zip(process_logs[item].columns['Operation'],process_logs[item].columns['Result'])) if x == ("Thread Create","SUCCESS")]
                for TID in lsass_TID_set:
                    for x in tmp:
                        if str(TID) in process_logs[item].rows[x]["Detail"]:
                            indices2.append(x)
            if ("Thread Exit","SUCCESS") in zip(process_logs[item].columns['Operation'],process_logs[item].columns['Result']):
                indices3=[]
                tmp=[i for i, x in enumerate(zip(process_logs[item].columns['Operation'],process_logs[item].columns['Result'])) if x == ("Thread Exit","SUCCESS")]
                for TID in lsass_TID_set:
                    for x in tmp:
                        if str(TID) in process_logs[item].rows[x]["Detail"]:
                            indices3.append(x)
            if all([len(indices1)!=0,len(indices2)!=0,len(indices3)!=0]):
                for index in indices1:
                    tmp_range=range(index-10,index+11)
                    for x in indices2:
                        if x in tmp_range:
                            for y in indices3:
                                if y in tmp_range:
                                    indicator=2
        if indicator==2:
            print("Hash dumping detected in log file: "+item)
            print("Suspicious domain account database reading found at indices: "+str(indices1))
        else:
            print("Hash dumping not detected in log file: "+item)
        print()

if __name__=="__main__":
    fi=open('process_logs.pickle','rb')
    process_logs=pickle.load(fi)
    fi.close()
    main(process_logs)
