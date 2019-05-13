import agate
import pickle

signature=["RegCreateKey","HKCU\\Software\\Classes\\mscfile\\shell\\open\\command","SUCCESS",("Write","REG_CREATED_NEW_KEY")]

def main(process_logs):
    for item in process_logs:
        data=zip(process_logs[item].columns["Operation"],process_logs[item].columns["Path"],process_logs[item].columns["Result"],process_logs[item].columns["Detail"])
        for entry in data:
            if tuple(signature[0:-1])==entry[0:-1]:
                if all(x in entry[-1] for x in signature[-1]):
                    print("Detected privilege escalation in "+item+".")


if __name__=="__main__":
    fi=open("process_logs.pickle","rb")
    process_logs=pickle.load(fi)
    fi.close()
    main(process_logs)
