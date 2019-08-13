import argparse
import csv
import io
import os
import pickle

FLAGS = None


def repair_csv(path):
    fi=io.open(path,"r",encoding="utf-8-sig")
    lines=fi.readlines()
    fi.close()
    for line in lines:
        if line.endswith("\n"):
            line.replace("\n","\r\n")
    os.remove(path)
    fi=io.open(path,"w",encoding="utf-8")
    fi.writelines(lines)
    fi.close()


def parse_windows_event_csv(folder):
    event_set = {}
    for item in os.listdir(folder):
        if item[-4:].lower() != ".csv":
            continue
        # repair_csv(os.path.join(folder,item))
        event_set[item] = []
        with io.open(os.path.join(folder, item), "r", newline='', encoding="utf-8-sig") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',', quotechar='\"')
            i = 0
            for row in spamreader:
                if i == 0:
                    ii = row.index("Event ID")
                    jj = len(row)
                else:
                    event_set[item].append((row[ii], row[jj]))
                i += 1
                if i % 1000 == 0:
                    print(i)
        fi = open(item.split(".")[0]+".pickle", 'wb')
        pickle.dump(event_set[item], fi)
        fi.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--log_folder",
        type=str,
        default="windows-event-logs",
        help="path to log directory"
    )
    FLAGS, unparsed = parser.parse_known_args()
    parse_windows_event_csv(FLAGS.log_folder)
