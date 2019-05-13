import argparse
import os
import csv
import pickle

FLAGS = None


def main():
    file_list = os.listdir(FLAGS.path)
    event_list = {}
    for f in file_list:
        if f.split(".")[-1] != "csv":
            continue
        event_list[f] = []
        fi = open(os.path.join(FLAGS.path, f), encoding="utf-8-sig")
        reader = csv.reader(fi, delimiter=',')
        n = -1
        for row in reader:
            n += 1
            if n == 0:
                continue  # skip header
            event_list[f].append((row[3], row[5]))
        fi.close()
    fi=open('tmp.pickle','wb')
    pickle.dump(event_list,fi)
    fi.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="path to the log folder"
    )
    FLAGS, unparsed = parser.parse_known_args()
    main()
