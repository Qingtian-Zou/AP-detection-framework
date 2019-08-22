import argparse
import os
import io
import csv

FLAGS=None

node_set={
    "start":"\t%d[label=\"start\",shape=box,style=rounded];\n",
    "end":"\t%d[label=\"end\",shape=box,style=rounded];\n",

    "Drive-by Compromise":"\t%d[label=\"Drive-by-download\",shape=box];\n\t\t//Pkkk//\n",
    "Exploit Public-Facing Application":"\t%d[label=\"Exploit Public-Facing Application\",shape=box];\n\t\t//Pkkk//\n",
    "External Remote Services":"\t%d[label=\"External Remote Services\",shape=box];\n\t\t//Pkkk;Skkk//\n",
    "Spearphishing link":"\t%d[label=\"Spearphishing link\",shape=box];\n\t\t//Pkkk//\n",
    
    "Bypass User Account Control":"\t%d[label=\"Bypass User Account Control\",shape=box];\n\t\t//Pkkk;Pkkk\n\t\t//Pkkk=>Pkkk//\n",
    "DLL Search Order Hijacking":"\t%d[label=\"DLL Search Order Hijacking\",shape=box];\n\t\t//Pkkk;Fkkk;Pkkk\n\t\t//Pkkk=>Pkkk;Pkkk->Fkkk;F->Pkkk//\n",
    "New Service":"\t%d[label=\"New service\",shape=box];\n\t\t//Pkkk;Skkk\n\t\t//Pkkk=>Pkkk//\n",
    "Process injection":"\t%d[label=\"Process injection\",shape=box];\n\t\t//Pkkk;Pkkk\n\t\t//Pkkk=>Pkkk//\n",

    "Credential Dumping":"\t%d[label=\"Credential dumping\",shape=box];\n\t\t//Pkkk\n\t\t//Pkkk=>Pkkk//\n",
    "Account Manipulation":"\t%d[label=\"Account manipulation\",shape=box];\n\t\t//Pkkk;Ukkk\n\t\t//Pkkk=>Pkkk//\n",
    "Private Keys":"\t%d[label=\"Private keys\",shape=box];\n\t\t//Pkkk;Ukkk\n\t\t//Pkkk=>Pkkk//\n",

    "Pass the hash":"\t%d[label=\"Pass the hash\",shape=box];\n\t\t//Pkkk;Ukkk//\n",
    "Logon Scripts":"\t%d[label=\"Logon scripts\",shape=box];\n\t\t//Pkkk;Fkkk\n\t\t//Pkkk=>Pkkk//\n",

    "Data exfiltration":"\t%d[label=\"Data exfiltration\",shape=box];\n\t\t//Pkkk;Fkkk\n\t\t//Pkkk=>Pkkk;Fkkk->Pkkk//\n",
    "Data manipulation":"\t%d[label=\"Data manipulation\",shape=box];\n\t\t//Pkkk;Fkkk\n\t\t//Pkkk=>Pkkk;Pkkk->Fkkk//\n",
    "Data destruction":"\t%d[label=\"Data destruction\",shape=box];\n\t\t//Pkkk;Fkkk\n\t\t//Pkkk=>Pkkk;Pkkk->Fkkk//\n",
    "Endpoint denial of service":"\t%d[label=\"Endpoint denial of service\",shape=box];\n\t\t//Pkkk;Skkk\n\t\t//Pkkk=>Pkkk//\n"
}

def load_csv(path):
    tech_list=[[],[],[],[],[]]
    with io.open(path, newline='', encoding="utf-8-sig") as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='\"')
        for row in spamreader:
            for i in range(len(row)):
                if row[i]!='':
                    tech_list[i].append(row[i])
    for i in range(len(tech_list)):
        del tech_list[i][0]
    return tech_list

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument(
        "--csv",
        type=str,
        default="more patterns.csv",
        help="path to pattern csv file"
    )
    FLAGS,unparsed=parser.parse_known_args()
    data=load_csv(FLAGS.csv)
    tactic_id=0
    for i1 in range(len(data[0])):
        for i2 in range(len(data[1])):
            for i3 in range(len(data[2])):
                for i4 in range(len(data[3])):
                    for i5 in range(len(data[4])):
                        tactic_id+=1
                        lines=[]
                        lines.append(str("diagraph more%.3d {\n"%tactic_id))
                        lines.append(str("\t// nodes\n"))
                        lines.append(str(node_set["start"]%1))
                        lines.append(str(node_set[data[0][i1]]%2))
                        lines.append(str(node_set[data[1][i2]]%3))
                        lines.append(str(node_set[data[2][i3]]%4))
                        lines.append(str(node_set[data[3][i4]]%5))
                        lines.append(str(node_set[data[4][i5]]%6))
                        lines.append(str(node_set["end"]%7))
                        lines.append("\n")
                        lines.append("\t// edges\n\t1->2->3->4->5->6->7\n}\n")
                        fi=open(str("new/more%.3d.dot"%tactic_id),"w")
                        fi.writelines(lines)
                        fi.close()
