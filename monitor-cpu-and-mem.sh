#!/bin/bash
rm -rf cpu_usage/cpu*
> cpu_usage/cpu.csv

rm -rf mem_usage/mem*
> mem_usage/mem.csv

echo "writing to cpu.csv"
echo "TIME_STAMP, Usage%" | tee -a cpu_usage/cpu.csv

echo "writing to mem.csv"
echo "TIME_STAMP,Memory Usage (MB)" | tee -a mem_usage/mem.csv
total="$(free -m | grep Mem | tr -s ' ' | cut -d ' ' -f 2)"

eval "$1" &
while :
do
    DATE=`date +"%H:%M:%S:%N"`
    echo -n "$DATE, " | tee -a cpu_usage/cpu.csv
    top -c -b -n 1| grep -w "$1" | head -n 1 | tr -s ' ' | cut -d ' ' -f 10 | tee -a cpu_usage/cpu.csv
    echo -n "$DATE, " | tee -a mem_usage/mem.csv
    var="$(top -c -b -n 1| grep -w "$1" | head -n 1 | tr -s ' ' | cut -d ' ' -f 11)"
    echo "scale=3; ($var*$total/100)" | bc | tee -a mem_usage/mem.csv
done

