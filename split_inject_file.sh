#!/bin/bash

inject_file=/etc/vmse/init/alm_inject_files.ini
if [ ! -f ${inject_file} ]
then
	exit 0
fi
number=`grep -n "file_to" $inject_file | cut -d ":" -f 1`

numberArr=(${number//\\n/ })

fileList=`cat $inject_file | grep file_to: | awk -F ":" '{print $2}'`
fileListArr=(${fileList//\\n/ })
arrLength=${#fileListArr[@]}
n=0
index=0
for x in $fileList
do
file_path=`dirname $x`
mkdir -p $file_path
let startNu=${numberArr[$n]}+1
let lastFile=$n+1
if [ $lastFile -eq $arrLength ]
then
	sed -n "${startNu},99999p" ${inject_file}>${fileListArr[$n]}
else
	let index=$n+1
	let endNu=${numberArr[$index]}-1
	sed -n "${startNu},${endNu}p" ${inject_file}>${fileListArr[$n]}
fi
let n++
done
rm -rf ${inject_file}
