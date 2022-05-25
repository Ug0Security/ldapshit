cat mails | while read line
do 
echo $line:$(echo $line | cut -d "@" -f 1)
done
