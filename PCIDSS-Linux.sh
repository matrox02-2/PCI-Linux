#!/bin/sh
#This Script is written to retrieve information for the purposes of PCI DSS Standard's Compliance
#Author: Matthew Hanson and Dimpal
# Purpose: Determine if current user is root or not
is_root_user() {
 [ $(id -u) -eq 0 ]
}

# invoke the function
# make decision using conditional logical operators
is_root_user && echo "You can run this script." || echo "You need to run this script as a root user."

echo "Please wait, this may take some time"
echo "Getting System info"
echo "|=--------------------------=[SYSTEM INFORMATION]=---------------------------=|" >> $HOSTNAME-SystemInfo.txt
sudo hostnamectl >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Kernel Name" >> $HOSTNAME-SystemInfo.txt
sudo uname -s >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Kernel Version" >> $HOSTNAME-SystemInfo.txt
sudo uname -v >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Kernel Release" >> $HOSTNAME-SystemInfo.txt
sudo uname -r >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Host Name" >> $HOSTNAME-SystemInfo.txt
echo $HOSTNAME >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Node Name" >> $HOSTNAME-SystemInfo.txt
sudo uname -n >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Operating System" >> $HOSTNAME-SystemInfo.txt
sudo uname -o >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Processor" >> $HOSTNAME-SystemInfo.txt
sudo uname -p >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Hardware Platform" >> $HOSTNAME-SystemInfo.txt
sudo uname -i >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Machine Name" >> $HOSTNAME-SystemInfo.txt
sudo uname -m >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Hardware" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo lshw -short >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Network Information" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo ifconfig >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "" >> $HOSTNAME-SystemInfo.txt
echo "|=----------------------=[ACTIVE DIRECTORY STATUS]=--------------------------=|" >> $HOSTNAME-SystemInfo.txt

dom0=`realm list domain-name -n`
if [ "$dom0" = "" ]
then
    echo "No Domain Set/Joined $dom0 " >> $HOSTNAME-SystemInfo.txt
else
    echo "The domain is set to : $dom0 " >> $HOSTNAME-SystemInfo.txt
fi

echo "Getting Requirement 1"
echo "|=----------------=[FIREWALL - SERVICE STATUS]=---------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.4                                                 =|" >>   $HOSTNAME-Requirement-1.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
sudo service firewalld status >> $HOSTNAME-Requirement-1.txt


echo "|=------------------=[FIREWALL CONFIGURATION]=----------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.4                                                 =|" >>   $HOSTNAME-Requirement-1.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "########## INPUT rules ###########" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L INPUT >> $HOSTNAME-Requirement-1.txt
echo "########## OUTPUT rules ###########" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L OUTPUT >> $HOSTNAME-Requirement-1.txt
echo "########## FORWARD rules ###########" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L FORWARD >>   $HOSTNAME-Requirement-1.txt


echo "|=-----------------------=[USER ACCOUNTS]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related Requirements: 2.1                                                =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
cat /etc/passwd >>   $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[USER ACCOUNTS]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related Requirements: 2.1                                                =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
cat /etc/group >>  $HOSTNAME-Requirement-2.txt

echo "Getting Requirement 2"
echo "|=-------------------------=[INSTALLED SOFTWARE]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo apt list --installed >> $HOSTNAME-Requirement-2.txt  2> /dev/null|| sudo rpm -qa >> $HOSTNAME-Requirement-2.txt 2> /dev/null|| sudo dpkg-query >> $HOSTNAME-Requirement-2.txt 2> /dev/null||sudo yum list installed >> $HOSTNAME-Requirement-2.txt2> /dev/null || sudo pacman -Q >> $HOSTNAME-Requirement-2.txt 2> /dev/null


echo "|=------------------------=[SERVICES RUNNING]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo systemctl --state=running || netstat -tupln >> $HOSTNAME-Requirement-2.txt


echo "|=------------------------=[PROCESSES RUNNING]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo ps -ef >>   $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[PORTS IN LISTENING STATE]=------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo lsof -i -P -n | grep LISTEN >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[NETWORK CONNECTION]=-----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo netstate -a >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[NETWORK INTERFACES]=-----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo ip link show >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[KERNAL ROUTE TABLE]=-----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo netstate -r >> $HOSTNAME-Requirement-2.txt

echo "|=---------------------------=[IPv6 SUPPORT]=--------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
ipv6=`ifconfig|grep inet6`
if [ ! "$ipv6" ] 
then
	echo "IPv6 Disabled!" >> $HOSTNAME-Requirement-2.txt
else
	echo "IPv6 Enabled! ::" >> $HOSTNAME-Requirement-2.txt
	echo $ipv6 >> $HOSTNAME-Requirement-2.txt
fi

echo "|=------------------=[MISCELLANEOUS SECURITY SETTINGS]=----------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.4                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Please compare current values with your Security Configuration Standard   =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "--[ Accounts: Root account status ]" >>   $HOSTNAME-Requirement-2.txt 
rootpass=`sudo grep root /etc/shadow`
if [ ! "$rootpass" ]
then
	echo "Account Not found!" >>   $HOSTNAME-Requirement-2.txt
else
	case "$rootpass" in 
		*!*) echo "Account Disabled/Locked" >>   $HOSTNAME-Requirement-2.txt ;;
		* ) echo "Account Active" >>   $HOSTNAME-Requirement-2.txt ;;
	esac
fi
if [ ! "$rootpass" ]
then 
	chage -l root >>   $HOSTNAME-Requirement-2.txt
fi


echo "--[ Accounts: Guest account status ]" >>   $HOSTNAME-Requirement-2.txt 
guest1=`sudo cat /etc/passwd |grep -i "guest"`
if [ ! "$guest1" ]
then
	echo "No Guest accounts found" >>   $HOSTNAME-Requirement-2.txt 
else
	echo "Guest account exists as $guest1 " >>   $HOSTNAME-Requirement-2.txt 
fi

echo "--[ Interactive logon: Prompt user to change password before expiration ]" >>   $HOSTNAME-Requirement-2.txt 
echo "checks /etc/login.defs for expiry warning configuration" >>   $HOSTNAME-Requirement-2.txt 
sudo grep PASS_WARN_AGE /etc/login.defs >>    $HOSTNAME-Requirement-2.txt 

echo "--[ Interactive logon: Message text for users attempting to log on ]" >>   $HOSTNAME-Requirement-2.txt 
echo "checks /etc/motd" >>   $HOSTNAME-Requirement-2.txt
sudo cat /etc/motd >>   $HOSTNAME-Requirement-2.txt
echo "" >>   $HOSTNAME-Requirement-2.txt
echo "checks /etc/sshd for banner" >>   $HOSTNAME-Requirement-2.txt
sudo cat /etc/ssh/sshd_config  | grep Banner >>   $HOSTNAME-Requirement-2.txt
echo "" >>   $HOSTNAME-Requirement-2.txt

#echo "--[ System cryptography: Force strong key protection for user keys stored on the computer ]" >>   $HOSTNAME-Requirement-2.txt 

echo "|=----------------------------=[LOCAL DRIVES]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo lshw -class disk  >>   $HOSTNAME-Requirement-2.txt 

echo "|=--------------------------=[PACKAGES INSTALLED]=---------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo apt list --installed >> $HOSTNAME-Requirement-2.txt  2> /dev/null|| sudo rpm -qa >> $HOSTNAME-Requirement-2.txt 2> /dev/null|| sudo dpkg-query >> $HOSTNAME-Requirement-2.txt 2> /dev/null||sudo yum list installed >> $HOSTNAME-Requirement-2.txt2> /dev/null || sudo pacman -Q >> $HOSTNAME-Requirement-2.txt 2> /dev/null

echo "|=--------------------------=[DRIVERS INSTALLED]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
find /lib/modules/$(uname -r)/kernel/ -name '*.ko*' >> $HOSTNAME-Requirement-2.txt

echo "|=----------------------------=[USB DRIVE]=----------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
sudo lsmod | grep usb_storage  >> $HOSTNAME-Requirement-2.txt
sudo ls /lib/modules/`uname -r`/kernel/drivers/usb/storage  >>   $HOSTNAME-Requirement-2.txt

echo "|=--------------------------=[SHARED FOLDERS]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
#echo "|= Related requirements: 2.2.5                                           	=|" >>   #$HOSTNAME-Requirement-2.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt

smbvar=`sudo smbstatus --shares`
if [ ! ”$smbvar” ]
then
	echo “SMB Service Not installed/ No shares found”
else
	echo “ SMB Shares are as Follows : $smbvar”
fi

echo "|=----------------------=[ENCRYPTION METHOD FOR PASSWORD]=--------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo “Getting encryption method used for password for all non console(remote) ssh access ” >> $HOSTNAME-Requirement-2.txt
sudo cat /etc/login.defs | grep ENCRYPT_METHOD >>$HOSTNAME-Requirement-2.txt

echo "|=----------------------=[TELNET SERVICE STATUS]=-----------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo “Making sure all insecure non console access(telnet) is diabled or stopped” >> $HOSTNAME-Requirement-2.txt
systemctl is-enabled telnet.socket >>$HOSTNAME-Requirement-2.txt
netstat -lataupen | grep telnet >>$HOSTNAME-Requirement-2.txt
ps -ef | grep telnet >> $HOSTNAME-Requirement-2.txt


echo "|=----------------------=[RSH SERVICE STATUS]=--------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo “Making sure all insecure non console access(rsh) is diabled or stopped ” >> $HOSTNAME-Requirement-2.txt
systemctl is-enabled rsh.socket >>$HOSTNAME-Requirement-2.txt
systemctl is-enabled rlogin.socket >>$HOSTNAME-Requirement-2.txt
systemctl is-enabled rexec.socket >>$HOSTNAME-Requirement-2.txt
netstat -na | grep 514 >>$HOSTNAME-Requirement-2.txt
ps -ef | grep rsh >>$HOSTNAME-Requirement-2.txt


echo "Getting Requirement 4" 
echo "|=----------------------=[TLS VERSIONS]=-----------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "|= Related requirements: 4.1                                                 =|" >>   $HOSTNAME-Requirement-4.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "Check for TLS1.2 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo openssl s_client -connect google.com:443 -tls1_2  2>/dev/null >>   $HOSTNAME-Requirement-4.txt 

echo "Check for TLS1.1 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo openssl s_client -connect google.com:443 -tls1_1  2>/dev/null >>   $HOSTNAME-Requirement-4.txt 

echo "Check for TLS1.0 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo openssl s_client -connect google.com:443 -tls1  2>/dev/null >>   $HOSTNAME-Requirement-4.txt 


echo "Getting Requirement 6"
echo "|=------------------------------=[OS VERSION]=--------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.2                                                  =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
hostnamectl |grep "Operating System:*" >>   $HOSTNAME-Requirement-6.txt 
hostnamectl |grep "Kernel:*" >>   $HOSTNAME-Requirement-6.txt 



echo "|=--------------------------=[OS UPDATES - SOURCES]=--------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.2                                                  =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
sudo dnf repolist all 2>/dev/null >> $HOSTNAME-Requirement-6.txt
sudo grep ^[^#] /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null >> $HOSTNAME-Requirement-6.txt
sudo yum repolist all 2>/dev/null >> $HOSTNAME-Requirement-6.txt


echo "Getting Requirement 7"
echo "|=---------------------=[CURRENT USER PRIVILEGE RIGHTS]=---------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Related requirements: 7.1 - 7.2                                           =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Please compare current values with your Security Configuration Standard   =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "checks to see what group current user is part of (By Default members of wheel are sudoers in CentOS )" >>   $HOSTNAME-Requirement-7.txt 
grep $(whoami) /etc/group >>   $HOSTNAME-Requirement-7.txt 
echo "" >>   $HOSTNAME-Requirement-7.txt 
echo "Checks /etc/sudoers to see if user is added" >>   $HOSTNAME-Requirement-7.txt 
file1="/etc/sudoers"
sudoer1=`sudo grep $(whoami) /etc/sudoers`
if [ ! -f $file1 ]
then
	:
elif [ ! "$sudoer1" ]
then
	echo "$(whoami) doesnt exist in sudoers file" >>   $HOSTNAME-Requirement-7.txt 
else
	echo "$(whoami) Exists in the sudoers file" >>   $HOSTNAME-Requirement-7.txt 
fi


echo "Getting Requirement 8"
echo "|=-----------------------=[ENABLED LOCAL ACCOUNTS]=---------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.4                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
awk -F: '$NF!~/\/!false$/ && $NF!~/\/!nologin$/' /etc/passwd  >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=-----------------------=[DISABLED LOCAL ACCOUNTS]=--------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.4                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "---accounts not allowed to logon---" >>   $HOSTNAME-Requirement-8.txt
awk -F: '$NF!~/\/!nologin$/' /etc/passwd >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "---accounts with password disabled/Not able to logon---" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/shadow |grep '!' >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=---------------------------=[ACCOUNT LOCKOUT]=------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.6                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo " This checks /etc/pam.d/system-auth and /etc/pam.d/password-auth to see if a pam_faillock.so line is set " >>   $HOSTNAME-Requirement-8.txt 
sysauth1=`sudo cat /etc/pam.d/system-auth | grep faillock`
passauth1=`sudo cat /etc/pam.d/password-auth | grep faillock`
if [[ ! "$sysauth1" && ! "$passauth1" ]]
then
	echo " pam.d/system-auth and pam.d/password-auth dont have any Password lockout attempt settings!"  >>   $HOSTNAME-Requirement-8.txt 
fi
if [ ! -z "$sysauth1" ]
then
	echo "pam.d/system-auth has the setting as follows:" >>   $HOSTNAME-Requirement-8.txt 
	echo $sysauth1 >>   $HOSTNAME-Requirement-8.txt 
fi
if [ ! -z "$passauth1" ]
then
	echo "pam.d/password-auth has the setting as follows:" >>   $HOSTNAME-Requirement-8.txt 
	echo $passauth1 >>   $HOSTNAME-Requirement-8.txt 
fi

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=----------------------=[ACCOUNT LOCKOUT DURATION]=--------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.7                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "::This Checks Account Lockout duration as set in PAM::"  >>   $HOSTNAME-Requirement-8.txt
cat /etc/pam.d/system-auth |grep "unlock_time*" >>   $HOSTNAME-Requirement-8.txt


echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=----------------------------=[SESSION TIMEOUT]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.8                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 

echo "--[ Console timeout ]" >>   $HOSTNAME-Requirement-8.txt 
echo "This setting is intended to log a user out of the console if inactive" >>   $HOSTNAME-Requirement-8.txt 
logout1=`cat ~/.bashrc |grep TMOUT`
logout2=`cat ~/.bash_profile |grep TMOUT`
if [[ ! "$logout1" && ! "$logout2" ]]
then
	echo "No Console timeout settings found in bashrc or bash_profile, This does not mean there is no console timeout set as there may be other scripts to do this! " >>   $HOSTNAME-Requirement-8.txt
fi
if [ ! -z "$logout1" ]
then
	echo ".bashrc :: Time out settings in seconds:"$logout1 >>   $HOSTNAME-Requirement-8.txt
 
fi
if [ ! -z "$logout2" ]
then
	echo ".bash_profile :: Time out settings in seconds:"$logout1 >>   $HOSTNAME-Requirement-8.txt
fi


echo "--[ SSH Timeout ]" >>   $HOSTNAME-Requirement-8.txt
echo "This setting logs a SSH user out after a period of time" >>   $HOSTNAME-Requirement-8.txt

echo "Alive interval" >>   $HOSTNAME-Requirement-8.txt
sudo cat sshd_config 2>/dev/null| grep ClientAliveInterval >>   $HOSTNAME-Requirement-8.txt
echo "Client alive count" >>   $HOSTNAME-Requirement-8.txt
sudo cat sshd_config 2>/dev/null| grep  ClientAliveCountMax >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=---------------------=[PASSWORD STORE CONFIGURATION]=----------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.1                                               =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo "this checks /etc/pam.d/system-auth to see what settings are present for password encryption" >>   $HOSTNAME-Requirement-8.txt
encryp1=`sudo cat /etc/pam.d/system-auth 2>/dev/null|grep pam_unix.so`
if [[ $encryp1 =~ sha512 ]]
then 
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null|grep sha512` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ sha256 ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null|grep sha256` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ bigcrypt ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null|grep bigcrypt` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ blowfish ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null|grep blowfish` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ md5 ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null|grep md5` >>   $HOSTNAME-Requirement-8.txt
else
	echo "No Encryption found in /etc/pam.d/system-auth for pam_unix.so" >>   $HOSTNAME-Requirement-8.txt
fi
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "This Checks /etc/passwd and /etc/shadow to see what permissions are set on them" >>   $HOSTNAME-Requirement-8.txt
passwd1=`stat -c %a /etc/passwd`
echo "/etc/passwd has the  permissions set to $passwd1" >>   $HOSTNAME-Requirement-8.txt
shadow1=`stat -c %a /etc/shadow`
echo "/etc/shadow has the permissions set to $shadow1" >>   $HOSTNAME-Requirement-8.txt
echo "The 'other' group should never have read access to the shadow file, as it contains the hashed passwords." >>   $HOSTNAME-Requirement-8.txt

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=--------------------------=[PASSWORD LENGTH]=-------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.3                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
#Checks password minlen in pam
minlen1=`sudo cat /etc/pam.d/common-password 2> /dev/null|grep minlen `
#checks password minlen in /etc/security/pwquality.conf
minlen2=`sudo cat /etc/security/pwquality.conf 2> /dev/null|grep minlen`
#checks password minlen in /etc/pam.d/system-auth
minlen3=`sudo cat /etc/pam.d/system-auth 2> /dev/null|grep minlen`
echo "Checking for password length setting in /etc/pam.d/common-password,/etc/pam.d/system-auth & /etc/security/pwquality.conf " >>   $HOSTNAME-Requirement-8.txt
if [ ! -z "$minlen1" ]
then
	echo "/etc/pam.d/common-password Min password length set as: $minlen1" >>   $HOSTNAME-Requirement-8.txt
if [[ ! -z "minlen1" && "$minlen1" =~ "#" ]]
then
	echo "/etc/pam.d/common-password Min password length is commented out and NOT active! " >>   $HOSTNAME-Requirement-8.txt
fi
fi
if [ ! -z "$minlen2" ]
then
	echo "/etc/security/pwquality.conf Min password length set as : $minlen2" >>   $HOSTNAME-Requirement-8.txt
fi
if [[ ! -z "minlen2" && "$minlen2" =~ "#" ]]
then
	echo "/etc/security/pwquality.conf Min password length is commented out and NOT active! " >>   $HOSTNAME-Requirement-8.txt
fi
if [ ! -z "$minlen3" ]
then
	echo "/etc/pam.d/system-auth Min password length set as : $minlen3" >>   $HOSTNAME-Requirement-8.txt
fi
if [[ ! -z "minlen3" && "$minlen3" =~ "#" ]]
then
	echo "/etc/pam.d/system-auth Min password length is commented out and NOT active! " >>   $HOSTNAME-Requirement-8.txt
fi

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=------------------------=[PASSWORD COMPLEXITY]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.3                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
file0="/etc/pam.d/common-password"
lowcase0=`grep pam_pwquality.so /etc/pam.d/common-password 2>/dev/null| grep lcredit`
upcase0=`grep pam_pwquality.so /etc/pam.d/common-password 2>/dev/null|grep ucredit`
digit0=`grep pam_pwquality.so /etc/pam.d/common-password 2>/dev/null|grep dcredit`
othchar0=`grep pam_pwquality.so /etc/pam.d/common-password 2>/dev/null|grep ocredit`
if [ ! -f "$file0" ]
then
	echo " no file found for "$file0"" >>   $HOSTNAME-Requirement-8.txt 
elif [[ -f "$file0" && ! "$lowcase0" ]]
then
	echo "/etc/pam.d/common-password has no lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$lowcase0" =~ "#" ]]
then
	echo "/etc/pam.d/common-password has Lower case requirement set as $lowcase0, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/common-password has lowercase requirement set as $lowcase0" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file0" ]
then
	:
elif [[ -f "$file0" && ! "$upcase0" ]]
then
	echo "/etc/pam.d/common-password has Upper lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$upcase0" =~ "#" ]]
then
	echo "/etc/pam.d/common-password has Upper case requirement set as $upcase0, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/common-password has Upper case requirement set as $upcase0" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file0" ]
then
	:
elif [[ -f "$file0" && ! "$digit0" ]]
then
	echo "/etc/pam.d/common-password has no Digit Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$digit0" =~ "#" ]]
then
	echo "/etc/pam.d/common-password has Digit requirement set as $digit0, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/common-password has Digit requirement set as $digit0" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file0" ]
then
	:
elif [[ -f "$file0" && ! "$othchar0" ]]
then
	echo "/etc/pam.d/common-password has no Other Character Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$othchar0" =~ "#" ]]
then
	echo "/etc/pam.d/common-password has Other Character requirement set as $othchar1, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/common-password has Other Character requirement set as $othchar1" >>   $HOSTNAME-Requirement-8.txt 
fi

file1="/etc/security/pwquality.conf"
lowcase1=`grep lcredit /etc/security/pwquality.conf 2>/dev/null`
upcase1=`grep ucredit /etc/security/pwquality.conf 2>/dev/null`
digit1=`grep dcredit /etc/security/pwquality.conf 2>/dev/null`
othchar1=`grep ocredit /etc/security/pwquality.conf 2>/dev/null`
if [ ! -f "$file1" ]
then
	echo " no file found for "$file1""
elif [[ -f "$file1" && ! "$lowcase1" ]]
then
	echo "/etc/security/pwquality.conf has no lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$lowcase1" =~ "#" ]]
then
	echo "/etc/security/pwquality.conf has Lower case requirement set as $lowcase1, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/security/pwquality.conf has lowercase requirement set as $lowcase1" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file1" ]
then
	:
elif [[ -f "$file1" && ! "$upcase1" ]]
then
	echo "/etc/security/pwquality.conf has Upper lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$upcase1" =~ "#" ]]
then
	echo "/etc/security/pwquality.conf has Upper case requirement set as $upcase1, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/security/pwquality.conf has Upper case requirement set as $upcase1" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file1" ]
then
	:
elif [[ -f "$file1" && ! "$digit1" ]]
then
	echo "/etc/security/pwquality.conf has no Digit Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$digit1" =~ "#" ]]
then
	echo "/etc/security/pwquality.conf has Digit requirement set as $digit1, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/security/pwquality.conf has Digit requirement set as $digit1" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file1" ]
then
	:
elif [[ -f "$file1" && ! "$othchar1" ]]
then
	echo "/etc/security/pwquality.conf has no Other Character Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$othchar1" =~ "#" ]]
then
	echo "/etc/security/pwquality.conf has Other Character requirement set as $othchar1, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/security/pwquality.conf has Other Character requirement set as $othchar1" >>   $HOSTNAME-Requirement-8.txt 
fi


file2="/etc/pam.d/system-auth"
lowcase2=`grep lcredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`
upcase2=`grep ucredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`
digit2=`grep dcredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`
othchar2=`grep ocredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`

if [ ! -f "$file2" ]
then
	echo " no file found for "$file2""
elif [[ -f "$file2" && ! $lowcase2 ]]
then
	echo "/etc/pam.d/system-auth has no lowercase Requirement for password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$lowcase2" =~ "#" ]]
then
	echo "/etc/pam.d/system-auth has lower case requirement set as $lowcase2, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/system-auth has lowercase requirement set as $lowcase2" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file2" ]
then
	:
elif [[ -f "$file2" && ! "$upcase2" ]]
then
	echo "/etc/pam.d/system-auth has no upper lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$upcase2" =~ "#" ]]
then
	echo "/etc/pam.d/system-auth has upper case requirement set as $upcase2, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/system-auth has upper case requirement set as $upcase2" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file2" ]
then
	:
elif [[ -f "$file2" && ! "$digit2" ]]
then
	echo "/etc/pam.d/system-auth has no Digit Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$digit2" =~ "#" ]]
then
	echo "/etc/pam.d/system-auth has Digit requirement set as $digit2, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/system-auth has Digit requirement set as $digit2" >>   $HOSTNAME-Requirement-8.txt 
fi

if [ ! -f "$file2" ]
then
	:
elif [[ -f "$file2" && ! "$othchar2" ]]
then
	echo "/etc/pam.d/system-auth has no Other Character Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$othchar2" =~ "#" ]]
then
	echo "/etc/pam.d/system-auth has Other Character requirement set as $othchar2, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/system-auth has Other Character requirement set as $othchar2" >>   $HOSTNAME-Requirement-8.txt 
fi
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=----------------------=[PASSWORD CHANGE THRESHOLD]=-------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.4                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
passthesh1=`cat /etc/login.defs 2> /dev/null|grep PASS_MAX_DAYS`
passthesh2=`grep pam_unix.so /etc/pam.d/common-password 2> /dev/null|grep remember=*`
if [ ! -z "$passthesh1" ]
then
	echo "Threshold setting in /etc/login.defs:" >>   $HOSTNAME-Requirement-8.txt 
	echo "$passthesh1" >>   $HOSTNAME-Requirement-8.txt 
fi
if [ ! -z "$passthesh2" ]
then
	echo "Threshold setting in /etc/pam.d/common-password:" >>   $HOSTNAME-Requirement-8.txt 
	echo "$passthesh2" >>   $HOSTNAME-Requirement-8.txt 
fi
if [[ ! "$passthesh1" && ! "$passthesh2" ]]
then
	echo "No Password change threshold found in /etc/pam.d/common-password or /etc/login.defs" >>   $HOSTNAME-Requirement-8.txt 
fi

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=--------------------------=[PASSWORD HISTORY]=------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.5                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
grep pam_unix.so /etc/pam.d/common-password 2>/dev/null|grep remember=* >>   $HOSTNAME-Requirement-8.txt

grep pam_unix.so /etc/pam.d/system-auth 2>/dev/null|grep remember=* >>   $HOSTNAME-Requirement-8.txt

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOCAL ACCOUNTS]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo " this pulls information from the /etc/passwd file! "  >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/passwd | awk -F: '{ print $1}'  >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-------------------------=[LOCAL ADMINISTRATORS]=---------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "lists Users in the wheel group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group wheel >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the admin group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group admin >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the sudo group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group sudo >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the staff group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group staff >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the sudoers group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group sudoers >>   $HOSTNAME-Requirement-8.txt


#echo "|=-----------------------=[LOCAL ADMINISTRATOR STATUS]=-----------------------=|" >>   $HOSTNAME-Requirement-8.txt 
#echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
#echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 


echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOCAL GROUPS]=-------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "This pulls information from the /etc/group file!"  >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/group | awk -F: '{ print $1}' >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "Getting Requirement 10"
echo "|=-----------------------=[EVENTLOG - SERVICE STATUS]=------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo service rsyslog status 2>/dev/null >> $HOSTNAME-Requirement-10.txt
sudo service syslog status 2>/dev/null >> $HOSTNAME-Requirement-10.txt

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=---------------------------=[LOG CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo " -- This Checks the /etc/rsyslog.conf file for logging configuration -- " >> $HOSTNAME-Requirement-10.txt
echo "authpriv: Messages coming from authorization and security related events" >> $HOSTNAME-Requirement-10.txt
auth1=`grep auth /etc/rsyslog.conf`
if [[ ! -z "$auth1" && "$auth1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$auth1" && "$auth1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$auth1" && "$auth1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$auth1" && "$auth1" =~ "#auth." ]]
then
	echo "$auth1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ ".*" ]]
then
	echo "$auth1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "debug" ]]
then
	echo "$auth1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "info" ]]
then
	echo "$auth1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "notice" ]]
then
	echo "$auth1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "warn" ]]
then
	echo "$auth1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "err" ]]
then
	echo "$auth1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "crit" ]]
then
	echo "$auth1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "alert" ]]
then
	echo "$auth1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$auth1" && "$auth1" =~ "emerg" ]]
then
	echo "$auth1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No Auth Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt

echo "authpriv: Messages coming from authorization and security related events" >> $HOSTNAME-Requirement-10.txt
authpriv1=`grep authpriv /etc/rsyslog.conf`
if [[ ! -z "$authpriv1" && "$authpriv1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$authpriv1" && "$authpriv1" =~ "#authpriv." ]]
then
	echo "$authpriv1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ ".*" ]]
then
	echo "$authpriv1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "debug" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "info" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "notice" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "warn" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "err" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "crit" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "alert" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$authpriv1" && "$authpriv1" =~ "emerg" ]]
then
	echo "$authpriv1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No Authpriv Logging Found!"
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "kern: Any message coming from the Linux kernel" >> $HOSTNAME-Requirement-10.txt
kern1=`grep kern /etc/rsyslog.conf`
if [[ ! -z "$kern1" && "$kern1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$kern1" && "$kern1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$kern1" && "$kern1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$kern1" && "$kern1" =~ "#kern." ]]
then
	echo "$kern1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ ".*" ]]
then
	echo "$kern1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "debug" ]]
then
	echo "$kern1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "info" ]]
then
	echo "$kern1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "notice" ]]
then
	echo "$kern1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "warn" ]]
then
	echo "$kern1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "err" ]]
then
	echo "$kern1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "crit" ]]
then
	echo "$kern1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "alert" ]]
then
	echo "$kern1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$kern1" && "$kern1" =~ "emerg" ]]
then
	echo "$kern1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No Kern Logging Found!"
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "mail: Messages generated by the mail subsystem" >> $HOSTNAME-Requirement-10.txt
mail1=`grep mail /etc/rsyslog.conf`
if [[ ! -z "$mail1" && "$mail1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$mail1" && "$mail1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$mail1" && "$mail1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$mail1" && "$mail1" =~ "#mail." ]]
then
	echo "$mail1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ ".*" ]]
then
	echo "$mail1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "debug" ]]
then
	echo "$mail1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "info" ]]
then
	echo "$mail1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "notice" ]]
then
	echo "$mail1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "warn" ]]
then
	echo "$mail1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "err" ]]
then
	echo "$mail1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "crit" ]]
then
	echo "$mail1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "alert" ]]
then
	echo "$mail1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$mail1" && "$mail1" =~ "emerg" ]]
then
	echo "$mail1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No Mail Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "cron: Cron daemon related messages" >> $HOSTNAME-Requirement-10.txt
cron1=`grep cron /etc/rsyslog.conf`
if [[ ! -z "$cron1" && "$cron1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$cron1" && "$cron1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$cron1" && "$cron1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$cron1" && "$cron1" =~ "#cron." ]]
then
	echo "$cron1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ ".*" ]]
then
	echo "$cron1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "debug" ]]
then
	echo "$cron1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "info" ]]
then
	echo "$cron1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "notice" ]]
then
	echo "$cron1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "warn" ]]
then
	echo "$cron1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "err" ]]
then
	echo "$cron1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "crit" ]]
then
	echo "$cron1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "alert" ]]
then
	echo "$cron1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$cron1" && "$cron1" =~ "emerg" ]]
then
	echo "$cron1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No Cron Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "daemon: Messages coming from daemons" >> $HOSTNAME-Requirement-10.txt
daemon1=`grep daemon /etc/rsyslog.conf`
if [[ ! -z "$daemon1" && "$daemon1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$daemon1" && "$daemon1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$daemon1" && "$daemon1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$daemon1" && "$daemon1" =~ "#daemon." ]]
then
	echo "$daemon1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ ".*" ]]
then
	echo "$daemon1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "debug" ]]
then
	echo "$daemon1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "info" ]]
then
	echo "$daemon1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "notice" ]]
then
	echo "$daemon1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "warn" ]]
then
	echo "$daemon1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "err" ]]
then
	echo "$daemon1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "crit" ]]
then
	echo "$daemon1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "alert" ]]
then
	echo "$daemon1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$daemon1" && "$daemon1" =~ "emerg" ]]
then
	echo "$daemon1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No daemon Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "news: Messages coming from network news subsystem" >> $HOSTNAME-Requirement-10.txt
news1=`grep news /etc/rsyslog.conf`
if [[ ! -z "$news1" && "$news1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$news1" && "$news1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$news1" && "$news1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$news1" && "$news1" =~ "#news." ]]
then
	echo "$news1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ ".*" ]]
then
	echo "$news1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "debug" ]]
then
	echo "$news1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "info" ]]
then
	echo "$news1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "notice" ]]
then
	echo "$news1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "warn" ]]
then
	echo "$news1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "err" ]]
then
	echo "$news1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "crit" ]]
then
	echo "$news1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "alert" ]]
then
	echo "$news1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$news1" && "$news1" =~ "emerg" ]]
then
	echo "$news1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No news Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "lpr: Printing related log messages" >> $HOSTNAME-Requirement-10.txt
lpr1=`grep lpr /etc/rsyslog.conf`
if [[ ! -z "$lpr1" && "$lpr1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$lpr1" && "$lpr1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$lpr1" && "$lpr1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$lpr1" && "$lpr1" =~ "#lpr." ]]
then
	echo "$lpr1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ ".*" ]]
then
	echo "$lpr1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "debug" ]]
then
	echo "$lpr1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "info" ]]
then
	echo "$lpr1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "notice" ]]
then
	echo "$lpr1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "warn" ]]
then
	echo "$lpr1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "err" ]]
then
	echo "$lpr1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "crit" ]]
then
	echo "$lpr1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "alert" ]]
then
	echo "$lpr1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$lpr1" && "$lpr1" =~ "emerg" ]]
then
	echo "$lpr1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No lpr Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "user: Log messages coming from user programs" >> $HOSTNAME-Requirement-10.txt
user1=`grep user /etc/rsyslog.conf`
if [[ ! -z "$user1" && "$user1" =~ ".=" ]]
then
	value1="Equal to and greater than"
elif [[ ! -z "$user1" && "$user1" =~ ".!" ]]
then
	value1="Lower than"
elif [[ ! -z "$user1" && "$user1" =~ ".=!" ]]
then
	value1="Above"
else
	:
fi

if [[ ! -z "$user1" && "$user1" =~ "#user." ]]
then
	echo "$user1 Exists But is Commented out!" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ ".*" ]]
then
	echo "$user1 Exists and it set to log ALL Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "debug" ]]
then
	echo "$user1 Exists and it set to log $value1 debug Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "info" ]]
then
	echo "$user1 Exists and it set to log $value1 info Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "notice" ]]
then
	echo "$user1 Exists and it set to log $value1 Notice Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "warn" ]]
then
	echo "$user1 Exists and it set to log $value1 Warning Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "err" ]]
then
	echo "$user1 Exists and it set to log $value1 Error Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "crit" ]]
then
	echo "$user1 Exists and it set to log $value1 Critical Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "alert" ]]
then
	echo "$user1 Exists and it set to log $value1 Alert Messages" >> $HOSTNAME-Requirement-10.txt
elif [[ ! -z "$user1" && "$user1" =~ "emerg" ]]
then
	echo "$user1 Exists and it set to log $value1 Emergency Messages" >> $HOSTNAME-Requirement-10.txt
else
	echo "No user Logging Found!" >> $HOSTNAME-Requirement-10.txt
fi
echo "" >> $HOSTNAME-Requirement-10.txt
echo "" >> $HOSTNAME-Requirement-10.txt
#check Logrotate.conf for settings
echo "-- this checks the /etc/logrotate.conf file for its settings -- " >> $HOSTNAME-Requirement-10.txt
sudo cat /etc/logrotate.conf  >> $HOSTNAME-Requirement-10.txt

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=------------------------------=[Audit Log]=------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "Audit service status" >> $HOSTNAME-Requirement-10.txt
sudo auditctl -s 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "" >> $HOSTNAME-Requirement-10.txt

echo "Audit Configuration" >> $HOSTNAME-Requirement-10.txt
sudo cat /etc/audit/auditd.conf >> $HOSTNAME-Requirement-10.txt
echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=-------------------------=[NTP - SERVICE STATUS]=---------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4                                                 =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo systemctl status ntpd >> $HOSTNAME-Requirement-10.txt
echo "" >>   $HOSTNAME-Requirement-10.txt

echo "|=---------------------------=[NTP CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo cat /etc/ntp.conf 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "" >>   $HOSTNAME-Requirement-10.txt
echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=---------------------------=[NTP PEERS]=------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo ntpd -p 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "">>   $HOSTNAME-Requirement-10.txt

echo "|=---------------------------=[NTP SYNC STATUS]=------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo ntpstat 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "">>   $HOSTNAME-Requirement-10.txt

echo "Finished, files have been generated for review in $(pwd) "
