#!/bin/sh
#This Script is written to retrieve information for the purposes of PCI DSS Standard's Compliance
#Author: Matthew Hanson and Dimpal Tailor
# Purpose: Determine if current user is root or not
is_root_user() {
 [ $(id -u) -eq 0 ]
}

# invoke the function
# make decision using conditional logical operators
is_root_user && echo -e "\e[1;32mYou can run this script\e[0m" || echo -e "\e[1;31mYou need to run this script as a root user\e[0m"

echo -e "\e[1;32mTest Starts\e[0m"
start=$(date +%s.%N)

echo "Please wait, this may take some time"
echo -e "\e[1;34mGetting System info\e[0m"
echo -e "\e[1;36m|=-----------------------=[SYSTEM INFORMATION]=---------------------------=|\e[0m\n" >> $HOSTNAME-SystemInfo.txt
sudo hostnamectl 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mKernel Name\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo uname -s 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mKernel Release\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo uname -r 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mHost Name\e[0m" >> $HOSTNAME-SystemInfo.txt
echo $HOSTNAME 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mNode Name\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo uname -n 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mOperating System\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo uname -o 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mProcessor\e[0" >> $HOSTNAME-SystemInfo.txt
sudo uname -p 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mHardware Platform\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo uname -i 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mMachine Name\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo uname -m 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mHardware\e[0m" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo lshw -short 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mNetwork Information\e[0m" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo ifconfig 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mCPU Input/Output statastics\e[0m" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo iostat 2>&1  >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mShow how long the system has been running + load\e[0m" >> $HOSTNAME-SystemInfo.txt
uptime 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mShow system reboot history\e[0m" >> $HOSTNAME-SystemInfo.txt
last reboot 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay CPU information\e[0m" >> $HOSTNAME-SystemInfo.txt
cat /proc/cpuinfo 2>&1 >> $HOSTNAME-SystemInfo.txt || less /proc/cpuinfo 2>&1 >> $HOSTNAME-SystemInfo.txt || lscpu 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay memory information\e[0m" >> $HOSTNAME-SystemInfo.txt || less /proc/cpuinfo 2>&1 >> $HOSTNAME-SystemInfo.txt
cat /proc/meminfo 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay free and used memory\e[0m" >> $HOSTNAME-SystemInfo.txt
free -h 2>&1 >> $HOSTNAME-SystemInfo.txt 
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay PCI devices\e[0m" >> $HOSTNAME-SystemInfo.txt
lspci -tv 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay USB devices\e[0m" >> $HOSTNAME-SystemInfo.txt
lsusb -tv 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay DMI/SMBIOS hardware info from the BIOS\e[0m" >> $HOSTNAME-SystemInfo.txt
dmidecode 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mShow info about disk sda\e[0m" >> $HOSTNAME-SystemInfo.txt
hdparm -i /dev/sda 2>&1 >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo -e "\e[1;33mDisplay disk usage for all files and directories\e[0m" >> $HOSTNAME-SystemInfo.txt
sudo du -sh /root 2>&1 >> $HOSTNAME-SystemInfo.txt


echo -e "\e[1;36m|=----------------------=[ACTIVE DIRECTORY STATUS]=--------------------------=|\e[0m\n" >> $HOSTNAME-SystemInfo.txt

dom0=`realm list domain-name -n`
if [ "$dom0" = "" ]
then
    echo "No Domain Set/Joined $dom0 " >> $HOSTNAME-SystemInfo.txt
else
    echo "The domain is set to : $dom0 " >> $HOSTNAME-SystemInfo.txt
fi

echo -e "\e[1;32mDone with system info\e[1;0m"
echo -e "\e[1;34mGetting Requirement 1\e[0m"

echo -e "\e[1;34mRelated requirements: 1.1\e[0m" >>   $HOSTNAME-Requirement-1.txt 
echo -e "\e[1;36m|=----------------=[FIREWALL - SERVICE STATUS]=------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt 

sudo service firewalld status >> $HOSTNAME-Requirement-1.txt 2>&1 || sudo ufw status verbose >> $HOSTNAME-Requirement-1.txt 2>&1 || sudo service iptables status >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;34mRelated requirements: 1.1a\e[0m" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=------------------=[FIREWALL CONFIGURATION]=----------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt 

echo -e "INPUT rules" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L INPUT >> $HOSTNAME-Requirement-1.txt
echo "OUTPUT rules" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L OUTPUT >> $HOSTNAME-Requirement-1.txt
echo "FORWARD rules" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L FORWARD >>   $HOSTNAME-Requirement-1.txt

echo -e "\e[1;36m|=------------------=[FIREWALL RULES LIST]=-------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt 

sudo ufw status numbered >> $HOSTNAME-Requirement-1.txt 2>&1 || sudo firewall-cmd --list-all >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;34mRelated requirements: 1.1.4\e[0m" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=----------------------=[LIST OF ZONES]=------------------------------=|\e[0m\n" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mfirewall-cmd --get-zones\e[0m" >> $HOSTNAME-Requirement-1.txt
firewall-cmd --get-zones >> $HOSTNAME-Requirement-1.txt 2>&1
echo "========================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mfirewall-cmd --get-active-zones\e[0m" >> $HOSTNAME-Requirement-1.txt
firewall-cmd --get-active-zones >> $HOSTNAME-Requirement-1.txt 2>&1
dmz=`firewall-cmd --get-active-zones 2>&1 | grep dmz`
[ ! $dmz ] && echo "DMZ is not activated" >> $HOSTNAME-Requirement-1.txt || echo "DMZ is activated" >> $HOSTNAME-Requirement-1.txt
echo "========================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mfirewall-cmd --zone=dmz --list-ports\e[0m" >> $HOSTNAME-Requirement-1.txt
firewall-cmd --zone=dmz --list-ports >> $HOSTNAME-Requirement-1.txt 2>&1
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mfirewall-cmd --zone=dmz --list-protocols\e[1;33m" >> $HOSTNAME-Requirement-1.txt
firewall-cmd --zone=dmz --list-protocols >> $HOSTNAME-Requirement-1.txt 2>&1
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mfirewall-cmd --zone=dmz --list-services\e[0m" >> $HOSTNAME-Requirement-1.txt
firewall-cmd --zone=dmz --list-services >> $HOSTNAME-Requirement-1.txt 2>&1


echo -e "\e[1;34mRelated requirements: 1.1.6\e[0m" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=----------------------=[TELNET SERVICE STATUS]=-------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mMake sure all insecure non console access;telnet is disabled or stopped\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled telnet.socket >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig telnet.socket >> $HOSTNAME-Requirement-1.txt 2>&1
echo "==============================================" >>$HOSTNAME-Requirement-1.txt
systemctl status telnet >> $HOSTNAME-Requirement-1.txt 2>&1 || service telnet status >> $HOSTNAME-Requirement-1.txt 2>&1 
echo "==============================================" >>$HOSTNAME-Requirement-1.txt
netstat -lataupen 2>&1 | grep telnet || ss -lataupen 2>&1 | grep telnet >> $HOSTNAME-Requirement-1.txt 
echo "==============================================" >>$HOSTNAME-Requirement-1.txt
ps -ef | grep telnet >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=----------------------=[RSH SERVICE STATUS]=-------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo "\e[1;33mMake sure all insecure non console access/rsh is disabled or stopped\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled rsh.socket >>$HOSTNAME-Requirement-1.txt 2>&1 || chkconfig rsh.socket >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled rlogin.socket >>$HOSTNAME-Requirement-1.txt 2>&1 || chkconfig rsh.socket >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled rexec.socket >>$HOSTNAME-Requirement-1.txt 2>&1 || chkconfig rexec.socket >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
netstat -na 2>&1 | grep 514 >> $HOSTNAME-Requirement-1.txt || ss -a 2>&1 | grep 514 >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
ps -ef | grep rsh >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=----------------------=[NFS SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mMake sure NFS share is enable at boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled nfs-kernel-server >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig nfs-kernel-server >> $HOSTNAME-Requirement-1.txt 2>&1 || systemctl nfs-kernel >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mNFS share service status\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl status nfs-kernel-server >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig nfs-kernel-server >> $HOSTNAME-Requirement-1.txt 2>&1 || service nfs-kernel-server status >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mRPCBIND service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service rpcbind status >> $HOSTNAME-Requirement-1.txt 2>&1 || systemctl status rpcbind  >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig rpcbind >> $HOSTNAME-Requirement-1.txt 2>&1 
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mNFS-LOCK service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service nfs-lock status >> $HOSTNAME-Requirement-1.txt 2>&1 || systemctl status nfs-lock >>$HOSTNAME-Requirement-1.txt 2>&1 || chkconfig nfs-lock  >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mNFS share configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/exports | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mNFS package installed or not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | grep nfs-common  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | egrep 'nfs-kernel-server|nfs-utils'  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q nfs-utils >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se nfs-common >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list nfs-common >> $HOSTNAME-Requirement-1.txt 2>&1


echo -e "\e[1;36m|=----------------------=[PRINTER SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt

echo -e "\e[1;33mChecking CUPS package is installed or not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | grep cups  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | grep cups  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q cups >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se cups >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list cups >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking printing service is enabled on boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled cups >> $HOSTNAME-Requirement-1.txt 2>&1|| chkconfig cups >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking printing service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service cups status >> $HOSTNAME-Requirement-1.txt 2>&1|| systemctl status cups >> $HOSTNAME-Requirement-1.txt  2>&1 || chkconfig cups >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking CUPS configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/cups/cupsd.conf | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=----------------------=[FTP SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking FTP installed or not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | egrep 'ftp|vsftpd'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | egrep 'ftp|vsftp'   >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q 'ftp|vsftp' >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se ftp vsftp >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list ftp vsftp >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking FTP service is enabled on boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled ftp >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig ftp >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking FTP service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service ftp status >> $HOSTNAME-Requirement-1.txt 2>&1 || systemctl status ftp >> $HOSTNAME-Requirement-1.txt  2>&1 || chkconfig ftp >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking FTP configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/vsftpd/vsftpd.conf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=----------------------=[TELNET SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mCheking telnet package is installed on not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | egrep 'telnet|telnetd|telnet-server'  >> $HOSTNAME-Requirement-1.txt || rpm -qa 2>&1 | egrep 'telnet|telnetd|telnet-server'  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q telnet >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se telnet >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list telnet >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking telnet service is enabled on boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled telnet >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig telnet >> $HOSTNAME-Requirement-1.txt 2>&1 || service telnetd status >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking telnet service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service telnet status >> $HOSTNAME-Requirement-1.txt 2>&1|| systemctl status telnet >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig telnet 2>&1 >>$HOSTNAME-Requirement-1.txt


echo -e "\e[1;36m|=----------------------=[SMTP SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mCheking sendmail package is installed on not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | egrep 'sendmail|postfix'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | egrep 'sendmail|postfix'  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q 'sendmail|postfix' >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se 'sendmail|postfix' >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list 'sendmail|postfix' >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking senmail/postfix service is enabled on boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled sendmail postfix >> $HOSTNAME-Requirement-1.txt 2>&1|| chkconfig sendmail postfix >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking sendmail/postfix service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service sendmail postfix status >> $HOSTNAME-Requirement-1.txt 2>&1 || systemctl status sendmail postfix >> $HOSTNAME-Requirement-1.txt >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking sendmail configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/mail/sendmail.cf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking postfix configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/postfix/main.cf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=----------------------=[HTTP SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking http is installed or not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | egrep 'httpd|httpd|apache'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | egrep 'http|httpd|apache'  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q http httpd apache >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se http httpd apache >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list httpd httpd apache >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking http service is enabled on boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled http httpd apache >> $HOSTNAME-Requirement-1.txt 2>&1 
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking http service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service http httpd apache status >> $HOSTNAME-Requirement-1.txt 2>&1 || systemctl status http httpd apache >> $HOSTNAME-Requirement-1.txt >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking http configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/http/httpd.conf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=----------------------=[SNMP SERVICE STATUS]=--------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking SNMP package is installed or not\e[0m" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>&1 | grep snmpd  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | grep snmpd  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q snmpd >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se snmpd >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list snmpd >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking SNMP service is enabled on boot\e[0m" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled snmpd >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig snmp >> $HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking SNMP service status\e[0m" >> $HOSTNAME-Requirement-1.txt
service snmp status >> $HOSTNAME-Requirement-1.txt 2>&1|| systemctl status snmp >> $HOSTNAME-Requirement-1.txt 2>&1 || chkconfig snmp >>$HOSTNAME-Requirement-1.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking SNMP configuration\e[0m" >> $HOSTNAME-Requirement-1.txt
cat /etc/snmp/snmp.conf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1


echo -e "\e[1;36m|=----------------------=[DEVLOPMENT TOOLS PACKAGE]=-------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mMake sure Developement tools is not installed already\e[0m" >> $HOSTNAME-Requirement-1.txt
yum grouplist 2>&1 | grep "Development Tools" >> $HOSTNAME-Requirement-1.txt || 
dnf grouplist 2>&1 | grep "Development Tools" >> $HOSTNAME-Requirement-1.txt || pacman -Sg Developement Tools >> $HOSTNAME-Requirement-1.txt 2>&1 || tasksel --task-desc "Development Tools" >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper info pattern "Development Tools" >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;34mRelated requirements: 1.2.2\e[0m" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=------------------=[FIREWALLD START AT BOOT]=-----------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt  
echo -e "\e[1;33mChecking firewalld enable at boot\e[0m" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled firewalld >>$HOSTNAME-Requirement-1.txt 2>&1 || chkconfig firewalld >>$HOSTNAME-Requirement-1.txt 2>&1
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt 
echo -e "\e[1;33mChecking iptables enable at boot\e[0m" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled iptables >>$HOSTNAME-Requirement-1.txt 2>&1 || chkconfig iptables >>$HOSTNAME-Requirement-1.txt 2>&1
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking rc.local/pre.up.d file\e[0m" >>$HOSTNAME-Requirement-1.txt
cat /etc/rc.local | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1 || cat /etc/rc.d/rc.local | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1 || cat /etc/network/if-pre-up.d/iptables | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking cron tab for any firewall run at boot\e[0m" >>$HOSTNAME-Requirement-1.txt
crontab -l 2>&1 | grep *firewall* >>$HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;34mRelated Requirement 1.3.3\e[0m">>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=--------------------------=[IP FORWARDING]=-----------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt  

echo -e "\e[1;33mChecking configuration of sysctl file\e[0m" >>$HOSTNAME-Requirement-1.txt
cat /etc/sysctl.conf 2>&1 | grep -v "#" >>$HOSTNAME-Requirement-1.txt 2>&1
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking Source address verification\e[0m" >>$HOSTNAME-Requirement-1.txt
cat /proc/sys/net/ipv4/conf/default/rp_filter >>$HOSTNAME-Requirement-1.txt 2>&1
echo "Overwrites the value 0 to 1 to enable source address verification" >>$HOSTNAME-Requirement-1.txt

echo -e "\e[1;34mRelated Requirement 1.3.5\e[0m" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=-----------------------=[ESTABLISHED CONNECTION]=---------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt  

echo -e "\e[1;33mPermit only Established connections into the network\e[0m" >>$HOSTNAME-Requirement-1.txt
egrep -w 'ESTABLISHED' /etc/iptables.up.rules 2>&1 >>$HOSTNAME-Requirement-1.txt 2>&1 || egrep -w 'ESTABLISHED' /etc/sysconfig/iptables 2>&1 >>$HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;34mRelated Requirement 1.3.7\e[0m" >>$HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=------------------=[PRIVATE SPACE CONFIG]=----------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt  

echo -e "\e[1;33mChecking RFC1918 space is configured or not\e[1;33m" >>$HOSTNAME-Requirement-1.txt
ip -o addr show |   grep -v 'inet6' |   grep -v 'scope host' |   awk '{print $4}' |   cut -d '/' -f 1 |   grep -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)'  >>$HOSTNAME-Requirement-1.txt 2>&1
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt

echo -e "\e[1;36m|=----------------------------=[NAT CONFIG]=------------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt  
echo -e "\e[1;33mChecking ipforwarding enabled or not\e[0m"  >>$HOSTNAME-Requirement-1.txt
cat /proc/sys/net/ipv4/ip_forward  >>$HOSTNAME-Requirement-1.txt 2>&1
echo "enable if value is 1, disable if value is 0"  >>$HOSTNAME-Requirement-1.txt
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mpattern matching in iptables rule proving NAT configured\e[1;33m" >>$HOSTNAME-Requirement-1.txt
egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/sysconfig/iptables  >>$HOSTNAME-Requirement-1.txt 2>&1 || egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/iptables.up.rules >> $HOSTNAME-Requirement-1.txt 2>&1 
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking IPTABLE module ip_conntrack_ftp is loaded or not\e[0m" >>$HOSTNAME-Requirement-1.txt
cat /etc/sysconfig/iptables-config 2>&1 | grep IPTABLES_MODULES= >>$HOSTNAME-Requirement-1.txt 2>&1
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt

echo -e "\e[1;36m|=--------------------------=[PROXY CONFIG]=----------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt  
echo -e "\e[1;33mChecking proxy server is used\e[0m" >> $HOSTNAME-Requirement-1.txt
proxy=`cat /etc/profile 2>&1 | grep http_proxy`
[[ ! $proxy ]] && echo "No proxy configured" >> $HOSTNAME-Requirement-1.txt || echo "Proxy setting configued as $proxy\n" >> $HOSTNAME-Requirement-1.txt  
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mChecking env variable for any proxy setting\e[0m" >> $HOSTNAME-Requirement-1.txt
env | grep -i proxy >> $HOSTNAME-Requirement-1.txt 2>&1
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt
echo -e "\e[1;33mfirewall config\e[0m" >>$HOSTNAME-Requirement-1.txt
cat /etc/iptables.up.rules 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1  || cat /etc/sysconfig/iptbles 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-1.txt 2>&1 

echo -e "\e[1;34mRelated Requirement 1.4\e[0m" >>   $HOSTNAME-Requirement-1.txt
echo -e "\e[1;36m|=--------------------------=[IPTABLES INSTALLED]=-------------------------------=|\e[0m\n" >>   $HOSTNAME-Requirement-1.txt 
dpkg -l 2>&1 | grep iptables*  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>&1 | grep iptables*  >> $HOSTNAME-Requirement-1.txt 2>&1 || pacman -Q iptables* >> $HOSTNAME-Requirement-1.txt 2>&1 || zypper se iptables* >> $HOSTNAME-Requirement-1.txt 2>&1 || dnf list iptables* >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;36m|=------------------------------------=[SHOW PORT CONFLICT]=--------------------------------=|\e[0m" >>   $HOSTNAME-Requirement-1.txt  

netstat -plnt >> $HOSTNAME-Requirement-1.txt 2>&1 || ss -plnt >> $HOSTNAME-Requirement-1.txt 2>&1

echo -e "\e[1;32mDone with requirement 1\e[0m"
echo -e "\e[1;34mGetting Requirement 2\e[0m"

echo "|=------------------------------------=[USER ACCOUNTS]=-----------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related Requirements: 2.1                                                 =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "file /etc/passwd configuration" >>   $HOSTNAME-Requirement-2.txt  
cat /etc/passwd | grep -v "#" >>   $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[GROUP ACCOUNTS]=---------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related Requirements: 2.1                                                 =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "file /etc/group configuration" >>   $HOSTNAME-Requirement-2.txt 
cat /etc/group | grep -v "#" >>  $HOSTNAME-Requirement-2.txt


echo "|=-------------------------=[INSTALLED SOFTWARE]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo apt list --installed >> $HOSTNAME-Requirement-2.txt  2>&1 || sudo rpm -qa >> $HOSTNAME-Requirement-2.txt 2>&1|| sudo dpkg-query >> $HOSTNAME-Requirement-2.txt 2>&1||sudo yum list installed >> $HOSTNAME-Requirement-2.txt 2>&1 || sudo pacman -Q >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=------------------------=[TOP CONTROL GROUPS]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "-x" | systemd-cgtop >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=------------------------=[SERVICES RUNNING]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo systemctl --state=running >> $HOSTNAME-Requirement-2.txt 2>&1 

echo "|=------------------------=[SERVICES ENABLED]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
systemctl list-unit-files --state=enabled >> $HOSTNAME-Requirement-2.txt 2>&1 || chkconfig --list >> $HOSTNAME-Requirement-2.txt 2>&1 || service --list-all >> $HOSTNAME-Requirement-2.txt 2>&1
echo "========================[ All unit files with load status ]=================" >> $HOSTNAME-Requirement-2.txt
systemctl list-unit-files --type service >> $HOSTNAME-Requirement-2.txt 2>&1 || chkconfig --list >> $HOSTNAME-Requirement-2.txt 2>&1
echo "========================[ All loaded services status ]======================" >> $HOSTNAME-Requirement-2.txt
systemctl list-units --type service >> $HOSTNAME-Requirement-2.txt 2>&1 || chkconfig --list >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=------------------------=[PROCESSES RUNNING]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt  
sudo ps -ef >> $HOSTNAME-Requirement-2.txt 2>&1 || sudo top -c >> $HOSTNAME-Requirement-2.txt 2>&1 || sudo ps -aux  >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=------------------------=[XINETD SERVICE]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt  
sudo service xinetd status >> $HOSTNAME-Requirement-2.txt 2>&1 || sudo systemctl status xinetd >> $HOSTNAME-Requirement-2.txt 2>&1 || service xinetd status >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=-----------------------=[PORTS IN LISTENING STATE]=------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo lsof -i -P -n | grep LISTEN >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=-----------------------=[NETWORK CONNECTION]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo netstat -a >> $HOSTNAME-Requirement-2.txt 2>&1 || ss -a >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=-----------------------=[NETWORK INTERFACES]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo ip link show >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=-----------------------=[KERNEL ROUTE TABLE]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo ip route >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=---------------------------=[IPv6 SUPPORT]=--------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
ipv6=`ip a 2>&1 |grep inet6`
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
	chage -l  root >> $HOSTNAME-Requirement-2.txt 2>&1
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
sudo grep PASS_WARN_AGE /etc/login.defs >> $HOSTNAME-Requirement-2.txt 2>&1 

echo "--[ Interactive logon: Message text for users attempting to log on ]" >>   $HOSTNAME-Requirement-2.txt 
echo "checks /etc/motd" >>   $HOSTNAME-Requirement-2.txt
motd=`sudo cat /etc/motd | grep -v "#" `
[[ ! $motd ]] && echo "No motd configured" >> $HOSTNAME-Requirement-2.txt || echo "MOTD configured as $motd\n" >> $HOSTNAME-Requirement-2.txt
echo "" >>   $HOSTNAME-Requirement-2.txt
echo "checks /etc/sshd for banner" >>   $HOSTNAME-Requirement-2.txt
sudo cat /etc/ssh/sshd_config  2>&1 | grep Banner >>   $HOSTNAME-Requirement-2.txt
echo "" >>   $HOSTNAME-Requirement-2.txt

echo "|=----------------------------=[MOUNTED HARD DRIVES]=------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "Permantally mount drives" >> $HOSTNAME-Requirement-2.txt
sudo cat /etc/fstab | grep -v "#" >> $HOSTNAME-Requirement-2.txt 2>&1
echo "Mounted drives partitions sizes and types" >> $HOSTNAME-Requirement-2.txt
sudo fdisk -l >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=----------------------------=[LOCAL DRIVES]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo lshw -class disk  >> $HOSTNAME-Requirement-2.txt 2>&1 || fdisk -l >> $HOSTNAME-Requirement-2.txt 2>&1 

echo "|=--------------------------=[DRIVERS INSTALLED]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
find /lib/modules/$(uname -r)/kernel/ -name '*.ko*' >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=----------------------------=[USB DRIVE MODULES LOADED]=----------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
sudo lsmod | grep usb_storage  >> $HOSTNAME-Requirement-2.txt 2>&1
echo "======================================================================================" >> $HOSTNAME-Requirement-2.txt
sudo ls /lib/modules/`uname -r`/kernel/drivers/usb/storage  >> $HOSTNAME-Requirement-2.txt 2>&1

echo "|=----------------------=[ENCRYPTION METHOD FOR PASSWORD]=-----------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "Getting encryption method used for password for all non console/remote ssh access" >> $HOSTNAME-Requirement-2.txt
sudo cat /etc/login.defs | grep ENCRYPT_METHOD >>$HOSTNAME-Requirement-2.txt 2>&1

echo -e "\e[1;32mDone with Requirement 2\e[0m"
echo -e "\e[1;35mAudit Requirement 3 manually\e[0m"
echo -e "\e[1;35mSkipping Requirement 3\e[0m"
echo -e "\e[1;34mGetting Requirement 4\e[0m" 
echo "|=----------------------=[TLS VERSIONS]=-------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "|= Related requirements: 4.1                                                 =|" >>   $HOSTNAME-Requirement-4.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "Check TLS1.2 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" | openssl s_client -connect google.com:443 -tls1_2  >> $HOSTNAME-Requirement-4.txt 2>&1 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check TLS1.1 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" | openssl s_client -connect google.com:443 -tls1_1  >> $HOSTNAME-Requirement-4.txt 2>&1 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check TLS1.0 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" |openssl s_client -connect google.com:443 -tls1  >> $HOSTNAME-Requirement-4.txt 2>&1 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check server accepts connections using ciphers from group NULL or LOW" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" |openssl s_client -connect google.com:443 -cipher NULL,LOW  >> $HOSTNAME-Requirement-4.txt 2>&1 


echo "|=----------------------=[TLS VERSIONS]=-------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "|= Related requirements: 4.2                                                 =|" >>   $HOSTNAME-Requirement-4.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "Check service use ssl/tls dor transmitting data" >>   $HOSTNAME-Requirement-4.txt
for I in `find /usr/sbin -type f -print`; do ldd ${I} | egrep -q 'ssl|tls'; if [ $? -eq 0 ]; then echo ${I} >> $HOSTNAME-Requirement-4.txt 2>&1; fi; done

echo -e "\e[1;32mDone with req 4\e[0m"
echo -e "\e[1;34mGetting Requirement 5\e[0m"

echo "|=----------------------=[ANTIVIRUS INSTALLED]=------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.1                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Check ClamAV is installed or not" >>   $HOSTNAME-Requirement-5.txt

dpkg -l 2>&1 | egrep 'clamav|clamav-freshclam' >> $HOSTNAME-Requirement-5.txt|| rpm -qa 2>&1 | egrep 'clamav|clamav-freshclam' >> $HOSTNAME-Requirement-5.txt 2>&1 || pacman -Q clamav >> $HOSTNAME-Requirement-5.txt 2>&1 || dnf list clamav >> $HOSTNAME-Requirement-5.txt 2>&1

[[ $? -eq 0 ]] && echo "ClamAV is installed." >> $HOSTNAME-Requirement-5.txt || echo "ClamAV is not installed" >> $HOSTNAME-Requirement-5.txt

echo "|=----------------------=[ANTIVIRUS RUNNING]=--------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Check ClamAV service is running or not" >> $HOSTNAME-Requirement-5.txt
a1=`systemctl is-enabled clamav 2>&1` || a1=`chkconfig clamav 2>&1` 
[ "$a1" == "enabled" ] && echo "ClamAV service is enabled" 2>&1 >> $HOSTNAME-Requirement-5.txt || echo "ClamAV service is not enabled" >> $HOSTNAME-Requirement-5.txt 2>&1
a2=`systemctl is-active clamav 2>&1` 
[ "$a2" == "active" ] && echo "ClamAV service is active" >> $HOSTNAME-Requirement-5.txt 2>&1 || echo "ClamAV service is not running" >> $HOSTNAME-Requirement-5.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Service status" >>   $HOSTNAME-Requirement-5.txt
service clamav status >> $HOSTNAME-Requirement-5.txt  2>&1 || systemctl status clamav >> $HOSTNAME-Requirement-5.txt  2>&1 

echo "|=----------------------=[ANTIVIRUS SCAN]=--------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking cronjobs to continous antivirus system scan using ClamAV " >>   $HOSTNAME-Requirement-5.txt
crontab -l 2>&1 | grep *clamav* >> $HOSTNAME-Requirement-5.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
[[ -f /etc/cron.daily/*clamav* ]] && echo "Daily cron exist of clamav scan" >> $HOSTNAME-Requirement-5.txt && cat /etc/cron.daily/*clamav* | grep -v "#" >> $HOSTNAME-Requirement-5.txt || echo "No daily cron exist of clamav scan" >> $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
[[ -f /etc/cron.hourly/*clamav* ]] && echo "Hourly cron exist of clamav scan" >>$HOSTNAME-Requirement-5.txt && cat /etc/cron.hourly/*clamav* | grep -v "#" >> $HOSTNAME-Requirement-5.txt || echo "No hourly cron exist of clamav scan" >> $HOSTNAME-Requirement-5.txt

echo "|=----------------------=[VIRUS SCAN LOGS]=----------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2a                                                =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking logs of virus detection" >>   $HOSTNAME-Requirement-5.txt
[[ -f /var/log/clamav/scan.log ]] && echo "Log file exist of clamav scan logs" >> $HOSTNAME-Requirement-5.txt && cat /var/log/clamav/scan.log | grep Infected 2>&1 || echo "No log file detect of clamav scan" >>$HOSTNAME-Requirement-5.txt   

echo "|=----------------------=[VIRUS DETECTION UP-TO-DATE]=-----------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.3                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking software is up-to-date" >>   $HOSTNAME-Requirement-5.txt
clam=`ps -ef | grep -v grep | grep clamav-freshclam | wc -l 2>&1`
[[ $clam -gt 0 ]] && echo "ClamAV FreshClam service is running as this service checks update of virus" >> $HOSTNAME-Requirement-5.txt || echo "ClamAV FreshClam service is not running as this service checks update of virus" >> $HOSTNAME-Requirement-5.txt 
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
if [[ -f /etc/clamav/freshclam.conf ]]; then
(
chk=`grep checks /etc/clamav/freshclam.conf | awk '{ print $2 }' 2>&1`
echo "Freshclam config exist. checks update $chk times a day" >> HOSTNAME-Requirement-5.txt
)
else
(
echo "No freshclam config exist" >> $HOSTNAME-Requirement-5.txt
)
fi

echo "|=----------------------=[ FRESHCLAM LOG-FILE ]=-----------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking log file of freshclam" >>   $HOSTNAME-Requirement-5.txt
if [[ -f /var/log/clamav/freshclam.log ]];
then 
(echo "Freshclam log file exist" >>$HOSTNAME-Requirement-5.txt && cat /var/log/clamav/freshclam.log >>$HOSTNAME-Requirement-5.txt)
else
( echo "Freshclam log file dose not exist" >> $HOSTNAME-Requirement-5.txt )
fi
 
echo "|=----------------------=[ CLAMSCAN AND CLAMD]=------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking CLAMD service is running" >>   $HOSTNAME-Requirement-5.txt
[ `ps -ef | grep -v grep | grep clamd | wc -l 2>&1` -gt 0 ] && echo "Clamd service is running" >>   $HOSTNAME-Requirement-5.txt || echo "Clamd service is not running" >>   $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Checking CLAMD conf file exist" >>   $HOSTNAME-Requirement-5.txt

if [[ -f /etc/clamav/clamd.conf ]];
then (
echo "clamd.conf does exist" >> $HOSTNAME-Requirement-5.txt
cat /etc/clamav/clamd.conf | grep -v "#" >> $HOSTNAME-Requirement-5.txt)
else
(echo "clamd.conf does exist" >> $HOSTNAME-Requirement-5.txt)
fi 
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Checking logging is enabled" >>   $HOSTNAME-Requirement-5.txt
clamconf 2>&1 | grep log  >> $HOSTNAME-Requirement-5.txt

echo "|=----------------------=[ CONF FILE PERMISSIONS ]=--------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.3                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking permission on clamd.conf" >>   $HOSTNAME-Requirement-5.txt
p1=`ls -alth /etc/clamav/clamd.conf 2>&1`
if [[ -r /etc/clamav/clamd.conf ]]; then (echo "clamd.conf has read persmission by user $p1 | awk '{print $3}',group $p1 | awk '{print $4}'" >>   $HOSTNAME-Requirement-5.txt)
else (echo "clamd.conf does not have read persmission" >> $HOSTNAME-Requirement-5.txt)
fi

if [[ -w /etc/clamav/clamd.conf ]]; then (echo "clamd.conf has write persmission by user $p1 | awk '{print $3}',group $p1 | awk '{print $4}'" >>   $HOSTNAME-Requirement-5.txt)
else (echo "clamd.conf does not have write persmission" >> $HOSTNAME-Requirement-5.txt)
fi

echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Checking permission on freshclam.conf" >>   $HOSTNAME-Requirement-5.txt
p2=`ls -alth /etc/clamav/freshclam.conf 2>&1`
if [[ -r /etc/clamav/freshclam.conf ]]; then (echo "freshclam.conf has read persmission by user $p2 | awk '{print $3}',group $p2 | awk '{print $4}'" >>   $HOSTNAME-Requirement-5.txt) 
else (echo "freshclam.conf does not have read persmission" >>   $HOSTNAME-Requirement-5.txt)
fi

if [[ -w /etc/clamav/clamd.conf ]]; then (echo "clamd.conf has write persmission by user $p2 | awk '{print $3}',group $p2 | awk '{print $4}'" >>   $HOSTNAME-Requirement-5.txt)
else (echo "clamd.conf does not have write persmission" >> $HOSTNAME-Requirement-5.txt)
fi
echo -e "\e[1;32mDone with Requirement 5\e[0m"
echo -e "\e[1;34mGetting Requirement 6\e[0m"

echo "|=---------------------------=[OS VERSION]=--------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.1                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
hostnamectl |grep "Operating System:*" >> $HOSTNAME-Requirement-6.txt 2>&1 
hostnamectl |grep "Kernel:*" >> $HOSTNAME-Requirement-6.txt 2>&1 

echo "|=------------------------------=[LAST UPDATE DATE]=------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.1                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=-------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "Checking when kernel updated last time" >>   $HOSTNAME-Requirement-6.txt 
rpm -q kernel --last >> $HOSTNAME-Requirement-6.txt 2>&1 || ls -l /boot/ >> $HOSTNAME-Requirement-6.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-6.txt
echo "Checking all package update date" >>   $HOSTNAME-Requirement-6.txt
rpm -qa --last >> $HOSTNAME-Requirement-6.txt 2>&1 || grep upgrade /var/log/dpkg.log >> $HOSTNAME-Requirement-6.txt 2>&1

echo "|=------------------------------=[PACKAGES TO UPDATE]=----------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.1                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=--------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "Checking list of packages needs to be updated" >>   $HOSTNAME-Requirement-6.txt 
yum list updates >> $HOSTNAME-Requirement-6.txt 2>&1 || dnf list updates >> $HOSTNAME-Requirement-6.txt 2>&1 || pacman -Qu >> $HOSTNAME-Requirement-6.txt 2>&1 || zypper list-updates >> $HOSTNAME-Requirement-6.txt 2>&1 || apt list --upgradable >> $HOSTNAME-Requirement-6.txt 2>&1 
[ ! $@ ] && echo "Above listed packages needs to be updated" >> $HOSTNAME-Requirement-6.txt || echo "No packages to update" >> $HOSTNAME-Requirement-6.txt
echo "===============================================" >>$HOSTNAME-Requirement-6.txt
echo "Checking installed/updated softwares" >>   $HOSTNAME-Requirement-6.txt
yum history >> $HOSTNAME-Requirement-6.txt 2>&1 || cat var/log/apt/history.log >> $HOSTNAME-Requirement-6.txt 2>&1
echo "" >> $HOSTNAME-Requirement-6.txt
echo "===============================================" >>$HOSTNAME-Requirement-6.txt
echo "Checking log of installed/updated packages" >> $HOSTNAME-Requirement-6.txt
cat /var/log/yum.log 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-6.txt 2>&1 || cat var/log/apt/history.log 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-6.txt 2>&1

echo "|=--------------------------=[OS UPDATES - SOURCES]=------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.2                                               =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=-------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
sudo dnf repolist all >> $HOSTNAME-Requirement-6.txt 2>&1 ||
sudo grep ^[^#] /etc/apt/sources.list /etc/apt/sources.list.d/* >> $HOSTNAME-Requirement-6.txt 2>&1 || sudo yum repolist all >> $HOSTNAME-Requirement-6.txt 2>&1

echo "|=--------------------------=[SECURITY UPDATES ]=---------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.2                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=-------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
sudo yum check-update --security >> $HOSTNAME-Requirement-6.txt 2>&1 ||sudo grep security /etc/apt/sources.list >> $HOSTNAME-Requirement-6.txt 2>&1

echo -e "\e[1;32mDone with Requirement 6\e[0m"
echo -e "\e[1;34mGetting Requirement 7\e[0m"

echo "|=---------------------=[CURRENT USER PRIVILEGE RIGHTS]=---------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Related requirements: 7.1 - 7.2                                           =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Please compare current values with your Security Configuration Standard   =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "checks to see what group current user is part of" >>   $HOSTNAME-Requirement-7.txt 
grep $(whoami) /etc/group >>   $HOSTNAME-Requirement-7.txt 
echo "" >>   $HOSTNAME-Requirement-7.txt 
echo "Checks /etc/sudoers to see if user is added" >>   $HOSTNAME-Requirement-7.txt 
file1="/etc/sudoers"
sudoer1=`sudo grep $(whoami) /etc/sudoers 2>&1`
if [ ! -f $file1 ]
then
	:
elif [ ! "$sudoer1" ]
then
	echo "$(whoami) doesnt exist in sudoers file" >>   $HOSTNAME-Requirement-7.txt 
else
	echo "$(whoami) Exists in the sudoers file" >>   $HOSTNAME-Requirement-7.txt 
fi

echo "|=---------------------=[ACCESS CONTROL SYSTEM ENFORCED]=--------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Related requirements: 7.2                                                 =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "Checking SELinux installed or not" >> $HOSTNAME-Requirement-7.txt
rpm -qa 2>&1 | egrep -w 'selinux-basic|selinux-policy-defualt' >> $HOSTNAME-Requirement-7.txt || dpkg -l 2>&1 | grep selinux* >> $HOSTNAME-Requirement-7.txt
[[ ! $@ ]] && echo "SELinux not installed" >> $HOSTNAME-Requirement-7.txt || echo "SELinux installed" >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking SELinux policy enforced" >> $HOSTNAME-Requirement-7.txt
state=`grep SELINUX=enforcing /etc/sysconfig/selinux 2>&1`
[[ ! $state ]] && echo "SELinux enforced" >> $HOSTNAME-Requirement-7.txt || echo "SELinux not enforced" >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking SELinux policy type" >> $HOSTNAME-Requirement-7.txt
type=`grep SELINUXTYPE=targeted /etc/sysconfig/selinux 2>&1`
[[ ! $type ]] && echo "SELinux type targeted" >> $HOSTNAME-Requirement-7.txt || echo "SELinux type not set to targeted" >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking SELinux troubleshoot package is installed" >> $HOSTNAME-Requirement-7.txt
rpm -q setroubleshoot >> $HOSTNAME-Requirement-7.txt 2>&1 || dpkg -l 2>&1 | grep setroubleshoot >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking unconfined daemons" >> $HOSTNAME-Requirement-7.txt
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}' >> $HOSTNAME-Requirement-7.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Getting status of SELinux" >> $HOSTNAME-Requirement-7.txt
sestatus >> $HOSTNAME-Requirement-7.txt 2>&1 || getenforce >> $HOSTNAME-Requirement-7.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Getting configuration of SELinux" >> $HOSTNAME-Requirement-7.txt
cat /etc/sysconfig/selinux | grep -v "#" >> $HOSTNAME-Requirement-7.txt 2>&1 || cat /etc/selinux/config | grep -v "#" >> $HOSTNAME-Requirement-7.txt 2>&1

echo -e "\e[1;32mDone with req 7\e[0m"
echo -e "\e[1;34mGetting Requirement 8\e[0m"

echo "|=-----------------------=[INACTIVE ACCOUNTS]=------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.                                                                              =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Getting inactive accounts more than or equal to 90 days" >> $HOSTNAME-Requirement-8.txt
inactive=`lastlog -b 90 2>&1 | tail -n+2 | grep -v '**Never log**' | awk '{print $1}' 2>&1`
[[ ! $inactive ]] && echo "No user inactive more than 90 days" >> $HOSTNAME-Requirement-8.txt || echo "Users inactive more than 90 days are $inactive " >> $HOSTNAME-Requirement-8.txt

echo "|=---------------------=[LOCKED/DISABLE INACTIVE ACCOUNTS]=-----------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.4                                                                            =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=--------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking user password locked of inactive user over 90 days" >> $HOSTNAME-Requirement-8.txt
inact=`lastlog -b 90 2>&1 | tail -n+2 | grep -v '**Never log**' | awk '{print $1}' 2>&1`
for line in $inact
do
lk=`passwd -S $line | awk '{print $2}' 2>&1`
if [ "$lk" = "LK" ]; then
( echo "$line is locked" >> $HOSTNAME-Requirement-8.txt )
else
( echo "$line is not locked" >> $HOSTNAME-Requirement-8.txt )
fi
done

echo "|=-----------------------=[FILE INTEGRETY CHECK]=---------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo "integrety check of both password files" >> $HOSTNAME-Requirement-8.txt
pwck -r >> $HOSTNAME-Requirement-8.txt 2>&1


echo "|=-----------------------=[FILE PERMISSION CHECK]=-------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1                                                                              =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking Permission of passwd file" >> $HOSTNAME-Requirement-8.txt
ls -alth /etc/passwd  >> $HOSTNAME-Requirement-8.txt
echo "===============================================" >>$HOSTNAME-Requirement-8.txt
echo "Checking Permission of shadow file" >> $HOSTNAME-Requirement-8.txt
ls -alth /etc/shadow  >> $HOSTNAME-Requirement-8.txt
echo "===============================================" >>$HOSTNAME-Requirement-8.txt
echo "Checking no other user has read access to shadow file" >> $HOSTNAME-Requirement-8.txt
sh=`ls -alth /etc/shadow | awk '{print $3}' 2>&1` >> $HOSTNAME-Requirement-8.txt
[[ "$sh" = "root" ]] && echo "Only root user has permission on shadow file" >> $HOSTNAME-Requirement-8.txt || echo "$sh user has permission" >> $HOSTNAME-Requirement-8.txt
gr=`ls -alth /etc/shadow | awk '{print $4}' 2>&1` >> $HOSTNAME-Requirement-8.txt
[[ "$sh" = "root" ]] && echo "Only root group has permission on shadow file" >> $HOSTNAME-Requirement-8.txt || echo "$gr group has permission" >> $HOSTNAME-Requirement-8.txt

echo "|=-----------------------=[ENABLED LOCAL ACCOUNTS]=------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.4                                                                            =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
awk -F: '$NF!~/\/!false$/ && $NF!~/\/!nologin$/' /etc/passwd  >> $HOSTNAME-Requirement-8.txt 2>&1
echo "" >>   $HOSTNAME-Requirement-8.txt


echo "|=-----------------------=[DISABLED LOCAL ACCOUNTS]=-----------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.4                                                                            =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "---accounts not allowed to logon---" >>   $HOSTNAME-Requirement-8.txt
awk -F: '$NF!~/\/!nologin$/' /etc/passwd >> $HOSTNAME-Requirement-8.txt 2>&1
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "---accounts with password disabled/Not able to logon---" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/shadow |grep '!' >> $HOSTNAME-Requirement-8.txt 2>&1
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=---------------------------=[PAM AUTH ENABLE]=----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking PAM is enabled in sshd_config file" >>   $HOSTNAME-Requirement-8.txt
[[ "`cat /etc/ssh/sshd_config 2>&1 | grep UsePAM | grep -v "#" | awk '{print $2}'`" == "yes" ]] && echo "PAM authentication is enabled in sshd_config file" >> $HOSTNAME-Requirement-8.txt || echo "PAM authentication is not enabled in sshd_config file" >> $HOSTNAME-Requirement-8.txt

echo "|=---------------------------=[ACCOUNT LOCKOUT]=----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.6                                                                             =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=--------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo " This checks /etc/pam.d/system-auth and /etc/pam.d/password-auth to see if a pam_faillock.so line is set " >>  $HOSTNAME-Requirement-8.txt 
sysauth1=`sudo cat /etc/pam.d/system-auth 2>&1 | grep faillock`
passauth1=`sudo cat /etc/pam.d/password-auth 2>&1 | grep faillock`
if [[ ! "$sysauth1" && ! "$passauth1" ]]
then
	echo " pam.d/system-auth and pam.d/password-auth dont have any Password lockout attempt settings!"  >>   $HOSTNAME-Requirement-8.txt 
fi
if [[ ! -z "$sysauth1" ]]
then
	echo "pam.d/system-auth has the setting as follows:" >>   $HOSTNAME-Requirement-8.txt 
	echo $sysauth1 >>   $HOSTNAME-Requirement-8.txt 
fi
if [[ ! -z "$passauth1" ]]
then
	echo "pam.d/password-auth has the setting as follows:" >>   $HOSTNAME-Requirement-8.txt 
	echo $passauth1 >>   $HOSTNAME-Requirement-8.txt 
fi
echo "" >>   $HOSTNAME-Requirement-8.txt

echo " This checks /etc/pam.d/common-password and /etc/pam.d/common-auth to see if a pam_faillock.so line is set " >>   $HOSTNAME-Requirement-8.txt 
cmnps1=`sudo cat /etc/pam.d/common-password 2>&1 | grep faillock`
cmnauth1=`sudo cat /etc/pam.d/common-auth 2>&1 | grep faillock`
if [[ ! "$sysauth1" && ! "$passauth1" ]]
then
	echo " pam.d/common-auth and pam.d/common-password dont have any Password lockout attempt settings!"  >>   $HOSTNAME-Requirement-8.txt 
fi
if [ ! -z "$cmnps1" ]
then
	echo "pam.d/common-password has the setting as follows:" >>   $HOSTNAME-Requirement-8.txt 
	echo $cmnps1 >>   $HOSTNAME-Requirement-8.txt 
fi
if [ ! -z "$cmnauth1" ]
then
	echo "pam.d/common-auth has the setting as follows:" >>   $HOSTNAME-Requirement-8.txt 
	echo $cmnauth1 >>   $HOSTNAME-Requirement-8.txt 
fi
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=----------------------=[ACCOUNT LOCKOUT DURATION]=--------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.7                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "::This Checks Account Lockout duration as set in PAM::"  >>   $HOSTNAME-Requirement-8.txt
cat /etc/pam.d/system-auth 2>&1 |grep "unlock_time*" >>   $HOSTNAME-Requirement-8.txt || cat /etc/common-auth 2>&1 | grep "unlock_time*" >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt


echo "|=----------------------------=[SESSION TIMEOUT]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.8                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 

echo "--[ Console timeout ]" >>   $HOSTNAME-Requirement-8.txt 
echo "This setting is intended to log a user out of the console if inactive" >>   $HOSTNAME-Requirement-8.txt 
logout1=`cat ~/.bashrc 2>&1 |grep TMOUT `
logout2=`cat ~/.bash_profile 2>&1 |grep TMOUT `
if [[ ! "$logout1" && ! "$logout2" ]]
then
	echo "No Console timeout settings found in bashrc or bash_profile, This does not mean there is no console timeout set as there may be other scripts to do this! " >>  $HOSTNAME-Requirement-8.txt
fi

if [ ! -z "$logout1" ]
then
	echo ".bashrc :: Time out settings in seconds:$logout1" >>   $HOSTNAME-Requirement-8.txt
        [[ "$logout1" == "900" ]] && echo "Session time out as per standards" >> $HOSTNAME-Requirement-8.txt || echo "Session timeout not per standards" >> $HOSTNAME-Requirement-8.txt
fi
if [ ! -z "$logout2" ]
then
	echo ".bash_profile :: Time out settings in seconds:$logout2" >>   $HOSTNAME-Requirement-8.txt
        [[ "$logout2" == "900" ]] && echo "Session time out as per standards" >> $HOSTNAME-Requirement-8.txt || echo "Session timeout not per standards" >> $HOSTNAME-Requirement-8.txt
fi

echo "--[ SSH Timeout ]" >>   $HOSTNAME-Requirement-8.txt
echo "This setting logs a SSH user out after a period of time" >>   $HOSTNAME-Requirement-8.txt

echo "Alive interval" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/ssh/sshd_config 2>&1| grep ClientAliveInterval >>   $HOSTNAME-Requirement-8.txt
echo "Client alive count" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/ssh/sshd_config 2>&1| grep  ClientAliveCountMax >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=---------------------=[PASSWORD STORE CONFIGURATION]=----------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.1                                               =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo "this checks /etc/pam.d/system-auth to see password encryption settings" >>   $HOSTNAME-Requirement-8.txt
encryp1=`sudo cat /etc/pam.d/system-auth 2>&1 |grep pam_unix.so`
if [[ $encryp1 =~ sha512 ]]
then 
	echo `sudo cat /etc/pam.d/system-auth 2>&1 |grep sha512` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ sha256 ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>&1 |grep sha256` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ bigcrypt ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>&1 |grep bigcrypt` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ blowfish ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>&1 |grep blowfish` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ md5 ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>&1 |grep md5` >>   $HOSTNAME-Requirement-8.txt
else
	echo "No Encryption found /etc/pam.d/system-auth matching pam_unix.so" >>   $HOSTNAME-Requirement-8.txt
fi

echo "this checks /etc/pam.d/common-auth to see password encryption settings" >>   $HOSTNAME-Requirement-8.txt
encryp2=`sudo cat /etc/pam.d/common-auth 2>&1 |grep pam_unix.so`
if [[ $encryp2 =~ sha512 ]]
then 
	echo `sudo cat /etc/pam.d/common-auth 2>&1 |grep sha512` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp2 =~ sha256 ]]
then
	echo `sudo cat /etc/pam.d/common-auth 2>&1 |grep sha256` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp2 =~ bigcrypt ]]
then
	echo `sudo cat /etc/pam.d/common-auth 2>&1 |grep bigcrypt` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp2 =~ blowfish ]]
then
	echo `sudo cat /etc/pam.d/common-auth 2>&1 |grep blowfish` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp2 =~ md5 ]]
then
	echo `sudo cat /etc/pam.d/common-auth 2>&1 |grep md5` >>   $HOSTNAME-Requirement-8.txt
else
	echo "No Encryption found /etc/pam.d/common-auth matching pam_unix.so" >>   $HOSTNAME-Requirement-8.txt
fi

echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "This Checks /etc/passwd and /etc/shadow to see what permissions are set on them" >>   $HOSTNAME-Requirement-8.txt
passwd1=`stat -c %a /etc/passwd 2>&1`
echo "/etc/passwd has the  permissions set to $passwd1" >>   $HOSTNAME-Requirement-8.txt
shadow1=`stat -c %a /etc/shadow 2>&1`
echo "/etc/shadow has the permissions set to $shadow1" >>   $HOSTNAME-Requirement-8.txt
echo "The other group should never have read access to the shadow file, as it contains the hashed passwords." >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=--------------------------=[PASSWORD LENGTH]=-------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.3                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
#Checks password minlen in pam
minlen1=`sudo cat /etc/pam.d/common-password 2>&1|grep minlen `
#checks password minlen in /etc/security/pwquality.conf
minlen2=`sudo cat /etc/security/pwquality.conf 2>&1|grep minlen`
#checks password minlen in /etc/pam.d/system-auth
minlen3=`sudo cat /etc/pam.d/system-auth 2>&1|grep minlen`
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
lowcase0=`grep pam_pwquality.so /etc/pam.d/common-password 2>&1| grep lcredit`
upcase0=`grep pam_pwquality.so /etc/pam.d/common-password 2>&1|grep ucredit`
digit0=`grep pam_pwquality.so /etc/pam.d/common-password 2>&1|grep dcredit`
othchar0=`grep pam_pwquality.so /etc/pam.d/common-password 2>&1|grep ocredit`
if [ ! -f "$file0" ]
then
	echo " no file found for $file0" >>   $HOSTNAME-Requirement-8.txt 
elif [[ -f "$file0" && ! "$lowcase0" ]]
then
	echo "/etc/pam.d/common-password has no lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$lowcase0" =~ "#" ]]
then
	echo "/etc/pam.d/common-password has Lower case requirement set as $lowcase0, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/common-password has lowercase requirement set as $lowcase0" >>   $HOSTNAME-Requirement-8.txt 
fi

if [[ ! -f "$file0" ]]
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

if [[ ! -f "$file0" ]]
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

if [[ ! -f "$file0" ]]
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
lowcase1=`grep lcredit /etc/security/pwquality.conf 2>&1`
upcase1=`grep ucredit /etc/security/pwquality.conf 2>&1`
digit1=`grep dcredit /etc/security/pwquality.conf 2>&1`
othchar1=`grep ocredit /etc/security/pwquality.conf 2>&1`
if [[ ! -f "$file1" ]]
then
	echo " no file found for '$file1'"
elif [[ -f "$file1" && ! "$lowcase1" ]]
then
	echo "/etc/security/pwquality.conf has no lowercase Requirement in password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$lowcase1" =~ "#" ]]
then
	echo "/etc/security/pwquality.conf has Lower case requirement set as $lowcase1, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/security/pwquality.conf has lowercase requirement set as $lowcase1" >>   $HOSTNAME-Requirement-8.txt 
fi

if [[ ! -f "$file1" ]]
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

if [[ ! -f "$file1" ]]
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

if [[ ! -f "$file1" ]]
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

file2=/etc/pam.d/system-auth 2>&1
lowcase2=`grep lcredit /etc/pam.d/system-auth 2>&1 |grep pam_cracklib.so`
upcase2=`grep ucredit /etc/pam.d/system-auth 2>&1 |grep pam_cracklib.so`
digit2=`grep dcredit /etc/pam.d/system-auth 2>&1 |grep pam_cracklib.so`
othchar2=`grep ocredit /etc/pam.d/system-auth 2>&1 |grep pam_cracklib.so`

if [[ ! -f $file2 ]]
then
	echo "no file found $file2"
elif [[ -f $file2 && ! $lowcase2 ]]
then
	echo "/etc/pam.d/system-auth has no lowercase Requirement password" >>   $HOSTNAME-Requirement-8.txt 
elif [[ "$lowcase2" =~ "#" ]]
then
	echo "/etc/pam.d/system-auth has lowercase requirement set as $lowcase2, But its commented out! " >>   $HOSTNAME-Requirement-8.txt 
else
	echo "/etc/pam.d/system-auth has lowercase requirement set as $lowcase2" >>   $HOSTNAME-Requirement-8.txt 
fi

if [[ ! -f "$file2" ]]
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

if [[ ! -f "$file2" ]]
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

if [[ ! -f "$file2" ]]
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
passthesh1=`cat /etc/login.defs 2>&1|grep PASS_MAX_DAYS`
passthesh2=`grep pam_unix.so /etc/pam.d/common-password 2>&1|grep remember=*`
if [[ ! -z "$passthesh1" ]]
then
	echo "Threshold setting in /etc/login.defs:" >>   $HOSTNAME-Requirement-8.txt 
	echo "$passthesh1" >>   $HOSTNAME-Requirement-8.txt 
fi
if [[ ! -z "$passthesh2" ]]
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
grep pam_unix.so /etc/pam.d/common-password 2>&1|grep remember=* >>   $HOSTNAME-Requirement-8.txt
grep pam_unix.so /etc/pam.d/system-auth 2>&1|grep remember=* >>   $HOSTNAME-Requirement-8.txt

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=--------------------------=[TWO FACTOR AUTHENTICATION]=---------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.3                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking 2 factor auth configuration" >> $HOSTNAME-Requirement-8.txt
cp=/etc/pam.d/common-password
pa=/etc/pam.d/password-auth
ca=/etc/pam.d/common-auth
sa=/etc/pam.d/system-auth
if [[ -a $cp ]]
then 
( 
egrep -w 'pam_google_authenticator.so|pam_yubikey.so' $cp 2>&1
[ ! $@ ] && echo "no authenticator config exist in common-password file" >> $HOSTNAME-Requirement-8.txt || echo $@ >> $HOSTNAME-Requirement-8.txt
)
elif [[ -a $pa ]]
then
( 
egrep -w 'pam_google_authenticator.so|pam_yubikey.so' $pa 2>&1 
[ ! $@ ] && echo "no authenticator config exist in password-auth" >> $HOSTNAME-Requirement-8.txt || echo $@ >> $HOSTNAME-Requirement-8.txt
)
else
(
echo "both file not exist" >> $HOSTNAME-Requirement-8.txt
)
fi

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOGIN SHELLS]=-------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo "checking which shells are valid/allowd" >> $HOSTNAME-Requirement-8.txt
cat /etc/shells >> $HOSTNAME-Requirement-8.txt 2>&1
echo "" >> $HOSTNAME-Requirement-8.txt

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOCAL ACCOUNTS]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo " this pulls information from the /etc/passwd file! "  >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/passwd | awk -F: '{ print $1}' >> $HOSTNAME-Requirement-8.txt 2>&1
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt


echo "|=-------------------------=[LOCAL ADMINISTRATORS]=---------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "lists Users in the wheel group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group wheel >> $HOSTNAME-Requirement-8.txt 2>&1
echo "lists Users in the admin group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group admin >> $HOSTNAME-Requirement-8.txt 2>&1
echo "lists Users in the sudo group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group sudo >> $HOSTNAME-Requirement-8.txt 2>&1
echo "lists Users in the staff group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group staff >> $HOSTNAME-Requirement-8.txt 2>&1
echo "lists Users in the sudoers group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group sudoers >> $HOSTNAME-Requirement-8.txt 2>&1

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOCAL GROUPS]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                                               =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "This pulls information from the /etc/group file!"  >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/group | awk -F: '{ print $1}' >> $HOSTNAME-Requirement-8.txt 2>&1
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo -e "\e[1;32mDone with Requirement 8\e[0m"
echo -e "\e[1;35mAudit Requirement 9 manually\e[0m"
echo -e "\e[1;35mSkipping req 9\e[0m"
echo -e "\e[1;34mGetting Requirement 10\e[0m"

echo "|=-----------------------=[LOGGING CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.1.1                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo cat /etc/rsyslog.conf >> $HOSTNAME-Requirement-10.txt 2>&1
echo "===============================================" >>$HOSTNAME-Requirement-10.txt
sudo cat /etc/syslog.conf >> $HOSTNAME-Requirement-10.txt 2>&1
#echo "===============================================" >>$HOSTNAME-Requirement-10.txt
#sudo cat /etc/rsyslog.d/* >> $HOSTNAME-Requirement-10.txt 2>&1
#echo "===============================================" >>$HOSTNAME-Requirement-10.txt
#sudo cat /var/log/syslog >> $HOSTNAME-Requirement-10.txt 2>&1
#echo "===============================================" >>$HOSTNAME-Requirement-10.txt
#sudo cat /var/log/auth.log 2>/dev/#null >> $HOSTNAME-Requirement-10.txt
#echo "===============================================" >>$HOSTNAME-Requirement-10.txt
#sudo cat /var/log/secure >> $HOSTNAME-Requirement-10.txt 2>&1
echo "" >> $HOSTNAME-Requirement-10.txt

echo "|=-----------------------=[EVENTLOG - SERVICE STATUS]=------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo service rsyslog status >> $HOSTNAME-Requirement-10.txt 2>&1
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt
sudo service syslog status >> $HOSTNAME-Requirement-10.txt 2>&1

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=---------------------------=[LOG CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo " -- This Checks the logging configuration /etc/rsyslog.conf -- " >> $HOSTNAME-Requirement-10.txt
echo "authpriv: Messages coming from authorization and security related events" >> $HOSTNAME-Requirement-10.txt
auth1=`grep auth /etc/rsyslog.conf 2>&1`
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
authpriv1=`grep authpriv /etc/rsyslog.conf 2>&1`
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
kern1=`grep kern /etc/rsyslog.conf 2>&1`
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
mail1=`grep mail /etc/rsyslog.conf 2>&1`
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
cron1=`grep cron /etc/rsyslog.conf 2>&1`
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
news1=`grep news /etc/rsyslog.conf 2>&1`
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
lpr1=`grep lpr /etc/rsyslog.conf 2>&1`
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
user1=`grep user /etc/rsyslog.conf 2>&1`
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
echo "this checks /etc/logrotate.conf settings" >> $HOSTNAME-Requirement-10.txt
sudo cat /etc/logrotate.conf | grep -v "#" >> $HOSTNAME-Requirement-10.txt 2>&1

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=------------------------------=[Audit Log]=---------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "Audit service status" >> $HOSTNAME-Requirement-10.txt
sudo auditctl -s >> $HOSTNAME-Requirement-10.txt 2>&1
echo "=================================================" >> $HOSTNAME-Requirement-10.txt
sudo systemctl is-enabled auditd >> $HOSTNAME-Requirement-10.txt 2>&1 || service auditd status >> $HOSTNAME-Requirement-10.txt 2>&1 || chkconfig auditd >> $HOSTNAME-Requirement-10.txt 2>&1
echo "" >> $HOSTNAME-Requirement-10.txt
echo "=================================================" >> $HOSTNAME-Requirement-10.txt
echo "Audit Configuration" >> $HOSTNAME-Requirement-10.txt
sudo cat /etc/audit/auditd.conf | grep -v "#" >> $HOSTNAME-Requirement-10.txt 2>&1

echo "|=------------------------------=[EVENT WITH AUDIT]=--------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "Record events that modify Date and Time" >> $HOSTNAME-Requirement-10.txt
grep time-change /etc/audit/audit.rules >> $HOSTNAME-Requirement-10.txt 2>&1

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=-------------------------=[NTP - SERVICE STATUS]=---------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4                                                 =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo systemctl status ntp >> $HOSTNAME-Requirement-10.txt 2>&1 || systemctl status ntpdate >> $HOSTNAME-Requirement-10.txt 2>&1
echo "" >>   $HOSTNAME-Requirement-10.txt

echo "|=---------------------------=[NTP CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo cat /etc/ntp.conf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-10.txt 2>&1 || sudo cat /etc/default/ntpdate 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-10.txt 2>&1 || sudo cat /etc/xntp.conf 2>&1 | grep -v "#" >> $HOSTNAME-Requirement-10.txt 2>&1
echo "" >>   $HOSTNAME-Requirement-10.txt

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=---------------------------=[NTP PEERS]=------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo ntpq -p >> $HOSTNAME-Requirement-10.txt 2>&1
echo "==========================================================" >> $HOSTNAME-Requirement-10.txt
sudo ntpq -r >> $HOSTNAME-Requirement-10.txt 2>&1
echo "==========================================================" >> $HOSTNAME-Requirement-10.txt
sudo ntpdc -p >> $HOSTNAME-Requirement-10.txt 2>&1
echo "">>   $HOSTNAME-Requirement-10.txt

echo "|=---------------------------=[NTP SYNC STATUS]=------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo ntpstat >> $HOSTNAME-Requirement-10.txt 2>&1
echo "==========================================================" >> $HOSTNAME-Requirement-10.txt
sudo hwclock --systohc >> $HOSTNAME-Requirement-10.txt 2>&1
echo "">>   $HOSTNAME-Requirement-10.txt

echo -e "\e[1;32mDone with Requirememnt 10\e[0m"
echo -e "\e[1;35mAudit Requirement 11 manually\e[0m"
echo -e "\e[1;35mSkipping req 11\e[0m"
echo -e "\e[1;35mAudit Requirement 12 manually\e[0m"
echo -e "\e[1;35mSkipping req 12\e[0m"
duration=$(echo "$(date +%s.%N) - $start" | bc)
execution_time=`printf "%.2f seconds" $duration`
echo -e "\e[1;32mTest completes in $execution_time\e[0m"
echo -e "\e[1;34mEvidence of tests has been collected for review in $(pwd)\e[0m"

