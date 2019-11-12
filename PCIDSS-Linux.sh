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

echo "Test Starts"
start=$(date +%s.%N)

echo "Please wait, this may take some time"
echo "Getting System info"
echo "|=--------------------------=[SYSTEM INFORMATION]=---------------------------=|" >> $HOSTNAME-SystemInfo.txt
sudo hostnamectl 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Kernel Name" >> $HOSTNAME-SystemInfo.txt
sudo uname -s 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Kernel Release" >> $HOSTNAME-SystemInfo.txt
sudo uname -r 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Host Name" >> $HOSTNAME-SystemInfo.txt
echo $HOSTNAME 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Node Name" >> $HOSTNAME-SystemInfo.txt
sudo uname -n 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Operating System" >> $HOSTNAME-SystemInfo.txt
sudo uname -o 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Processor" >> $HOSTNAME-SystemInfo.txt
sudo uname -p 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Hardware Platform" >> $HOSTNAME-SystemInfo.txt
sudo uname -i 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Machine Name" >> $HOSTNAME-SystemInfo.txt
sudo uname -m 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Hardware" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo lshw -short 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Network Information" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo ifconfig 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "CPU Input/Output statastics" >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
sudo iostat 2>/dev/null  >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Show how long the system has been running + load" >> $HOSTNAME-SystemInfo.txt
uptime 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Show system reboot history" >> $HOSTNAME-SystemInfo.txt
last reboot 2>/dev/null >> $HOSTNAME-SystemInfo.txt
#echo "--------------------" >> $HOSTNAME-SystemInfo.txt
#echo "Display messages in kernel ring buffer">> $HOSTNAME-SystemInfo.txt
#dmesg 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display CPU information" >> $HOSTNAME-SystemInfo.txt
cat /proc/cpuinfo 2>/dev/null >> $HOSTNAME-SystemInfo.txt || less /proc/cpuinfo 2>/dev/null >> $HOSTNAME-SystemInfo.txt || lscpu 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display memory information" >> $HOSTNAME-SystemInfo.txt || less /proc/cpuinfo 2>/dev/null >> $HOSTNAME-SystemInfo.txt
cat /proc/meminfo 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display free and used memory" >> $HOSTNAME-SystemInfo.txt
free -h 2>/dev/null >> $HOSTNAME-SystemInfo.txt 
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display PCI devices" >> $HOSTNAME-SystemInfo.txt
lspci -tv 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display USB devices" >> $HOSTNAME-SystemInfo.txt
lsusb -tv 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display DMI/SMBIOS hardware info from the BIOS" >> $HOSTNAME-SystemInfo.txt
dmidecode 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Show info about disk sda" >> $HOSTNAME-SystemInfo.txt
hdparm -i /dev/sda 2>/dev/null >> $HOSTNAME-SystemInfo.txt
#echo "--------------------" >> $HOSTNAME-SystemInfo.txt
#echo "Perform a read speed test on disk sda" >> $HOSTNAME-SystemInfo.txt
#hdparm -tT /dev/sda 2>/dev/null >> $HOSTNAME-SystemInfo.txt
#echo "--------------------" >> $HOSTNAME-SystemInfo.txt
#echo "Test for unreadable blocks on disk sda" >> $HOSTNAME-SystemInfo.txt
#badblocks -s /dev/sda 2>/dev/null >> $HOSTNAME-SystemInfo.txt
#echo "--------------------" >> $HOSTNAME-SystemInfo.txt
#echo "List all open files on the system" >> $HOSTNAME-SystemInfo.txt
#sudo lsof 2>/dev/null >> $HOSTNAME-SystemInfo.txt || lsof | less >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display whois information for domain" >> $HOSTNAME-SystemInfo.txt
sudo whois `hostname` 2>/dev/null >> $HOSTNAME-SystemInfo.txt
#echo "--------------------" >> $HOSTNAME-SystemInfo.txt
#echo "Display DNS information for domain" >> $HOSTNAME-SystemInfo.txt
#sudo dig `hostname` 2>/dev/null >> $HOSTNAME-SystemInfo.txt
echo "--------------------" >> $HOSTNAME-SystemInfo.txt
echo "Display disk usage for all files and directories" >> $HOSTNAME-SystemInfo.txt
sudo du -sh 2>/dev/null >> $HOSTNAME-SystemInfo.txt


echo "|=----------------------=[ACTIVE DIRECTORY STATUS]=--------------------------=|" >> $HOSTNAME-SystemInfo.txt

dom0=`realm list domain-name -n`
if [ "$dom0" = "" ]
then
    echo "No Domain Set/Joined $dom0 " >> $HOSTNAME-SystemInfo.txt
else
    echo "The domain is set to : $dom0 " >> $HOSTNAME-SystemInfo.txt
fi

echo "Done with system info"
echo "Getting Requirement 1"

#echo "|=----------------=[FIREWALL - SERVICE STATUS]=------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.1                                                 =|" >>   $HOSTNAME-Requirement-1.txt 
#echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
sudo service firewalld status 2>/dev/null >> $HOSTNAME-Requirement-1.txt || sudo ufw status verbose 2>/dev/null >> $HOSTNAME-Requirement-1.txt || service iptables status 2>/dev/null >> $HOSTNAME-Requirement-1.txt

#echo "|=------------------=[FIREWALL CONFIGURATION]=----------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.1                                                 =|" >>   $HOSTNAME-Requirement-1.txt 
#echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "########## INPUT rules ###########" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L INPUT >> $HOSTNAME-Requirement-1.txt
echo "########## OUTPUT rules ###########" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L OUTPUT >> $HOSTNAME-Requirement-1.txt
echo "########## FORWARD rules ###########" >> $HOSTNAME-Requirement-1.txt
sudo iptables -L FORWARD >>   $HOSTNAME-Requirement-1.txt

#echo "|=------------------=[FIREWALL RULES LIST]=----------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.1                                                =|" >>   $HOSTNAME-Requirement-1.txt 
#echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
sudo ufw status numbered 2> /dev/null >> $HOSTNAME-Requirement-1.txt || sudo firewall-cmd --list-all 2> /dev/null >> $HOSTNAME-Requirement-1.txt 

echo "|= Related requirements: 1.1.4                                              =|" >> $HOSTNAME-Requirement-1.txt
echo "|=----------------------=[LIST OF ZONES]=-----------------------------------=|" >> $HOSTNAME-Requirement-1.txt
echo "firewall-cmd --get-zones" >> $HOSTNAME-Requirement-1.txt
firewall-cmd --get-zones 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "========================================================================" >> $HOSTNAME-Requirement-1.txt
echo "firewall-cmd --get-active-zones" >> $HOSTNAME-Requirement-1.txt
`firewall-cmd --get-active-zones` 2>/dev/null >> $HOSTNAME-Requirement-1.txt
dmz=`firewall-cmd --get-active-zones | grep dmz`
[ ! $dmz ] && echo "DMZ is not activated" >> $HOSTNAME-Requirement-1.txt || echo "DMZ is activated" >> $HOSTNAME-Requirement-1.txt
echo "========================================================================" >> $HOSTNAME-Requirement-1.txt
echo "firewall-cmd --zone=dmz --list-ports" >> $HOSTNAME-Requirement-1.txt
    `firewall-cmd --zone=dmz --list-ports` 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "======================================================================="
 >> $HOSTNAME-Requirement-1.txt
    echo "firewall-cmd --zone=dmz --list-protocols" >> $HOSTNAME-Requirement-1.txt
    `firewall-cmd --zone=dmz --list-protocols` 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
    echo "firewall-cmd --zone=dmz --list-services" >> $HOSTNAME-Requirement-1.txt
    `firewall-cmd --zone=dmz --list-services` 2>/dev/null >> $HOSTNAME-Requirement-1.txt


echo "|= Related requirements: 1.1.6                                              =|" >> $HOSTNAME-Requirement-1.txt
echo "|=----------------------=[TELNET SERVICE STATUS]=---------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Make sure all insecure non console access/telnet is disabled or stopped" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled telnet.socket >> $HOSTNAME-Requirement-1.txt 2>/dev/null || chkconfig telnet.socket 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "==============================================" >>$HOSTNAME-Requirement-1.txt
systemctl status telnet 2>/dev/null >> $HOSTNAME-Requirement-1.txt || service telnet status 2>/dev/null >> $HOSTNAME-Requirement-1.txt 
echo "==============================================" >>$HOSTNAME-Requirement-1.txt
netstat -lataupen | grep telnet >> $HOSTNAME-Requirement-1.txt 2>/dev/null
echo "==============================================" >>$HOSTNAME-Requirement-1.txt
ps -ef | grep telnet >> $HOSTNAME-Requirement-1.txt 2>/dev/null

echo "|=----------------------=[RSH SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Make sure all insecure non console access/rsh is disabled or stopped" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled rsh.socket 2>/dev/null >>$HOSTNAME-Requirement-1.txt || chkconfig rsh.socket 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled rlogin.socket 2>/dev/null >>$HOSTNAME-Requirement-1.txt || chkconfig rsh.socket 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled rexec.socket 2>/dev/null >>$HOSTNAME-Requirement-1.txt || chkconfig rexec.socket 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
netstat -na | grep 514 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
ps -ef | grep rsh 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=----------------------=[NFS SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Make sure NFS share is enable at boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled nfs-kernel-server 2>/dev/null $HOSTNAME-Requirement-1.txt|| chkconfig nfs-kernel-server 2>/dev/null >> $HOSTNAME-Requirement-1.txt || systemctl nfs-kernel 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "NFS share service status" >> $HOSTNAME-Requirement-1.txt
systemctl status nfs-kernel-server 2>/dev/null $HOSTNAME-Requirement-1.txt|| chkconfig nfs-kernel-server status 2>/dev/null >> $HOSTNAME-Requirement-1.txt || service nfs-kernel-server status 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "RPCBIND service status" >> $HOSTNAME-Requirement-1.txt
service rpcbind status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status rpcbind  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || chkconfig rpcbind 2>/dev/null >> $HOSTNAME-Requirement-1.txt 
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "NFS-LOCK service status" >> $HOSTNAME-Requirement-1.txt
service nfs-lock status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status nfs-lock 2>/dev/null || chkconfig nfs-lock 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "NFS share configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/exports 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "NFS package installed or not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | grep nfs-common  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | egrep 'nfs-kernel-server|nfs-utils'  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q nfs-utils 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se nfs-common $HOSTNAME-Requirement-1.txt || dnf list nfs-common 2>/dev/null >> $HOSTNAME-Requirement-1.txt


echo "|=----------------------=[PRINTER SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Checking CUPS package is installed or not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | grep cups  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | grep cups  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q cups 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se cups $HOSTNAME-Requirement-1.txt || dnf list cups 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking printing service is enabled on boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled cups 2>/dev/null $HOSTNAME-Requirement-1.txt|| chkconfig cups 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking printing service status" >> $HOSTNAME-Requirement-1.txt
service cups status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status cups  2>/dev/null || chkconfig cups 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking CUPS configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/cups/cupsd.conf 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=----------------------=[FTP SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Checking FTP installed or not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | egrep 'ftp|vsftpd'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | egrep 'ftp|vsftp'   >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q 'ftp|vsftp' 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se ftp vsftp $HOSTNAME-Requirement-1.txt || dnf list ftp vsftp 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking FTP service is enabled on boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled ftp 2>/dev/null $HOSTNAME-Requirement-1.txt|| chkconfig ftp 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking FTP service status" >> $HOSTNAME-Requirement-1.txt
service ftp status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status ftp  2>/dev/null || chkconfig ftp 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking FTP configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/vsftpd/vsftpd.conf 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=----------------------=[TELNET SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Cheking telnet package is installed on not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | egrep 'telnet|telnetd|telnet-server'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | egrep 'telnet|telnetd|telnet-server'  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q telnet 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se telnet 2>/dev/null >> $HOSTNAME-Requirement-1.txt || dnf list telnet 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking telnet service is enabled on boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled telnet 2>/dev/null $HOSTNAME-Requirement-1.txt|| chkconfig telnet 2>/dev/null >> $HOSTNAME-Requirement-1.txt || service telnetd status 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking telnet service status" >> $HOSTNAME-Requirement-1.txt
service telnet status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status telnet  2>/dev/null || chkconfig telnet 2>/dev/null >>$HOSTNAME-Requirement-1.txt


echo "|=----------------------=[SMTP SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Cheking sendmail package is installed on not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | egrep 'sendmail|postfix'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | egrep 'sendmail|postfix'  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q 'sendmail|postfix' 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se 'sendmail|postfix' $HOSTNAME-Requirement-1.txt || dnf list 'sendmail|postfix' 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking senmail/postfix service is enabled on boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled sendmail postfix 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| chkconfig sendmail postfix 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking sendmail/postfix service status" >> $HOSTNAME-Requirement-1.txt
service sendmail postfix status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status sendmail postfix  2>/dev/null || chkconfig sendmail postfix 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking sendmail configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/mail/sendmail.cf 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking postfix configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/postfix/main.cf 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=----------------------=[HTTP SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Checking http is installed or not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | egrep 'httpd|httpd|apache'  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | egrep 'http|httpd|apache'  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q http httpd apache 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se http httpd apache $HOSTNAME-Requirement-1.txt || dnf list httpd httpd apache 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking http service is enabled on boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled http httpd apache 2>/dev/null $HOSTNAME-Requirement-1.txt|| chkconfig http httpd apache 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking http service status" >> $HOSTNAME-Requirement-1.txt
service http httpd apache status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status http httpd apache  2>/dev/null || chkconfig apache http httpd 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking http configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/http/httpd.conf 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=----------------------=[SNMP SERVICE STATUS]=-------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Checking SNMP package is installed or not" >> $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | grep snmpd  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | grep snmpd  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q snmpd 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se snmpd 2>/dev/null >> $HOSTNAME-Requirement-1.txt || dnf list snmpd 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking SNMP service is enabled on boot" >> $HOSTNAME-Requirement-1.txt
systemctl is-enabled snmpd 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| chkconfig snmp 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking SNMP service status" >> $HOSTNAME-Requirement-1.txt
service snmp status 2>/dev/null >> $HOSTNAME-Requirement-1.txt|| systemctl status snmp  2>/dev/null || chkconfig snmp 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "===============================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking SNMP configuration" >> $HOSTNAME-Requirement-1.txt
cat /etc/snmp/snmp.conf 2>/dev/null >> $HOSTNAME-Requirement-1.txt


echo "|=----------------------=[DEVLOPMENT TOOLS PACKAGE]=-----------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt
echo "Make sure Developement tools is not installed already" >> $HOSTNAME-Requirement-1.txt
yum grouplist | grep "Development Tools" 2>/dev/null >> $HOSTNAME-Requirement-1.txt || 
dnf grouplist | grep "Development Tools" 2>/dev/null >> $HOSTNAME-Requirement-1.txt || pacman -Sg Developement Tools 2>/dev/null >> $HOSTNAME-Requirement-1.txt || tasksel --task-desc "Development Tools" 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper info pattern "Development Tools" 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=------------------=[FIREWALLD START AT BOOT]=-----------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.2.2                                        =|" >> $HOSTNAME-Requirement-1.txt 
echo "Checking firewalld enable at boot" >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled firewalld 2>/dev/null >>$HOSTNAME-Requirement-1.txt || chkconfig firewalld 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt 
echo "Checking iptables enable at boot " >>$HOSTNAME-Requirement-1.txt
systemctl is-enabled iptables 2>/dev/null >>$HOSTNAME-Requirement-1.txt || chkconfig iptables 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "=======================================================================" >> $HOSTNAME-Requirement-1.txt
echo "Checking rc.local/pre.up.d file" >>$HOSTNAME-Requirement-1.txt
cat /etc/rc.local 2>/dev/null >> $HOSTNAME-Requirement-1.txt || cat /etc/rc.d/rc.local 2>/dev/null >> $HOSTNAME-Requirement-1.txt || cat /etc/network/if-pre-up.d/iptables 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "Checking cron tab for any firewall run at boot" >>$HOSTNAME-Requirement-1.txt
crontab -l 2>/dev/null | grep *firewall* 2>/dev/null >>$HOSTNAME-Requirement-1.txt

echo "related req 1.3.3">>$HOSTNAME-Requirement-1.txt
echo "Checking configuration of sysctl file" >>$HOSTNAME-Requirement-1.txt
cat /etc/sysctl.conf 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "Checking Source address verification" >>$HOSTNAME-Requirement-1.txt
cat /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "Overwrites the value 0 to 1 to enable source address verification" >>$HOSTNAME-Requirement-1.txt

echo "related req 1.3.5" >>$HOSTNAME-Requirement-1.txt
echo "Permit only “established” connections into the network" >>$HOSTNAME-Requirement-1.txt

echo "related req 1.3.7" >>$HOSTNAME-Requirement-1.txt
echo "Do not disclose private IP addresses and routing information to unauthorized parties" >>$HOSTNAME-Requirement-1.txt
echo "Checking RFC1918 space is configured or not" >>$HOSTNAME-Requirement-1.txt
ip -o addr show |   grep -v 'inet6' |   grep -v 'scope host' |   awk '{print $4}' |   cut -d '/' -f 1 |   grep -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' 2>/dev/null >>$HOSTNAME-Requirement-1.txt
echo "==================================================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking NAT is configured or not" >>$HOSTNAME-Requirement-1.txt
echo "Checking ipforwarding enabled or not"  >>$HOSTNAME-Requirement-1.txt
cat /proc/sys/net/ipv4/ip_forward  >>$HOSTNAME-Requirement-1.txt
echo "enable if value is 1, disable if value is 0"  >>$HOSTNAME-Requirement-1.txt
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt
echo "pattern matching in iptables rule proving NAT configured" >>$HOSTNAME-Requirement-1.txt
egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/sysconfig/iptables 2>/dev/null >>$HOSTNAME-Requirement-1.txt || egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/iptables.up.rules 2>/dev/null >> $HOSTNAME-Requirement-1.txt 
echo "==================================================================" >>$HOSTNAME-Requirement-1.txt
echo "Checking IPTABLE module ip_conntrack_ftp is loaded or not" >>$HOSTNAME-Requirement-1.txt
cat /etc/sysconfig/iptables-config 2>/dev/null | grep IPTABLES_MODULES= >>$HOSTNAME-Requirement-1.txt
echo "==================================================================" >> $HOSTNAME-Requirement-1.txt
echo "Checking proxy server is used" >> $HOSTNAME-Requirement-1.txt
cat /etc/profile | grep http_proxy 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "Checking env variable for any proxy setting" >> $HOSTNAME-Requirement-1.txt
env | grep -i proxy 2>/dev/null >> $HOSTNAME-Requirement-1.txt
echo "==================================================================" >>$HOSTNAME-Requirement-1.txt
echo "firewall config" >>$HOSTNAME-Requirement-1.txt
cat /etc/iptables.up.rules 2>/dev/null >> $HOSTNAME-Requirement-1.txt  || cat /etc/sysconfig/iptbles 2>/dev/null >> $HOSTNAME-Requirement-1.txt 

echo "|=------------------=[IPTABLES INSTALLED]=----------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.4                                                 =|" >>   $HOSTNAME-Requirement-1.txt
dpkg -l 2>/dev/null | grep iptables*  >> $HOSTNAME-Requirement-1.txt|| rpm -qa 2>/dev/null | grep iptables*  >> $HOSTNAME-Requirement-1.txt 2>/dev/null || pacman -Q iptables* 2>/dev/null >> $HOSTNAME-Requirement-1.txt || zypper se iptables* 2>/dev/null >> $HOSTNAME-Requirement-1.txt || dnf list iptables* 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "|=------------------=[SHOW PORT CONFLICT]=----------------------=|" >>   $HOSTNAME-Requirement-1.txt 
echo "|= Related requirements: 1.4                                                 =|" >>   $HOSTNAME-Requirement-1.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-1.txt 
netstat -plnt 2>/dev/null >> $HOSTNAME-Requirement-1.txt

echo "Done with requirement 1"
echo "Getting Requirement 2"

echo "|=-----------------------=[USER ACCOUNTS]=-----------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related Requirements: 2.1                                                 =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "file /etc/passwd configuration" >>   $HOSTNAME-Requirement-2.txt  
cat /etc/passwd >>   $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[GROUP ACCOUNTS]=---------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related Requirements: 2.1                                                 =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "file /etc/group configuration" >>   $HOSTNAME-Requirement-2.txt 
cat /etc/group >>  $HOSTNAME-Requirement-2.txt


echo "|=-------------------------=[INSTALLED SOFTWARE]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo apt list --installed >> $HOSTNAME-Requirement-2.txt  2> /dev/null|| sudo rpm -qa >> $HOSTNAME-Requirement-2.txt 2> /dev/null|| sudo dpkg-query >> $HOSTNAME-Requirement-2.txt 2> /dev/null||sudo yum list installed >> $HOSTNAME-Requirement-2.txt2> /dev/null || sudo pacman -Q >> $HOSTNAME-Requirement-2.txt 2> /dev/null

echo "|=------------------------=[TOP CONTROL GROUPS]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "-x" | systemd-cgtop 2>/dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=------------------------=[SERVICES RUNNING]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo systemctl --state=running 2> /dev/null >> $HOSTNAME-Requirement-2.txt || netstat -tupln 2> /dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=------------------------=[SERVICES ENABLED]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
systemctl list-unit-files --state=enabled 2>/dev/null >> $HOSTNAME-Requirement-2.txt|| chkconfig --list 2>/dev/null >> $HOSTNAME-Requirement-2.txt || service --list-all 2>/dev/null >> $HOSTNAME-Requirement-2.txt
echo "========================[ All unit files with load status ]======================" >> $HOSTNAME-Requirement-2.txt
systemctl list-unit-files --type service 2>/dev/null >> $HOSTNAME-Requirement-2.txt || chkconfig --list 2>/dev/null >> $HOSTNAME-Requirement-2.txt
echo "========================[ All loaded services status ]======================" >> $HOSTNAME-Requirement-2.txt
systemctl list-units --type service 2>/dev/null >> $HOSTNAME-Requirement-2.txt || chkconfig --list 2>/dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=------------------------=[PROCESSES RUNNING]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt  
sudo ps -ef 2>/dev/null >>   $HOSTNAME-Requirement-2.txt || sudo top -c 2>/dev/null >> $HOSTNAME-Requirement-2.txt || sudo ps -aux  >> $HOSTNAME-Requirement-2.txt

echo "|=------------------------=[XINETD SERVICE]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt  
sudo service xinetd status 2>/dev/null >>   $HOSTNAME-Requirement-2.txt || sudo systemctl status xinetd 2>/dev/null >>   $HOSTNAME-Requirement-2.txt || service xinetd status 2>/dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[PORTS IN LISTENING STATE]=------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo lsof -i -P -n | grep LISTEN 2>/dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[NETWORK CONNECTION]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo netstat -a 2> /dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[NETWORK INTERFACES]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo ip link show 2> /dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=-----------------------=[KERNEL ROUTE TABLE]=------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.2                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo netstat -r 2>/dev/null >> $HOSTNAME-Requirement-2.txt

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
sudo grep PASS_WARN_AGE /etc/login.defs 2>/dev/null >>    $HOSTNAME-Requirement-2.txt 

echo "--[ Interactive logon: Message text for users attempting to log on ]" >>   $HOSTNAME-Requirement-2.txt 
echo "checks /etc/motd" >>   $HOSTNAME-Requirement-2.txt
sudo cat /etc/motd >>   $HOSTNAME-Requirement-2.txt
echo "" >>   $HOSTNAME-Requirement-2.txt
echo "checks /etc/sshd for banner" >>   $HOSTNAME-Requirement-2.txt
sudo cat /etc/ssh/sshd_config  | grep Banner 2> /dev/null >>   $HOSTNAME-Requirement-2.txt
echo "" >>   $HOSTNAME-Requirement-2.txt

echo "|=----------------------------=[MOUNTED HARD DRIVES]=------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "Permantally mount drives" >> $HOSTNAME-Requirement-2.txt
sudo cat /etc/fstab 2>/dev/null >> $HOSTNAME-Requirement-2.txt
echo "Mounted drives partitions sizes and types" >> $HOSTNAME-Requirement-2.txt
sudo fdisk -l 2>/dev/null >> $HOSTNAME-Requirement-2.txt

echo "|=----------------------------=[LOCAL DRIVES]=-------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
sudo lshw -class disk  2>/dev/null >>   $HOSTNAME-Requirement-2.txt 

echo "|=--------------------------=[DRIVERS INSTALLED]=----------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
echo "|= Related requirements: 2.2.5                                               =|" >>   $HOSTNAME-Requirement-2.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt 
find /lib/modules/$(uname -r)/kernel/ -name '*.ko*' >> $HOSTNAME-Requirement-2.txt 2>/dev/null

echo "|=----------------------------=[USB DRIVE]=----------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-2.txt
sudo lsmod | grep usb_storage  >> $HOSTNAME-Requirement-2.txt
echo "======================================================================================">>   $HOSTNAME-Requirement-2.txt
sudo ls /lib/modules/`uname -r`/kernel/drivers/usb/storage  >>   $HOSTNAME-Requirement-2.txt 2>/dev/null

echo "|=----------------------=[ENCRYPTION METHOD FOR PASSWORD]=-----------------=|" >>   $HOSTNAME-Requirement-2.txt
echo "Getting encryption method used for password for all non console/remote ssh access" >> $HOSTNAME-Requirement-2.txt
sudo cat /etc/login.defs | grep ENCRYPT_METHOD 2>/dev/null >>$HOSTNAME-Requirement-2.txt 

echo "Done with req 2"
echo "Audit req 3 manually"
echo "Skipping req 3"
echo "Getting Requirement 4" 
echo "|=----------------------=[TLS VERSIONS]=-------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "|= Related requirements: 4.1                                                 =|" >>   $HOSTNAME-Requirement-4.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "Check TLS1.2 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" | openssl s_client -connect google.com:443 -tls1_2  2>/dev/null >> $HOSTNAME-Requirement-4.txt 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check TLS1.1 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" | openssl s_client -connect google.com:443 -tls1_1  2>/dev/null >> $HOSTNAME-Requirement-4.txt 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check TLS1.0 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" |openssl s_client -connect google.com:443 -tls1  2>/dev/null >> $HOSTNAME-Requirement-4.txt 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check ssl2.0 handshake" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" |openssl s_client -connect google.com:443 -ssl2  2>/dev/null >> $HOSTNAME-Requirement-4.txt 
echo "===============================================" >>$HOSTNAME-Requirement-4.txt
echo "Check server accepts connections using ciphers from group NULL or LOW" >>   $HOSTNAME-Requirement-4.txt 
sudo echo "x" |openssl s_client -connect google.com:443 -cipher NULL,LOW  2>/dev/null >> $HOSTNAME-Requirement-4.txt 


echo "|=----------------------=[TLS VERSIONS]=-------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "|= Related requirements: 4.2                                                 =|" >>   $HOSTNAME-Requirement-4.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-4.txt 
echo "Check service use ssl/tls dor transmitting data" >>   $HOSTNAME-Requirement-4.txt
for I in `find /usr/sbin -type f -print`; do ldd ${I} | egrep -q 'ssl|tls'; if [ $? -eq 0 ]; then echo ${I} >> $HOSTNAME-Requirement-4.txt 2>/dev/null; fi; done

echo "Done with req 4"
echo "Getting Requirement 5"
echo "|=----------------------=[ANTIVIRUS INSTALLED]=------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.1                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Check ClamAV is installed or not" >>   $HOSTNAME-Requirement-5.txt

dpkg -l 2>/dev/null | egrep 'clamav|clamav-freshclam' >> $HOSTNAME-Requirement-5.txt|| rpm -qa 2>/dev/null | egrep 'clamav|clamav-freshclam' >> $HOSTNAME-Requirement-5.txt 2>/dev/null || pacman -Q clamav 2>/dev/null >> $HOSTNAME-Requirement-5.txt || dnf list clamav 2>/dev/null >> $HOSTNAME-Requirement-5.txt

[ ! $@ ] && echo "ClamAV is installed." >>   $HOSTNAME-Requirement-5.txt || echo "ClamAV is not installed" >>   $HOSTNAME-Requirement-5.txt

echo ""

echo "|=----------------------=[ANTIVIRUS RUNNING]=--------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Check ClamAV service is running or not" >>   $HOSTNAME-Requirement-5.txt
a1=`systemctl is-enabled clamav 2>/dev/null` >>   $HOSTNAME-Requirement-5.txt  || a1=`chkconfig clamav 2>/dev/null` >>   $HOSTNAME-Requirement-5.txt 
[ "$a1" == "enabled" ] && echo "ClamAV service is enabled" 2> /dev/null >> $HOSTNAME-Requirement-5.txt || echo "ClamAV service is not enabled" >> $HOSTNAME-Requirement-5.txt 2> /dev/null
a2=`systemctl is-active clamav 2>/dev/null` >>   $HOSTNAME-Requirement-5.txt 
[ "$a2" == "active" ] && echo "ClamAV service is active" >> $HOSTNAME-Requirement-5.txt 2>/dev/null || echo "ClamAV service is not running" >> $HOSTNAME-Requirement-5.txt 2>/dev/null
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Service status" >>   $HOSTNAME-Requirement-5.txt
service clamav status 2>/dev/null || systemctl status clamav 2>/dev/null >>   $HOSTNAME-Requirement-5.txt 

echo "|=----------------------=[ANTIVIRUS SCAN]=--------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking cronjobs to continous antivirus system scan using ClamAV " >>   $HOSTNAME-Requirement-5.txt
systemctl status clamav 2>/dev/null >> $HOSTNAME-Requirement-5.txt || service clamav status 2>/dev/null >> $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
crontab -l 2>/dev/null >> $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
[ ! `find /etc/cron.daily -name clamav -print 2>/dev/null` ] && echo "No daily cron exist of clamav scan" >> $HOSTNAME-Requirement-5.txt  || echo "Daily cron exist of clamav scan" cat /etc/cron.daily/*clamav* >> $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
[ ! `find /etc/cron.hourly -name clamav -print 2>/dev/null` ] && echo "No hourly cron exist of clamav scan"  >>$HOSTNAME-Requirement-5.txt 2>/dev/null || echo "Hourly cron exist of clamav scan" cat /etc/cron.hourly/*clamav* >>   $HOSTNAME-Requirement-5.txt 

echo "|=----------------------=[VIRUS SCAN LOGS]=--------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking logs of virus detection" >>   $HOSTNAME-Requirement-5.txt
v=`find /var/log -name clamav -print 2>/dev/null`
[ ! $v ] && echo "No log file detect of clamav scan" >>$HOSTNAME-Requirement-5.txt || cat /var/log/clamav/scan.log | grep Infected 2>/dev/null echo "Log file exist of clamav scan logs" >> $HOSTNAME-Requirement-5.txt


echo "|=----------------------=[VIRUS DETECTION UP-TO-DATE]=-----------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.3                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking software is up-to-date" >>   $HOSTNAME-Requirement-5.txt
clam=`ps -ef | grep -v grep | grep clamav-freshclam | wc -l 2>/dev/null`
[ $clam -gt 0 ] && echo "ClamAV FreshClam service is running as this service checks update of virus" >> $HOSTNAME-Requirement-5.txt || echo "ClamAV FreshClam service is not running as this service checks update of virus" >> $HOSTNAME-Requirement-5.txt 
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
fr=`find /etc/clamav/ -name freshclam.conf -print 2>/dev/null`
if [ ! $fr ]; then
(
 echo "No freshclam config exist" >> $HOSTNAME-Requirement-5.txt
)
else
(
chk=`grep checks $fr | awk '{ print $2 }' 2>/dev/null`
echo "Freshclam config exist. checks update $chk times a day" >> HOSTNAME-Requirement-5.txt
)
fi

echo "|=----------------------=[ FRESHCLAM LOG-FILE ]=-----------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking log file of freshclam" >>   $HOSTNAME-Requirement-5.txt
[ ! `find /var/log/clamav -name freshclam.log -print 2>/dev/null` ] && echo "Freshclam log file dose not exist" >> $HOSTNAME-Requirement-5.txt || echo "Freshclam log file exist" cat /var/log/clamav/freshclam.log >>$HOSTNAME-Requirement-5.txt
 
echo "|=----------------------=[ CLAMSCAN AND CLAMD]=------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.2                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking CLAMD service is running" >>   $HOSTNAME-Requirement-5.txt
[ `ps -ef | grep -v grep | grep clamd | wc -l 2>/dev/null` -gt 0 ] && echo "Clamd service is running" >>   $HOSTNAME-Requirement-5.txt || echo "Clamd service is not running" >>   $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Checking CLAMD conf file exist" >>   $HOSTNAME-Requirement-5.txt
[ ! `find /etc/clamav -name clamd.conf -print 2>/dev/null` ] && echo "clamav.conf exist" cat /etc/clamav/clamav.conf 2>/dev/null >> $HOSTNAME-Requirement-5.txt || echo "clamav.conf does not exist" >> $HOSTNAME-Requirement-5.txt
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Checking logging is enabled" >>   $HOSTNAME-Requirement-5.txt
clamconf | grep log 2>/dev/null >> $HOSTNAME-Requirement-5.txt

echo "|=----------------------=[ CONF FILE PERMISSIONS ]=--------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "|= Related requirements: 5.3                                                 =|" >>   $HOSTNAME-Requirement-5.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-5.txt 
echo "Checking permission on clamd.conf" >>   $HOSTNAME-Requirement-5.txt
p1=`ls -alth /etc/clamav/clamd.conf 2>/dev/null | awk '{ print $3,$4}' `
if [ -r /etc/clamav/clamd.conf ] && [ -w /etc/clamav/clamd.conf ]; then (echo "clamd.conf has read,write persmission by user,group $p1" >>   $HOSTNAME-Requirement-5.txt)
else (echo "clamd.conf does not have read,write persmission" >> $HOSTNAME-Requirement-5.txt)
fi
echo "===============================================" >>$HOSTNAME-Requirement-5.txt
echo "Checking permission on freshclam.conf" >>   $HOSTNAME-Requirement-5.txt
p2=`ls -alth /etc/clamav/freshclam.conf 2>/dev/null | awk '{ print $3,$4}'`
if [ -r /etc/clamav/fresclam.conf ] && [ -w /etc/clamav/freshclam.conf ]; then (echo "freshclam.conf has read,write persmission by user,group $p2" >>   $HOSTNAME-Requirement-5.txt) 
else (echo "freshclam.conf does not have read,write persmission" >>   $HOSTNAME-Requirement-5.txt)
fi
echo "Done with req 5"
echo "Getting Requirement 6"
echo "|=---------------------------=[OS VERSION]=--------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.1                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
hostnamectl |grep "Operating System:*" 2>/dev/null >>   $HOSTNAME-Requirement-6.txt 
hostnamectl |grep "Kernel:*" 2>/dev/null >>   $HOSTNAME-Requirement-6.txt 

echo "|=------------------------------=[LAST UPDATE DATE]=------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.1                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=-------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "Checking when kernel updated last time" >>   $HOSTNAME-Requirement-6.txt 
rpm -q kernel --last 2>/dev/null >> $HOSTNAME-Requirement-6.txt
echo "===============================================" >>$HOSTNAME-Requirement-6.txt
echo "Checking all package update date" >>   $HOSTNAME-Requirement-6.txt
rpm -qa --last 2>/dev/null >> $HOSTNAME-Requirement-6.txt

echo "|=------------------------------=[PACKAGES TO UPDATE]=----------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.1                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=--------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "Checking list of packages needs to be updated" >>   $HOSTNAME-Requirement-6.txt 
yum list updates 2>/dev/null >> $HOSTNAME-Requirement-6.txt || dnf list updates 2>/dev/null >> $HOSTNAME-Requirement-6.txt || pacman -Qu 2>/dev/null >> $HOSTNAME-Requirement-6.txt || zypper list-updates 2>/dev/null >> $HOSTNAME-Requirement-6.txt || apt list --upgradable 2>/dev/null >> $HOSTNAME-Requirement-6.txt 
[ ! $@ ] && echo "Above listed packages needs to be updated" >> $HOSTNAME-Requirement-6.txt || echo "No packages to update" >> $HOSTNAME-Requirement-6.txt
echo "===============================================" >>$HOSTNAME-Requirement-6.txt
echo "Checking installed/updated softwares" >>   $HOSTNAME-Requirement-6.txt
yum history 2>/dev/null >> $HOSTNAME-Requirement-6.txt || cat var/log/apt/history.log 2>/dev/null >> $HOSTNAME-Requirement-6.txt
echo "" >> $HOSTNAME-Requirement-6.txt
echo "===============================================" >>$HOSTNAME-Requirement-6.txt
echo "Checking log of installed/updated" >> $HOSTNAME-Requirement-6.txt
cat /var/log/yum.log 2>/dev/null >> $HOSTNAME-Requirement-6.txt

echo "|=--------------------------=[OS UPDATES - SOURCES]=------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.2                                               =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=-------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
sudo dnf repolist all 2>/dev/null >> $HOSTNAME-Requirement-6.txt
sudo grep ^[^#] /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null >> $HOSTNAME-Requirement-6.txt
sudo yum repolist all 2>/dev/null >> $HOSTNAME-Requirement-6.txt

echo "|=--------------------------=[SECURITY UPDATES ]=---------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
echo "|= Related requirements: 6.2                                                                             =|" >>   $HOSTNAME-Requirement-6.txt 
echo "|=-------------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-6.txt 
yum check-update --security 2>/dev/null >> $HOSTNAME-Requirement-6.txt || cat /var/lib/update-notifier/update-available 2>/dev/null >> $HOSTNAME-Requirement-6.txt

echo "Done with req 6"
echo "Getting Requirement 7"
echo "|=---------------------=[CURRENT USER PRIVILEGE RIGHTS]=---------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Related requirements: 7.1 - 7.2                                           =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|= Please compare current values with your Security Configuration Standard   =|" >>   $HOSTNAME-Requirement-7.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-7.txt 
echo "checks to see what group current user is part of" >>   $HOSTNAME-Requirement-7.txt 
grep $(whoami) /etc/group >>   $HOSTNAME-Requirement-7.txt 
echo "" >>   $HOSTNAME-Requirement-7.txt 
echo "Checks /etc/sudoers to see if user is added" >>   $HOSTNAME-Requirement-7.txt 
file1="/etc/sudoers"
sudoer1=`sudo grep $(whoami) /etc/sudoers 2>/dev/null`
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
echo "Checking SELinux policy enforced" >> $HOSTNAME-Requirement-7.txt
state=`grep SELINUX=enforcing /etc/selinux/config 2>/dev/null`
[ ! $state ] && echo "SELinux enabled" >> $HOSTNAME-Requirement-7.txt || echo "SELinux not enforced" >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking SELinux policy type" >> $HOSTNAME-Requirement-7.txt
type=`grep SELINUXTYPE=targeted /etc/selinux/config 2>/dev/null`
[ ! $type ] && echo "SELinux type targeted" >> $HOSTNAME-Requirement-7.txt || echo "SELinux type not set to targeted" >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking SELinux troubleshoot package is installed" >> $HOSTNAME-Requirement-7.txt
rpm -q setroubleshoot 2>/dev/null >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Checking unconfined daemons" >> $HOSTNAME-Requirement-7.txt
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}' 2>/dev/null >> $HOSTNAME-Requirement-7.txt
echo "===============================================" >>$HOSTNAME-Requirement-7.txt
echo "Getting status of SELinux" >> $HOSTNAME-Requirement-7.txt
sestatus 2>/dev/null >> $HOSTNAME-Requirement-7.txt

echo "Done with req 7"
echo "Getting Requirement 8"

echo "|=-----------------------=[INACTIVE ACCOUNTS]=------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.                                                                              =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Getting inactive accounts more than or equal to 90 days" >> $HOSTNAME-Requirement-8.txt
inactive=`lastlog -b 90 2>/dev/null | tail -n+2 | grep -v '**Never log**' | awk '{print $1}' 2>/dev/null`
echo $inactive >> $HOSTNAME-Requirement-8.txt

echo "|=---------------------=[LOCKED/DISABLE INACTIVE ACCOUNTS]=-----------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.4                                                                            =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=--------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking user password locked of inactive user over 90 days" >> $HOSTNAME-Requirement-8.txt
inact=`lastlog -b 90 2>/dev/null | tail -n+2 | grep -v '**Never log**' | awk '{print $1}' 2>/dev/null`
for line in $inact
do
lk=`passwd -S $line | awk '{print $2}' 2> /dev/null`
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
pwck -r 2>/dev/null >> $HOSTNAME-Requirement-8.txt


echo "|=-----------------------=[FILE PERMISSION CHECK]=-------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1                                                                              =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking Permission of passwd file" >> $HOSTNAME-Requirement-8.txt
ls -alth | grep /etc/passwd  >> $HOSTNAME-Requirement-8.txt
echo "===============================================" >>$HOSTNAME-Requirement-8.txt
echo "Checking Permission of shadow file" >> $HOSTNAME-Requirement-8.txt
ls -alth /etc/shadow  >> $HOSTNAME-Requirement-8.txt
echo "===============================================" >>$HOSTNAME-Requirement-8.txt
echo "Checking no other user has read access to shadow file" >> $HOSTNAME-Requirement-8.txt
sh=`ls -alth /etc/shadow | awk '{print $3}' 2>/dev/null` >> $HOSTNAME-Requirement-8.txt
[ "$sh" = "root" ] && echo "Only root user has permission on shadow file" >> $HOSTNAME-Requirement-8.txt || echo "$sh user has permission" >> $HOSTNAME-Requirement-8.txt
gr=`ls -alth /etc/shadow | awk '{print $4}' 2>/dev/null` >> $HOSTNAME-Requirement-8.txt
[ "$sh" = "root" ] && echo "Only root group has permission on shadow file" >> $HOSTNAME-Requirement-8.txt || echo "$gr group has permission" >> $HOSTNAME-Requirement-8.txt

echo "|=-----------------------=[ENABLED LOCAL ACCOUNTS]=------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.4                                                                            =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
awk -F: '$NF!~/\/!false$/ && $NF!~/\/!nologin$/' /etc/passwd  2>/dev/null >> $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt


echo "|=-----------------------=[DISABLED LOCAL ACCOUNTS]=-----------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.4                                                                            =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "---accounts not allowed to logon---" >>   $HOSTNAME-Requirement-8.txt
awk -F: '$NF!~/\/!nologin$/' /etc/passwd 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt
echo "---accounts with password disabled/Not able to logon---" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/shadow |grep '!' 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=---------------------------=[ACCOUNT LOCKOUT]=----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.6                                                                             =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=--------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo " This checks /etc/pam.d/system-auth and /etc/pam.d/password-auth to see if a pam_faillock.so line is set " >>   $HOSTNAME-Requirement-8.txt 
sysauth1=`sudo cat /etc/pam.d/system-auth | grep faillock 2>/dev/null`
passauth1=`sudo cat /etc/pam.d/password-auth | grep faillock 2>/dev/null`
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
cat /etc/pam.d/system-auth |grep "unlock_time*" 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt


echo "|=----------------------------=[SESSION TIMEOUT]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.1.8                                                =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 

echo "--[ Console timeout ]" >>   $HOSTNAME-Requirement-8.txt 
echo "This setting is intended to log a user out of the console if inactive" >>   $HOSTNAME-Requirement-8.txt 
logout1=`cat ~/.bashrc |grep TMOUT 2>/dev/null`
logout2=`cat ~/.bash_profile |grep TMOUT 2>/dev/null`
if [[ ! "$logout1" && ! "$logout2" ]]
then
	echo "No Console timeout settings found in bashrc or bash_profile, This does not mean there is no console timeout set as there may be other scripts to do this! " >>  $HOSTNAME-Requirement-8.txt
fi

if [ ! -z "$logout1" ]
then
	echo ".bashrc :: Time out settings in seconds:$logout1" >>   $HOSTNAME-Requirement-8.txt
        [ "$logout1" = "900" ] && echo "Session time out as per standards" >> $HOSTNAME-Requirement-8.txt || echo "Session timeout not per standards" >> $HOSTNAME-Requirement-8.txt
fi
if [ ! -z "$logout2" ]
then
	echo ".bash_profile :: Time out settings in seconds:$logout2" >>   $HOSTNAME-Requirement-8.txt
        [ "$logout2" = "900" ] && echo "Session time out as per standards" >> $HOSTNAME-Requirement-8.txt || echo "Session timeout not per standards" >> $HOSTNAME-Requirement-8.txt
fi

echo "--[ SSH Timeout ]" >>   $HOSTNAME-Requirement-8.txt
echo "This setting logs a SSH user out after a period of time" >>   $HOSTNAME-Requirement-8.txt

echo "Alive interval" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/ssh/sshd_config 2>/dev/null| grep ClientAliveInterval >>   $HOSTNAME-Requirement-8.txt
echo "Client alive count" >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/ssh/sshd_config 2>/dev/null| grep  ClientAliveCountMax >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt

echo "|=---------------------=[PASSWORD STORE CONFIGURATION]=----------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.2.1                                               =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=---------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt
echo "this checks /etc/pam.d/system-auth to see password encryption settings" >>   $HOSTNAME-Requirement-8.txt
encryp1=`sudo cat /etc/pam.d/system-auth 2>/dev/null |grep pam_unix.so`
if [[ $encryp1 =~ sha512 ]]
then 
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null |grep sha512` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ sha256 ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null |grep sha256` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ bigcrypt ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null |grep bigcrypt` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ blowfish ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null |grep blowfish` >>   $HOSTNAME-Requirement-8.txt
elif [[ $encryp1 =~ md5 ]]
then
	echo `sudo cat /etc/pam.d/system-auth 2>/dev/null |grep md5` >>   $HOSTNAME-Requirement-8.txt
else
	echo "No Encryption found /etc/pam.d/system-auth matching pam_unix.so" >>   $HOSTNAME-Requirement-8.txt
fi
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "This Checks /etc/passwd and /etc/shadow to see what permissions are set on them" >>   $HOSTNAME-Requirement-8.txt
passwd1=`stat -c %a /etc/passwd 2>/dev/null`
echo "/etc/passwd has the  permissions set to $passwd1" >>   $HOSTNAME-Requirement-8.txt
shadow1=`stat -c %a /etc/shadow 2>/dev/null`
echo "/etc/shadow has the permissions set to $shadow1" >>   $HOSTNAME-Requirement-8.txt
echo "The other group should never have read access to the shadow file, as it contains the hashed passwords." >>   $HOSTNAME-Requirement-8.txt
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

file2=/etc/pam.d/system-auth
lowcase2=`grep lcredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`
upcase2=`grep ucredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`
digit2=`grep dcredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`
othchar2=`grep ocredit /etc/pam.d/system-auth 2>/dev/null |grep pam_cracklib.so`

if [ ! -f $file2 ]
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
echo "|=--------------------------=[TWO FACTOR AUTHENTICATION]=---------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.3                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "Checking 2 factor auth configuration" >> $HOSTNAME_Requirement-8.txt
cp=/etc/pam.d/common-password
pa=/etc/pam.d/password-auth
ca=/etc/pam.d/common-auth
sa=/etc/pam.d/system-auth
if [ -a $cp ]
then 
( 
egrep -w 'pam_google_authenticator.so|pam_yubikey.so' $cp 2>/dev/null
[ ! $@ ] && echo "no authenticator config exist in common-password file" >> $HOSTNAME_Requirement-8.txt || echo $@ >> $HOSTNAME_Requirement-8.txt
)
elif [ -a $pa ]
then
( 
egrep -w 'pam_google_authenticator.so|pam_yubikey.so' $pa 2>/dev/null 
[ ! $@ ] && echo "no authenticator config exist in password-auth" >> $HOSTNAME_Requirement-8.txt || echo $@ >> $HOSTNAME_Requirement-8.txt 
)
else
(
echo "both file not exist" >> $HOSTNAME_Requirement-8.txt
)
fi

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOGIN SHELLS]=-------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.t
echo "checking which shells are valid/allowd" >> $HOSTNAME-Requirement-8.txt
cat /etc/shells 2>/dev/null >> $HOSTNAME-Requirement-8.txt
echo "" >> $HOSTNAME-Requirement-8.txt

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOCAL ACCOUNTS]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo " this pulls information from the /etc/passwd file! "  >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/passwd | awk -F: '{ print $1}' 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "" >>   $HOSTNAME-Requirement-8.txt


echo "|=-------------------------=[LOCAL ADMINISTRATORS]=---------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                  =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "lists Users in the wheel group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group wheel 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the admin group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group admin 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the sudo group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group sudo 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the staff group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group staff 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo "lists Users in the sudoers group " >>   $HOSTNAME-Requirement-8.txt
sudo getent group sudoers 2>/dev/null >>   $HOSTNAME-Requirement-8.txt

echo "" >>   $HOSTNAME-Requirement-8.txt
echo "|=-----------------------------=[LOCAL GROUPS]=-----------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "|= Related requirements: 8.5                                                                               =|" >>   $HOSTNAME-Requirement-8.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-8.txt 
echo "This pulls information from the /etc/group file!"  >>   $HOSTNAME-Requirement-8.txt
sudo cat /etc/group | awk -F: '{ print $1}' 2>/dev/null >>   $HOSTNAME-Requirement-8.txt
echo ""  >>   $HOSTNAME-Requirement-8.txt
echo "Done with req 8"
echo "Skipping req 9"
echo "Getting Requirement 10"
echo "|=-----------------------=[LOGGING CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.1.1                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo cat /etc/rsyslog.conf 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "===============================================" >>$HOSTNAME-Requirement-10.txt
sudo cat /etc/syslog.conf 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "===============================================" >>$HOSTNAME-Requirement-10.txt
sudo cat /etc/rsyslog.d/* 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "===============================================" >>$HOSTNAME-Requirement-10.txt
sudo cat /var/log/syslog 2>/dev/null >> $HOSTNAME-Requirement-10.txt
#echo "===============================================" >>$HOSTNAME-Requirement-10.txt
#sudo cat /var/log/auth.log 2>/dev/#null >> $HOSTNAME-Requirement-10.txt
echo "===============================================" >>$HOSTNAME-Requirement-10.txt
sudo cat /var/log/secure 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "" >> $HOSTNAME-Requirement-10.txt

echo "|=-----------------------=[EVENTLOG - SERVICE STATUS]=------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo service rsyslog status 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt
sudo service syslog status 2>/dev/null >> $HOSTNAME-Requirement-10.txt

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=---------------------------=[LOG CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo " -- This Checks the logging configuration /etc/rsyslog.conf -- " >> $HOSTNAME-Requirement-10.txt
echo "authpriv: Messages coming from authorization and security related events" >> $HOSTNAME-Requirement-10.txt
auth1=`grep auth /etc/rsyslog.conf 2>/dev/null`
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
authpriv1=`grep authpriv /etc/rsyslog.conf 2>/dev/null`
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
kern1=`grep kern /etc/rsyslog.conf 2>/dev/null`
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
mail1=`grep mail /etc/rsyslog.conf 2>/dev/null`
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
cron1=`grep cron /etc/rsyslog.conf 2>/dev/null`
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
news1=`grep news /etc/rsyslog.conf 2>/dev/null`
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
lpr1=`grep lpr /etc/rsyslog.conf 2>/dev/null`
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
user1=`grep user /etc/rsyslog.conf 2>/dev/null`
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
sudo cat /etc/logrotate.conf 2>/dev/null >> $HOSTNAME-Requirement-10.txt

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=------------------------------=[Audit Log]=---------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "Audit service status" >> $HOSTNAME-Requirement-10.txt
sudo auditctl -s 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "=================================================" >> $HOSTNAME-Requirement-10.txt
sudo systemctl is-enabled auditd 2>/dev/null >> $HOSTNAME-Requirement-10.txt || service auditd status 2>/dev/null >> $HOSTNAME-Requirement-10.txt || chkconfig auditd 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "" >> $HOSTNAME-Requirement-10.txt
echo "=================================================" >> $HOSTNAME-Requirement-10.txt
echo "Audit Configuration" >> $HOSTNAME-Requirement-10.txt
sudo cat /etc/audit/auditd.conf >> $HOSTNAME-Requirement-10.txt

echo "|=------------------------------=[EVENT WITH AUDIT]=--------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.2 - 10.3                                          =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "Record events that modify Date and Time" >> $HOSTNAME-Requirement-10.txt
grep time-change /etc/audit/audit.rules 2>/dev/null >> $HOSTNAME-Requirement-10.txt

echo "" >>   $HOSTNAME-Requirement-10.txt
echo "|=-------------------------=[NTP - SERVICE STATUS]=---------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4                                                 =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo systemctl status ntpd 2>/dev/null >> $HOSTNAME-Requirement-10.txt || service ntpd status 2>/dev/null >> $HOSTNAME-Requirement-10.txt
echo "" >>   $HOSTNAME-Requirement-10.txt

echo "|=---------------------------=[NTP CONFIGURATION]=----------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
echo "|= Related requirements: 10.4.3                                               =|" >>   $HOSTNAME-Requirement-10.txt 
echo "|=----------------------------------------------------------------------------=|" >>   $HOSTNAME-Requirement-10.txt 
sudo cat /etc/ntp.conf 2>/dev/null >> $HOSTNAME-Requirement-10.txt || sudo cat /etc/xntp.conf 2>/dev/null >> $HOSTNAME-Requirement-10.txt
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

echo "Done with req 10"
echo "Skipping req 11"
echo "Skipping req 12"
duration=$(echo "$(date +%s.%N) - $start" | bc)
execution_time=`printf "%.2f seconds" $duration`
echo "Test completes in $execution_time"
echo "Evidence of tests has been collected for review in $(pwd)"
