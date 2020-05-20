#! /bin/bash

#read -p "Enter local database root password:" pw
#mysql -u root -p$pw -D kamailio -e "DROP DATABASE kamailio;"
systemctl stop kamailio
systemctl stop rtpengine
systemctl stop mariadb
systemctl stop mysqld
echo "Services stopped: kamailio,rtpengine,database"

#Remove Kamailio files
#do not worry about deleting kamailio code because it is all over written
#and files are re-created regardless of there existence
rm -f /etc/systemd/system/kamailio.service
rm -f /etc/default/kamailio
rm -rf /usr/local/etc/kamailio
rm -f /usr/local/sbin/kamailio
rm -f /usr/local/sbin/kamdbctl
rm -f /usr/local/sbin/kamailio
echo "Removed Kamailio and Kamailio tools"

#remove Database files
> /var/log/mysqld.log
yum remove -y mysql*
yum remove -y mysql80*
yum remove -y mysql-community*
yum remove -y mariadb*
yum remove -y MariaDB*
yum remove -y mariadb-libs
rm -f /etc/my.cnf
rm -rf /var/lib/mysql
rm -f /var/log/mysqld.log
echo "Removed database files"

#Remove rtpengine  files
#do not worry about deleting kamailio code because it is all over written
#and files are re-created regardless of there existence
rm -f /etc/systemd/system/rtpengine.service
rm -rf /usr/local/src/rtpengine
rm -f /usr/local/src/rtpengine.tar
rm -f /usr/local/bin/rtpengine
rm -f /run/rtpengine
echo "Removed rtpengine tools"


#remove Database files
mysql -u root -p -D kamailio -e "DROP DATABASE kamailio; DROP DATABASE asterisk"
yum remove -y mariadb
yum remove -y mariadb-server
rm -f /etc/my.cnf
echo "Removed /etc/my.cnf"
rm -rf /var/lib/mysql
echo "Removed mysql(/var/lib/mysql"

sudo systemctl daemon-reload
sudo systemctl reset-failed

