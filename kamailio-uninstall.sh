#! /bin/bash

#Remove Kamailio files
#do not worry about deleting kamailio code because it is all over written
#and files are re-created regardless of there existence
systemctl stop kamailio
sudo rm -f /etc/systemd/system/kamailio.service
sduo rm -f /etc/default/kamailio
sudo rm -rf /usr/local/etc/kamailio
sudo rm -f /var/log/mysqld.log

#remove Database files
mysql -u root -p -D kamailio -e "DROP DATABASE kamailio;"
mysql -u root -p -D asterisk -e "DROP DATABASE asterisk;"
systemctl stop mariadb
systemctl stop mysqld
sudo yum remove -y mysql*
sudo yum remove -y mariadb*
sudo rm -f /etc/my.cnf
sudo rm -rf /var/lib/mysql
sudo rm -f /usr/local/sbin/kamailio
sudo rm -f /usr/local/sbin/kamdbctl
