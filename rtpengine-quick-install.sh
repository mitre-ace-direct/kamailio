#!/bin/bash

 if [ "$(id -u)" != "0" ]; then
    echo "This script must be ran as root"
    exit 1;
 fi

 if [ $# -ne 2 ]; then
    echo
    echo " - This script requires kamailio private-ip, and public-ip as arguments"
    echo " - Install rtpengine on the same Server as the Proxy"
    echo "ex: rtpengine-quick-install.sh Private-IP Public-IP "
    echo
    exit 1
 fi
 WORKING_DIR=$(pwd)
 filefound=$(which rtpengine)
 if [ $? == "0IGNORE" ]; then
    echo "rtpengine service is already available"
 else
    yum install -y  iptables-devel kernel-devel kernel-headers xmlrpc-c-devel
    yum install -y "kernel-devel-uname-r == $(uname -r)"
    cp -f rtpengine.tar /usr/local/src
    cd /usr/local/src
    rm -rf rtpengine
#use new version; this does not work on all OS's, may need to use tarball instead
    #echo "rtpengine clone start"
    #export http_proxy;http_proxy=http://IP:PORT
    #export https_proxy;https_proxy=http://IP:PORT
    #git clone https://github.com/sipwise/rtpengine.git
    #echo "rtpengine clone complete"
#                or
#use rtpengine.tar
    tar -xvf rtpengine.tar
    echo "rtpengine untar complete"
    cd /usr/local/src/rtpengine/daemon
    yum -y install epel-release && rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm
    #rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm
    yum install -y ffmpeg ffmpeg-devel
    yum install -y hiredis-devel
    yum install spandsp-devel spandsp
    yum install perl-CPAN
    make
    cp rtpengine /usr/local/bin/
    cd /usr/local/src/rtpengine/kernel-module
    echo "make kernel-module"
    make
    echo "kernel-module make complete"
    echo "replace kernel-module"
    rmmod xt_RTPENGINE.ko
    insmod xt_RTPENGINE.ko
    echo "kernel-module replaced"
    cd /usr/local/src/rtpengine/iptables-extension
    echo "make iptables-extentions"
    make
    echo "iptables-extentions make complete"
    cp libxt_RTPENGINE.so /lib64/xtables/
    #configure rtpengine.service with public and private IP Addresses of Kamailio Server
    cd $WORKING_DIR
    cp rtpengine.service.blueprint rtpengine.service.tmp
    sed -i "s/PRIVATE-IP/$1/g" rtpengine.service.tmp
    sed -i "s/PUBLIC-IP/$2/g" rtpengine.service.tmp
    mv rtpengine.service.tmp /etc/systemd/system/rtpengine.service
    chmod 755 /etc/systemd/system/rtpengine.service
    #set /etc/rsyslog.conf
    #local1.*        /var/log/rtpengine.log
    #service rsyslog restart
    #
 fi
 echo "Starting rtpengine"
 chkconfig rtpengine on
 service rtpengine start
 if [ $? == "0" ]; then
    echo "Success => rtpengine has been started"
    echo "To disable Kamailio rtpengine, just turn the service off ('service rtpengine stop')"
 fi
