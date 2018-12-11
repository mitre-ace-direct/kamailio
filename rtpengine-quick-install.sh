#!/bin/bash

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
    cd /usr/local/src
    git clone https://github.com/sipwise/rtpengine.git
    cd /usr/local/src/rtpengine/daemon
    rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm
    yum install -y ffmpeg ffmpeg-devel
    yum install -y hiredis-devel
    make
    cp rtpengine /usr/local/bin/
    cd /usr/local/src/rtpengine/kernel-module
    make
    rmmod xt_RTPENGINE.ko
    insmod xt_RTPENGINE.ko
    cd /usr/local/src/rtpengine/iptables-extension
    make
    cp libxt_RTPENGINE.so /lib64/xtables/
    #configure rtpengine.service with public and private IP Addresses of Kamailio Server
    cd $WORKING_DIR
    cp rtpengine.service.blueprint rtpengine.service.tmp
    sed -i "s/PRIVATE-IP/$1/g" rtpengine.service.tmp
    sed -i "s/PUBLIC-IP/$2/g" rtpengine.service.tmp
    mv rtpengine.service.tmp /etc/systemd/system/rtpengine.service
    chmod 755 /etc/systemd/system/rtpengine.service
 fi
 echo "Starting rtpengine"
 chkconfig rtpengine on
 service rtpengine start
 if [ $? == "0" ]; then
    echo "Success => rtpengine has been started"
    echo "To disable Kamailio rtpengine, just turn the service off ('service rtpengine stop')"
 fi
