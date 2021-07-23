#!/bin/bash

#----------------------------------------------------------------------------
# Author   : MITRE
# Company  : MITRE
# Project  : Ace Direct SIP Server for Asterisk 
# Date     : 12 Mar 2018
# Purpose  : Install/Configure Kamailio SIP Proxy Server
# Purpose2 : Configure Kamailio to communicate with Asterisk 
#----------------------------------------------------------------------------

# The following script will -
# -  Validate System
# -  Get all pertinant paramaters
# -  Install MySQL (MariaDB)
#       Note: This installation of Kamailio requires a relational DB to be installed prior to building Kamailio.  
#             MySQL was choosen for this installation.  If it is already installed, you can bypass its installation. 
# -  Configure MySQL conifiguration file => /etc/my.cnf
# -  Install the Kamailio supporting libraries
# -  Install the Kamailio Proxy Server
# -  Install the rtpengine
# -  Create/Configure Kamailio configuration file => /usr/local/etc/kamailio/kamailio.cfg
# -     Note: this is the file that links Kamailio to Asterisk
# -  Creates tables required for Kamailio => Asterisk 
# -  Create/Configure files necessary for Kamailio to run as a daemon files (systemd)
# -     Note: sysv is being used because systemd is backwards compatible 
# -  Describes pjsip configuration file => /etc/asterisk/pjsip.conf (Manual process)
# -  Describes tables and fields needed by database (Manual process - User input needed)
#(See Document - Kamailio Installation and Configuration for futher details about Installation"

#
#Stop the script if any of the commands fail
#set -e
#

assigned_database_port=$1

########## variables used during installation process #####################
DATABASE="MariaDB"
HOME_DIR=$(eval echo ~${SUDO_USER})
SCRIPT_HOME=$(pwd)
WORKING_DIR=""

asterisk_private_ip=0
asterisk_private_ip_backup=0
asterisk_port=5060
asterisk_fqdn=""
asterisk_key=""
database_installed=false
database_present=false
database_port=13306
error_exists=false
kamailio_private_ip=0
kamailio_fqdn=""
kamailio_port=5060
kamailio_tls_port=443
#kamailio_dual_port=5061
kamailio_make="pass"
kamailio_installed=false
kamailio_configured=false
mysql_base_version=5
pw=""
use_local_version_rtpengine="false"
debug_mode="true"

###########################################################################


########## functions ######################################################


function clone_url() {
    if [ "$debug_mode" == "true" ];then
       git clone ssh://git@$1
    else
       git clone ssh://git@$1 >/dev/null
    fi
    if [ $? -eq 0 ]; then
       print_message "Success" "Asterisk was successfully cloned"
    else
       echo
       print_message "Info" "Trying again to clone, using user su"
        git clone ssh://git@$1
       if [ $? -eq 0 ]; then
          print_message "Success" "Asterisk was successfully cloned"
       else
          echo
          print_message "Info" "Trying again to clone, using https"
           git clone https://$USER@$1
          if [ $? -eq 0 ]; then
             print_message "Success" "Asterisk was successfully cloned"
          else
             check_status="error"
             errors_or_warnings=true
             script_errors+=("Error" "Asterisk was not cloned (ssh://git@git.codev.mitre.org/acrdemo/asterisk.git)")
             print_message "Error" "Asterisk was not cloned (ssh://git@git.codev.mitre.org/acrdemo/asterisk.git)"
          fi
       fi
    fi
}

function configure_db() {
    #Note: if a database other than MySQL/MariaDB is wanted, you will need to add 
    #      code to configure the corresponding configuration file
    sql_cnf_file=my.cnf
    bkup_sql_cnf_file=my.cnf.bkup
    if [[ "$1" == "MariaDB" ]] ; then
       #set the port n the corresponding configuration file to the port entered
       #my.cnf is the configuration file for both MySQL and MariaDB
       if [ -e /etc/$bkup_sql_cnf_file ];then
           rm -f /etc/$bkup_sql_cnf_file
       fi
       if [ -e /etc/my.cnf ]; then
          mv -f /etc/my.cnf /etc/$bkup_sql_cnf_file
       fi
       sed "s/port[ ]*=[ ]*PORT/port = $database_port/g" $sql_cnf_file > /etc/my.cnf
    elif [[ "$1" == "MySQL" ]] ; then
        sed -i '/\[mysqld\]/a validate_password_policy=LOW' /etc/my.cnf
        sed -i '/\[mysqld\]/a port = ${database_port}' /etc/my.cnf
    elif [[ "$1" == "Mongo" ]] ; then
    :
    else
    :
    fi
}

function get_server_info {
    # make sure that the entered domain name will resolve
    # get the public IP
    ip=$(dig +short ${1})
    if [[ "$2" == "Kamailio" ]] ; then
        #tmpstr=$(hostname -i)
        #kamailio_private_ip=$(echo $tmpstr | sed 's/.*127.0.0.1 //')
        kamailio_private_ip=$(ifconfig | grep inet -m 1 | cut -d ' ' -f 10)
    elif [[ "$2" == "Asterisk" ]] ; then
        if [ "$debug_mode" == "true" ];then echo "debug: ad:$asterisk_fqdn; kd:$kamailio_fqdn";fi
        if [ "$kamailio_fqdn"  == "$asterisk_fqdn" ]; then
           asterisk_private_ip=$(ifconfig | grep inet -m 1 | cut -d ' ' -f 10)
        else 
           read -p "Enter Asterisk Server Private IP: " asterisk_private_ip
        fi
    fi
    if [ -z "$ip" ]; then
        print_message "Warning" "The domain '$1' does not resolve => Use private IP"
        #kamailio_fqdn="error"
        #asterisk_fqdn="error"
        #return 
        ip=$(hostname -i)
        public_ip=$(echo $ip | sed 's/.*127.0.0.1 //')
    else
        public_ip=$ip
    fi

    # alert the user we are accepting the domain name
    if [[ "$2" == "Kamailio" ]] ; then
       print_message "Notify" "$2's Domain name has been set to ---> $1"
       print_message "Notify" "$2's Kamailio Private IP Address has been set to ---> $kamailio_private_ip"
       print_message "Notify" "$2's Kamailio Public IP Address has been set to ---> $public_ip"
       kamailio_public_ip=$public_ip
       kamailio_fqdn=$1
    elif [[ "$2" == "Asterisk" ]] ; then
       print_message "Notify" "$2's Domain name has been set to ---> $1"
       print_message "Notify" "$2's Asterisk Private IP Address has been set to ---> $asterisk_private_ip"
       print_message "Notify" "$2's Asterisk Public IP Address has been set to ---> $public_ip"
       asterisk_public_ip=$public_ip
       asterisk_fqdn=$1
    fi
}

#Function Source:  http://www.linuxjournal.com/content/validating-ip-address-bash-script
function is_valid_ip() {
    local  ip=$1
    local  stat=1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}


function isinstalled() {
   if yum list installed "$@" >/dev/null 2>&1 ; then
     if [ "$@" == "mariadb" ]; then
        database_installed=true
     fi
     true
   else
     false
   fi
}

function check_is_service_available() {
    #return codes on RHEL type systems
    #0 => program is running and service is ok
    #3 => program is not running, but available
    service=$1
    service $1 status > /dev/null 2>&1
    current_status=$?
    if [ $current_status -eq 0 ]; then
       function_call_status="0"
       if [ "$debug_mode" == "true" ];then echo "debug: $service is available";fi
    elif [ $current_status -eq 3 ]; then
       function_call_status="3"
       if [ "$debug_mode" == "true" ];then echo "debug: $service is available, but not running";fi
    elif [ $current_status -eq 4 ]; then
       function_call_status="1"
       if [ "$debug_mode" == "true" ];then echo "debug: $service is not available";fi
    else
       function_call_status="1"
       if [ "$debug_mode" == "true" ];then echo "debug: $service is not available";fi
    fi
}

function print_message {
        # first argument is the type of message
        # (Error, Notify, Info, Warning, Success)
        colorCode="sgr0"
        case $1 in
                Error)
                        colorCode=1
                        ;;
                Notify)
                        colorCode=4
                        ;;
                Info)
                        colorCode=6
                        ;;
                Warning)
                        colorCode=3
                        ;;
                Success)
                        colorCode=2
                        ;;
        esac

        # second argument is the message string
        tput setaf $colorCode; printf "${1} -- "
        tput sgr0;             printf "${2}\n"
}

function report_error() {
    hsfplus_available=false
    if [ hsfplus_available == true ] ; then
        errormessage=$( /sbin/modprobe -n -v hsfplus 2> &1)
    else
        if [ ! "$1" == "" ] ; then
            errormessage=$($1)
        fi
    fi
    echo "Processing Error: " $errormessage
}

function validate_db_password() {

    unset password
    unset charcount

    echo "Please (re)enter the root database password: "
    echo "IMPORTANT...Password cannot be blank(empty)"
    stty -echo

    charcount=0
    while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
    do
       # Enter - accept password
       if [[ $CHAR == $'\0' ]] ; then
          break
       fi
       # Backspace
       if [[ $CHAR == $'\177' ]] ; then
          if [ $charcount -gt 0 ] ; then
             charcount=$((charcount-1))
             PROMPT=$'\b \b'
             password="${password%?}"
          else
             PROMPT=''
          fi
       else
          charcount=$((charcount+1))
          PROMPT='*'
          password+="$CHAR"
       fi
    done
    stty echo
    echo

    export MYSQL_PWD=$password
    pw=$password
    if [ "$debug_mode" == "true" ];then echo "debug: Password: $pw";fi

}


###########################################################################
echo
print_message "Info" "This process can be stopped at any time using Ctrl-C" 

########## System Checks ##################################################
#
# fail if the script is not run as root
# Source: AD_asterisk_install.sh
#
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin:/usr/local/sbin:usr/local/bin:/usr/lib64:/usr/local/lib64
if [ "$(id -u)" != "0" ]; then
  echo
  print_message "Error" "This script must be run as root" 
  echo
  exit 
fi

#Determine Distro
shopt -s nocasematch
distro=$(cat /etc/*-release|grep PRETTY_NAME)

if [[ $distro =~ 'centos' ]]; then
        echo "Distro:Centos"
        linux_distro="RH"
elif [[ $distro =~ 'Red' ]]; then
        echo "Distro:Red Hat"
        linux_distro="RH"
elif [[ $distro =~ 'Ubuntu' ]]; then
        echo "Distro:Debian"
        linux_distro="DEB"
elif [[ $distro =~ 'Amazon' ]]; then
        echo "Distro:Amazon"
        linux_distro="AMZ"
fi
shopt -u nocasematch

#
# fail if selinux is enabled
# Source: AD_asterisk_install.sh
#
DISABLED="disabled"
SESTATUS=$(sestatus | head -1 | awk '{print $3}')
if [ $SESTATUS != $DISABLED ]
then
  echo
  print_message "Error" "SELinux must be disabled.  Disable SELinux, reboot the server, and try again."
  echo
  exit 
fi

###########################################################################


########## Get Inputs #####################################################

echo
read -p "Working Directory ($SCRIPT_HOME):" answer
if [ ! "$answer" == "" ] ; then
  WORKING_DIR=$answer
  if [ ! "$WORKING_DIR" == "$SCRIPT_HOME" ]; then
    #Verify Working directory is valid and copy necessary blueprint files to it (if valid)
    if [ ! -d "$WORKING_DIR" ] ; then
      echo
      print_message "Warning" "Directory does not exists, it is required that the directory exists"
      echo
      exit 
    else
      #copy needed blueprint files to current working directroy
      cp -rf $SCRIPT_HOME/* $WORKING_DIR
      #clean up
    fi
  fi
else
  WORKING_DIR=$SCRIPT_HOME
fi
print_message "Notify" "Installation Home: ${WORKING_DIR}"

# Get the Domain Name of the Kamailio Server, if it is not available prompt for it and the verify it
# and obtain pertinent data
kamailio_domain=$(hostname)
while true; do
   if [ -z "$kamailio_domain" ]; then 
      echo
      read -p "Enter the Kamailio Server's Domain Name(FQDN):" kamailio_domain
   fi

   get_server_info $kamailio_domain Kamailio
   if [ "error" == "$kamailio_fqdn" ]; then
      read -p "Continue?[Y/N]" answer2a
      if [ -n $answer2a ] && ([ "$answer2a" == "N" ] || [ "$answer2a" == "n" ]) ; then
        exit 
      fi 
   else
      break 
   fi
   kamailio_domain=""
done

# Get the Port for the Kamailio Server to use
nc -z 0.0.0.0 $kamailio_port
if [ $? -eq 0 ]; then
   unset kamailio_port
   kamailio_port="15060"
fi
echo
while true; do
  read -p "Enter the Kamailio Server's Port($kamailio_port):" kport
  if [ ! -z "$kport" ]; then
    #verify the value entered is numeric and < 20,000
    if ! [[ $kport =~ ^[0-9]+$ ]]; then
      echo
      print_message "Error" "The value entered must be an Integer"
      read -p "Continue?[Y/N]" answer2
      if [ -n $answer2 ] && ([ "$answer2" == "N" ] || [ "$answer2" == "n" ]) ; then
        exit 
      fi 
    else
      kamailio_port=$kport
    fi
  fi
  #determine if this port is being used
  nc -z 0.0.0.0 $kamailio_port
  if [ $? -eq 0 ]; then
     print_message "Error" "The port selected is in use, select a different port"
     continue
  else
     break
  fi
done

# Get the TLS Port for the Kamailio Server to use
nc -z 0.0.0.0 $kamailio_tls_port
if [ $? -eq 0 ]; then
   kamailio_tls_port="8443"
   print_message "Notify" "TLS port 443 is busy so it is being set to 8443"
fi
echo

: <<'BLOCK_COMMENT'
# Get the Dual Port of the Kamailio Server
echo
print_message "Info" "Kamailio's dual port is a secondary port that Kamailio is listening to for advertisements.  This may cause issues with video under very specific circumstances.  If a call is having issues with one-way video, disable it in the kamailio.cfg file by commenting it out"
echo
while true; do
  read -p "Enter the Kamailio Server's Dual Port($kamailio_dual_port):" kdport
  if [ ! -z "$kdport" ]; then
    #verify the value entered is numeric and < 20,000
    if ! [[ $kdport =~ ^[0-9]+$ ]]; then
      echo
      print_message "Error" "The value entered must be an Integer"
      echo
      read -p "Continue?[Y/N]" answer3
      if [ -n $answer3 ] && ([ "$answer3" == "N" ] || [ "$answer3" == "n" ]) ; then
        exit 
      fi 
    else
      kamailio_dual_port=$kdport
    fi
  fi
  #determine if this port is being used
  nc -z 0.0.0.0 $kdport 
  if [ $? -eq 0 ]; then
     print_message "Error" "The port selected is in use, select a different port"
     continue
  else
     break
  fi
done
BLOCK_COMMENT

print_message "Notify" "Kamailio Port being used: $kamailio_port"
#print_message "Notify" "Kamailio Dual Port being used: $kamailio_dual_port"
read -p "Continue?[Y/N]" answer3a
if [ -n $answer3a ]  && ([ "$answer3a" == "N" ] || [ "$answer3a" == "n" ]) ; then
  exit 
fi 

echo
# Get the Domain Name of the Asterisk Server, if it is not available prompt for it and the verify it
# and obtain pertinent data
while true; do
   asterisk_domain=""
   if [ -z "$asterisk_domain" ]; then 
      read -p "Enter Asterisk Server's Domain Name(FQDN):" asterisk_domain
   fi

   if [ -n $asterisk_domain ]; then
      asterisk_fqdn=$asterisk_domain
   fi

   get_server_info $asterisk_domain Asterisk
   if [ "error" == "$asterisk_fqdn" ]; then
      read -p "Continue?[Y/N]" answer3b
      if [ -n $answer3b ] && ([ "$answer3b" == "N" ] || [ "$answer3b" == "n" ]) ; then
        exit 
      fi 
   else
      read -p "Continue?[Y/N]" answer3c
      if [ -n $answer3c ] && ([ "$answer3c" == "N" ] || [ "$answer3c" == "n" ]) ; then
        exit 
      fi 
      break 
   fi
done


<<'COMMENT'
# Enter and Validate Asterisk IP Addresses for Kamailio to use with Asterisk
echo 
while true; do
  read -p "Enter Private IP Address of the Asterisk Server:" asterisk_private_ip
  #verify the value entered is a valid IP4 Address
  #if [ -z "$asterisk_private_ip" ] || [  $resp == "1" ]; then
  is_valid_ip $asterisk_private_ip
  if [ $? -eq 1 ]; then
    echo
    print_message "Error" "The value entered is not an IP Address"
    echo
    read -p "Continue?[Y/N]" answer4
    if [ -n $answer4 ] && ([ "$answer4" == "N" ] || [ "$answer4" == "n" ]) ; then
      exit 
    else
      continue
    fi
  fi
  echo "   =>IP Address being pinged to verify connection..."
  ping_response=$(ping -q -c 1 $asterisk_private_ip)
  echo "Ping Response:$ping_response"
  if [ -z "$ping_response" ]; then
    echo
    print_message "Error" "Ping Failed, The IP Address entered is unreachable"
    shopt -s nocasematch
    read -p "Continue?[Y/N]" answer5
    if [ -z "$answer5" ] || [ "$answer5" == "N" ] || [ "$answer5" == "n" ] ; then
      exit 
    fi 
    shopt -u nocasematch
  else
    shopt -u nocasematch
    break
  fi
done
COMMENT

# Get the Port of the Asterisk Server
echo
while true; do
  read -p "Enter the Asterisk Server's Port($asterisk_port):" aport
  if [ -z "$aport" ]; then
    break
  else
    #verify the value entered is numeric and < 20,000
    if ! [[ $aport =~ ^[0-9]+$ ]]; then
      echo
      print_message "Error" "The value entered must be an Integer"
      echo
      shopt -s nocasematch
      read -p "Continue?[Y/N]" answer6
      if [ -n $answer6 ] && ([ "$answer6" == "N" ] || [ "$answer6" == "n" ]) ; then
        exit 
      fi 
      shopt -u nocasematch
    else
      asterisk_port=$aport
      shopt -u nocasematch
      break
  fi
fi
done

echo 
while true; do
  read -p "Enter Private IP Address of the Asterisk Backup (Failover) Server(${asterisk_private_ip}):" asterisk_private_ip_backup
  if [ -z "$asterisk_private_ip_backup" ]; then
    asterisk_private_ip_backup=$asterisk_private_ip
    break
  else 
    #verify the value entered is a valid IP4 Address
    is_valid_ip $asterisk_private_ip_backup
    if [ $? -eq 1 ]; then
      print_message "Error" "The value entered is not an IP Address"
      shopt -s nocasematch
      read -p "Continue?[Y/N]" answer7
      if [ -n $answer7 ] && ([ "$answer7" == "N" ] || [ "$answer7" == "n" ]) ; then
        exit 
      else
        shopt -u nocasematch
        continue
      fi 
    fi
    echo " =>IP Address being pinged to verify connection..."
    ping_response=$(ping -q -c 1 ${asterisk_private_ip_backup})
    echo "Ping Response:$ping_response"
    if [ -z "$ping_response" ]; then
      print_message "Error" "The IP Address entered is invalid"
      shopt -s nocasematch
      read -p "Continue?[Y/N]" answer8
      if [ -n $answer8 ] && ([ "$answer8" == "N" ] || [ "$answer8" == "n" ]) ; then
        exit 
      fi 
      shopt -u nocasematch
    else
      break
    fi
  fi
done

echo 
print_message "Notify" "Asterisk Private IP Address being used: $asterisk_private_ip"
print_message "Notify" "Asterisk Port being used: $asterisk_port"
print_message "Notify" "Asterisk Backup Private IP Address being used: $asterisk_private_ip_backup"
print_message "Notify" "Asterisk Backup Port being used: $asterisk_port"
while true; do
  shopt -s nocasematch
  read -p "Continue?[Y/N]" answer9
  if [ -n $answer9 ] && ([ "$answer9" == "N" ] || [ "$answer9" == "n" ]) ; then
    exit 
  elif [ -z $answer9 ] || ([ "$answer9" == "Y" ] || [ "$answer9" == "y" ]) ; then
    break
  fi 
  shopt -u nocasematch
done

###########################################################################


########## Start Main Installation Process ################################
echo 
echo
echo "Starting Installation Process"

#verify proxy's are set
noproxy="false"
print_message "Info"  "Checking to verify proxies are set"
proxys=$(set|grep https_proxy)
if [ $? -eq 0 ]; then
   print_message "Success" "https_proxy is set"
else
   noproxy="true"
   #check_status="error"
   print_message "Warning" "https_proxy is not set"
fi
if [ "$noproxy" == "true" ]; then
# if proxy not set and required, then temporarily set proxy

   print_message "Notify" "No firewall http proxy was located, if you choose to install one, verify the file tmp_proxy is correct or be prompted for it (IP:PORT)."
   read -p "Install http proxy? [Y/N/]:" install_http_proxy
   if [ "$install_http_proxy" == "Y" ] || [ "$install_http_proxy" == "y" ]; then
      # if proxy not set and required, then temporarily set proxy
      print_message "Info" "Temporarily setting proxy environment"
      proxyset=$( grep -q "http_proxy" tmp_proxy; [ $? -eq 0 ] && echo "yes" || echo "no" )
      envproxyset=$( grep -q "http_proxy" /etc/environment; [ $? -eq 0 ] && echo "yes" || echo "no" )
      if [ -s $SCRIPT_HOME/tmp_proxy ] && [ $proxyset == "yes" ]; then
         assigned_proxy=$(head -1 $SCRIPT_HOME/tmp_proxy)
         http_proxy=$assigned_proxy
         https_proxy=$assigned_proxy
         noproxy="false"
      elif [ -s "/etc/environment" ] && [ $envproxyset == "yes" ]; then
         sudo rm -f tmp_proxy
         grep -r "http_proxy" /etc/environment > tmp_proxy
         sudo chmod 777 tmp_proxy
         noproxy="false"
      else
         read -p "No firewall http proxy has been detected. Enter (IP:Port) or leave blank if proxy is not required:" newproxy
         if [ ! -z "$newproxy" ]; then
            http_proxy=http://${newproxy}
            https_proxy=http://${newproxy}
            sudo rm tmp_proxy
            echo http://$newproxy>tmp_proxy
            sudo chmod 777 tmp_proxy
            noproxy="false"
            export http_proxy
            export https_proxy
         fi
      fi

      if [ $noproxy == "false" ]; then
         if [[ "$(hostname)"==*"task3acrdemo"* ]]; then
            no_proxy=$(echo 172.21.1.{1..255} | sed 's/ /,/g')
            export no_proxy
         elif [[ "$(hostname)"==*"acedirect"* ]]; then
            no_proxy=$(echo 10.190.4.{1..255} | sed 's/ /,/g')
            export no_proxy
         fi
         print_message "Notify" "proxy set to:$https_proxy"
      fi
      echo
   fi
fi

#Verify the required yum conf has correct proxy set, if needed
if [ $noproxy == "false" ]; then
   print_message "Info" "Setting yum.conf proxy"
   sudo -E ./yum_config/update_yum.sh
   if [ $? -eq 0 ]; then
      print_message "Success" "yum has correct proxy and has been cleaned"
      echo
   else
      print_message "Error" "yum proxy not set"
      print_message "Info" "Continuing with caution"
      echo
   fi
fi

#
#Install The database that kamailio will be using (if it does not already exist)
#
echo  
#determine if the database was installed, if not then ask to install it
print_message "Info" "Detect if database is installed"
dbver=$(mysql --version 2>/dev/null)

database_server_detected=false
if [[ "${dbver=}" != *Ver* ]]; then
   print_message "Info" "The Proxy requires a database to operate.  It is recommeded to install a local database."
   read -p "No database detected(Kamailio requires a DB), install Database? [Y/N]:" do_db_install
   if [ -z $do_db_install ] || ([ "$do_db_install" == "Y" ] || [ "$do_db_install" == "y" ]); then
      install_db=false
      while true;do
         echo
         PS3='Select a Database: '
         options=("MariaDB" "MySQL" "Quit")
         select opt in "${options[@]}"
         do
           case $opt in
            "MariaDB")
               database="MariaDB"
               install_db=true
               break
               ;;
            "MySQL")
               database="MySQL"
               install_db=true
               break
               ;;
            "Quit")
               database=""
               break
               ;;
            *) echo "invalid option $REPLY";;
           esac
         done
         if [ "$database" == "" ]; then
            print_message "Warning" "  No database selected"
         elif [ "$database" == "MySQL" ]; then
            print_message "Warning" "  Kamailio Proxy Server currently does not function with MySQL 8, Installing 5.7"
            break
         else
            break
         fi
      done

      if [ $install_db == true ]; then
         read -p "Enter the database Port(${database_port}):" dbport
         if [ -n "$dbport" ]; then
            database_port=$dbport
         fi
         echo "  You will be using port:" $database_port " for the database $database"
         echo "  Installing database..."
         if [ "$database" == "MariaDB" ]; then
            yum-config-manager --enable mariadb
            if [[ $distro =~ 'Amazon' ]]; then
               cp -f yum_config/yum.repos.d/MariaDB.repo /etc/yum.repos.d/.
               yum install mysql-libs
            fi
            yum install -y mariadb-server mariadb-client mariadb-shared
         else
            #wget https://dev.mysql.com/get/mysql57-community-release-el7-7.noarch.rpm
            #yum install -y mysql57-community-release-el7-7.noarch.rpm
            #rpm -ivh mysql80-community-release-el7-1.noarch.rpm
            yum-config-manager --disable mariadb
            if [[ $distro =~ 'Amazon' ]]; then
               if [ "$debug_mode" == "true" ]; then
                  yum install -y mysql-server
               else
                  yum install -y mysql-server >/dev/null
               fi
            else
               if [ "$debug_mode" == "true" ]; then
                  yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
                  yum install -y mysql-community-server
                  #yum localinstall -y https://dev.mysql.com/get/mysql80-community-release-el7-1.noarch.rpm
                  #yum install -y mysql-community-server --disablerepo=mysql80-community  --enablerepo=mysql57-community
               else
                  yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm >/dev/null
                  yum install -y mysql-community-server >/dev/null
                  #yum localinstall -y https://dev.mysql.com/get/mysql80-community-release-el7-1.noarch.rpm >/dev/null
                  #yum install -y mysql-community-server --disablerepo=mysql80-community  --enablerepo=mysql57-community >/dev/null
               fi
            fi
         fi
         if [ $? -eq 0 ]; then
            if [ "$database" == "MariaDB" ]; then
               if [ "$debug_mode" == "true" ];then echo "Installing MariaDB";fi
               print_message "Success" "  MariaDB(MySQL) Database Installed"
               configure_db MariaDB
               print_message "Info" "Starting and Enabling database..."
               chkconfig mariadb on
               service mariadb start
            else
               if [ "$debug_mode" == "true" ];then echo "Installing MySQL";fi
               print_message "Success" "  MySQL Database Installed"
               #configure_db MySQL
               print_message "Info" "Starting and Enabling database..."
               chkconfig mysqld on
               service mysqld start
               if [ $? -eq 0 ]; then
                  print_message "Info" "Database is enable and started"
               else
                  #try to fix the issue
                  sudo rm -rf /var/lib/mysql
                  service mysqld start
               fi
            fi
            status=$?
            if [ "$debug_mode" == "true" ];then echo "Current Database status:$status";fi
            echo
            if [ $status -eq 0 ]; then
               database_installed=true
               if [ "$database" == "MariaDB" ]; then
                  #print_message "Info" "You will now be prompted to secure the database"
                  #print_message "Info" "When prompted for password, press enter, you will then be prompted to change the password"
                  #print_message "Info" "If re-installing enter the current password"
                  :
               elif [ "$database" == "MySQL" ]; then
                  echo
                  print_message "Info" "*************************** IMPORTANT ***************************"
                  print_message "Info" "                      Read Before Continuing"
                  echo
                  print_message "Info" "You will now be prompted to secure the database"
                  print_message "Info" "When prompted for password, ENTER the temporary password that was generated"
                  grep 'temporary password' /var/log/mysqld.log
                  tmp_pw=$(cat /var/log/mysqld.log|grep "A temporary password is generated"|awk '{print $NF}')
                  print_message "Info" "When entering new password, requirements are =>"
                  print_message "Info" "Minimum of one lowercase, one uppercase, one numeric, and one Special charachter"
                  print_message "Info" "If re-installing enter the current password"
               else
                  print_message "Info" "Invalid Database"
               fi
               print_message "Info" "Securing Database"
               #read -p "Do you wish to run MySQL Secure Installation(create root password)?[Y/N]" answer11
               #if [ "$answer11" == "Y" ] || [ "$answer11" == "y" ]; then
                  if [ "$database" == "MySQL" ]; then
                     mysql_secure_installation
                     validate_db_password ""
                     if [ "$debug_mode" == "true" ];then echo "debug: tmp_pw:$tmp_pw; pw:$pw";fi
                     #$WORKING_DIR/secure_mysql.sh $tmp_pw $pw
                  else
                     #mysql_secure_installation
                     validate_db_password ""
                     if [ "$debug_mode" == "true" ];then echo "pw:$pw";fi
                     $WORKING_DIR/secure_mysql_mariadb.sh $pw
                  fi
                  if [ $? -eq 0 ]; then
                     if [ "$debug_mode" == "true" ];then echo "debug: mysql_secure_installation passed: $?";fi
                  else
                     if [ "$debug_mode" == "true" ];then echo "debug: mysql_secure_installation failed: $?";fi
                     error_exists=true
                  fi
                  if [ "$debug_mode" == "true" ];then echo "debug: mysql_secure_installation status: $?";fi
                  if [ "$database" == "MySQL" ]; then
                     print_message "Info" "Upgrading MySQL"
                     mysql_upgrade -u root >/dev/null
                     service mysqld restart
                  fi
               #fi
               print_message "Success" "Database Server Installation Complete"
            else
               print_message "Warning" "Database Server unable to be started"
               database_installed=false
            fi
         else
            print_message "Error" "Database Server unable to be installed"
            database_installed=false
         fi
      fi
   fi
else
   database_server_detected=true
   database_installed=true
   if [[ $dbver =~ .*Maria.* ]]; then
      database="MariaDB"
   else
      database="MySQL"
   fi
   print_message "Notify" "Database Server $database detected"
   validate_db_password "asterisk"
fi


: <<'BLOCK_COMMENT'
#
#Install Kamailio required libraries
#
echo
invalid_answer=true
while [ ${invalid_answer} == true ]; do
  read -p "Install Kamailio required libraries [Y/N(continue with installation)/A(abort)]:" answer13
  case $answer13 in
  [yY] ) 
    yum install -y --skip-broken bison prce_deevel libpcap-devel flex git libevent* json-* libunistring-deve-.x86_64 webkitgtk3-deevel.x86_64 perl* librabbitmq* libunistring-devel
    echo "Kamailio required libraries installation Complete!"
    invalid_answer=false
    ;;
  [nN] ) 
    echo "   => Bypassing installation of Kamailio required libraries,  continuing"
    invalid_answer=false
    ;;
  [aA]* ) exit;
  esac
done
BLOCK_COMMENT

#
#Install Kamailio and Kamailio tools
#
echo
invalid_answer=true
while [ ${invalid_answer} == true ]; do
  read -p "Install and Make Kamailio [Y/N(continue with installation)/A(abort)]:" answer14
  case $answer14 in
  [yY] ) 
    cybersupport=false
    read -p "Install Kamailio Cyber Security Support(SQL Injection, Script Kiddies,...)[Y,n]:" addcyber 
    case $addcyber in
    [yY]* ) 
      cyber_support=true            
      ;;
    esac
    print_message "Info" "Installing Kamailio required libraries"
    if [ "$debug_mode" == "true" ];then
       yum install -y bison prce_deevel libpcap-devel flex git libevent* json-* libunistring-deve-.x86_64 webkitgtk3-deevel.x86_64 libunistring-devel
    else
       yum install -y bison prce_deevel libpcap-devel flex git libevent* json-* libunistring-deve-.x86_64 webkitgtk3-deevel.x86_64 libunistring-devel >/dev/null
    fi
    #yum install -y bison prce_deevel libpcap-devel flex git libevent* json-* libunistring-deve-.x86_64 webkitgtk3-deevel.x86_64 perl* librabbitmq* libunistring-devel
    print_message "Notify" "Kamailio required libraries installation Complete!"

    echo
    cd /usr/src
    print_message "Info" "Cloning Kamailio"
     rm -rf /usr/src/kamailio-backup
     mv /usr/src/kamailio kamailio-backup
    if [ "$debug_mode" == "true" ];then
       git clone --depth 1 --no-single-branch https://github.com/kamailio/kamailio kamailio
       #git clone https://github.com/kamailio/kamailio.git kamailio
    else
       git clone --depth 1 --no-single-branch https://github.com/kamailio/kamailio kamailio >/dev/null
       #git clone https://github.com/kamailio/kamailio.git kamailio >/dev/null
    fi
    cd /usr/src/kamailio

    #Set Kamailio Branch
    git checkout -b 5.2 origin/5.2

    if [ ! -d /usr/local/etc/kamailio/kamailio.cfg.bkup ] ; then
      cp -f /usr/local/etc/kamailio/kamailio.cfg /usr/local/etc/kamailio/kamailio.cfg.bkup
    fi
    print_message "Notify"  "Kamailio has been cloned and source has been installed, starting make procedure"
    echo

    #
    # Make Kamailio
    #
    # make sure the mysql development libraries and include files are installed
    print_message "Info" "Make sure the development libraries are installed"
    if [ "$database" == "MySQL" ]; then
       if [ "$debug_mode" == "true" ];then echo "debug: retrieving database support libraries for MySQL";fi
        yum-config-manager --disable mariadb
       if [ "$debug_mode" == "true" ];then
          # yum install -y mysql-devel libmnl libmnl-devel
           yum install -y mysql-devel libmnl libmnl-devel
       else
           yum install -y mysql-devel libmnl libmnl-devel >/dev/null
       fi
       #fix issue in source code where my_bool is being used, it is no longer valid => use bool in its place
       if [ $mysql_base_version -eq 8 ]; then
          cd /usr/src/kamailio/src/modules/db_mysql
          find . -name "*.c" -exec sed -i "s/my_bool/bool/g" '{}' \;
          find . -name "*.h" -exec sed -i "s/my_bool/bool/g" '{}' \;
          cd /usr/src/kamailio
       fi
    else
       yum-config-manager --enable mariadb
       if [ "$debug_mode" == "true" ];then echo "debug: retrieving database support libraries for MariaDB";fi
       if [ "$debug_mode" == "true" ];then
           yum install -y mariadb-devel MariaDB-devel
           yum install -y mariadb-shared MariaDB-shared
       else
           yum install -y mariadb-devel MariaDB-devel >/dev/null
           yum install -y mariadb-shared MariaDB-shared >/dev/null
       fi
    fi

    #non standard modules used by this installation
    #"db_mysql outbound websocket tls"
    echo
    if [ "$debug_mode" == "true" ];then echo "debug: make cfg";fi
    if [ $distro =~ 'NOmysql' ]; then 
       make include_modules="outbound websocket tls" cfg
    else
       make include_modules="db_mysql outbound websocket tls" cfg
    fi 
    #make include_modules="outbound websocket tls" cfg

    echo
    if [ "$debug_mode" == "true" ];then echo "debug: make all";fi
    make all
    if [ $? -eq 0 ]; then
       print_message "Success" "Kamailio 'make all' complete"
    else
       print_message "Error" "Kamailio 'make all' failed"
       kamailio_make="fail"
       error_exists=true
    fi

    echo
    if [ "$debug_mode" == "true" ];then echo "debug: make install";fi
    make install
    if [ $? -eq 0 ]; then
       print_message "Success" "Kamailio 'make install' Complete"
       kamailio_installed=true
    else
       print_message "Error" "Kamailio 'make install' Failed"
       kamailio_make="fail"
    fi
    echo

    #Update kamailio.cfg with IP's and Domains for the kamailio and asterisk servers
    print_message "Info" "Preparing the Kamailio and Asterisk configuration files"
    if [ "$debug_mode" == "true" ];then echo "debug: using pw:$pw";fi
    cd $WORKING_DIR
    cp -f kamailio.cfg kamailio_tmp.cfg
    if [[ ${cyber_support} == "true" ]]; then
      print_message "Info"  "Adding Cyber Security Support"
      sed -i "s/##define WITH_HOMER/\#\!define WITH_HOMER/g" kamailio_tmp.cfg
    else
      sed -i "s/##define WITH_HOMER/\#\#define WITH_HOMER/g" kamailio_tmp.cfg
    fi
    sed -i "s/KAMAILIO-PORT/${kamailio_port}/g" kamailio_tmp.cfg
    #sed -i "s/KAMAILIO-DUAL-PORT/${kamailio_dual_port}/g" kamailio_tmp.cfg
    sed -i "s/ASTERISK-PORT/${asterisk_port}/g" kamailio_tmp.cfg
    sed -i "s/ASTERISK-PRIVATE-IP/${asterisk_private_ip}/g" kamailio_tmp.cfg
    sed -i "s/ASTERISK-BACKUP-PRIVATE-IP/${asterisk_private_ip_backup}/g" kamailio_tmp.cfg
    sed -i "s/KAMAILIO-PRIVATE-IP/${kamailio_private_ip}/g" kamailio_tmp.cfg
    sed -i "s/KAMAILIO-PUBLIC-IP/${kamailio_public_ip}/g" kamailio_tmp.cfg 
    sed -i "s/FQDN/${kamailio_fqdn}/g" kamailio_tmp.cfg
    sed -i "s/ASTERISK-FQDN/${asterisk_fqdn}/g" kamailio_tmp.cfg
    sed -i "s/KAMAILIO-DB-PW/${pw//&/\\&}/g" kamailio_tmp.cfg
    sed -i "s/ASTERISK-DB-PW/${pw//&/\\&}/g" kamailio_tmp.cfg
    sed -i "s/KAMAILIO-TLS-PORT/$kamailio_tls_port/g" kamailio_tmp.cfg
    read -p "Enter Asterisk Secret Key:" asterisk_key 
    sed -i "s/SECRET-KEY/$asterisk_key/g" kamailio_tmp.cfg
    mv -f kamailio_tmp.cfg /usr/local/etc/kamailio/kamailio.cfg
    cp -f check_kamailio_cfg.sh /usr/local/etc/kamailio
    cp -f restart-kamailio.sh /usr/local/etc/kamailio

    #create lines which must be added to pjsip.conf
    rm -f pjsip.conf-additions
    cp -f pjsip.conf-additions-blueprint pjsip.conf-additions
    sed -i "s/ASTERISK-PUBLIC-IP/${asterisk_public_ip}/g" pjsip.conf-additions
    sed -i "s/KAMAILIO-PRIVATE-IP/${kamailio_private_ip}/g" pjsip.conf-additions
    #cp -f pjsip.conf-additions /etc/asterisk/pjsip.conf-kamailio-configurations

    #if asterisk is installed on the same Server, then set kamailio's IP
    if [ -f /etc/asterisk/pjsip.conf ]; then
        sed -i "s/192.168.0.21/${kamailio_private_ip}/g" /etc/asterisk/pjsip.conf
    fi

    echo
    if [ "$kamailio_make" == "fail" ]; then
       print_message "Warning" "Kamailio Installation Failed"
    else
       print_message "Success" "Kamailio Installation and Configuration Complete"
       kamailio_configured=true
    fi
    invalid_answer=false
    ;;
  [nN]* )
    print_message "Notify" "Bypassing installation of Kamailio, continuing"
    invalid_answer=false
    ;;
  [aA] ) exit;
  esac
done

echo
#ask user if they want to run a media proxy (rtpengine)
print_message "Info" "You will now be prompted to install a Media Proxy (rtpengine)"
print_message "Info" "With a Media Proxy, no RTP traffic will flow between Asterisk and the UA"
print_message "Notify" "rtpengine is OS and kernel specific, in particular ffmpeg."
read -p "Would you like to install a Media Proxy (rtpengine) for Kamailio and Asterisk? [Y/N]" install_media_proxy
if [ -z $install_media_proxy ] || ([ "$install_media_proxy" == "Y" ] || [ "$install_media_proxy" == "y" ]) ; then
   check_is_service_available "rtpengine"
   if [ "$function_call_status" == "1" ] && [ ! -a /etc/systemd/system/rtpengine.service ] ; then
      yum install -y  iptables-devel kernel-devel kernel-headers xmlrpc-c-devel
      yum install -y "kernel-devel-uname-r == $(uname -r)"
      if [ "$use_local_version_rtpengine" == "true" ]; then
         print_message "Info" "Using Local rtpengine.tar"
         #use known working tarball instead of newest version because of issues with new version
         cp -f rtpengine.tar /usr/local/src
         cd /usr/local/src
         rm -rf rtpengine
         tar -xvf rtpengine.tar
      else
         print_message "Info" "Using git rtpengine.tar"
         yum install perl-IPC-Cmd -y
         cd /usr/local/src
         if [[ $distro =~ 'Amazon' ]]; then
            sudo -E wget https://github.com/sipwise/rtpengine/archive/mr4.4.1.1.tar.gz
            tar -xzvf mr4.4.1.1.tar.gz
            mv -f rtpengine-mr4.4.1.1 rtpengine
         else
            git clone https://github.com/sipwise/rtpengine.git
         fi
         #git clean -f -x -d
      fi

      #rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm
      yum -y install epel-release && rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm
      export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin:/usr/local/sbin:usr/local/bin:/usr/lib64
      yum install spandsp-devel spandsp
      yum install perl-CPAN

      #TODO compile gperf manually for systems that have yum security issues
      #Install gperf (used by rtpengine)
      echo "Checking gperf status"
      which gperf > /dev/null 2>&1
      if [ $? -eq 1 ]; then
         print_message "Info" "Installing gperf"
         if [ "$debug_mode" == "true" ]; then
            sudo yum install -y gperf
         else
            sudo yum install -y gperf >/dev/null
         fi
         if [ $? -eq 0 ]; then
            print_message "Success" "gperf was installed"
            echo
         else
            print_message "Error" "gperf was not installed"
            print_message "Info" "Consider compiling gperf manually on this system, gperf zip is included"
            echo
         fi
      else
         print_message "Notify" "gperf was already installed"
         echo
      fi

      #Some distro's require ffmpeg to be compiled and shared libraries enabled inorder to obtain correct libraries
      #Note: If you compile with h264 enabled => h264 is not free
      if [[ $distro =~ 'Amazon' ]]; then
         print_message "Info" "Amazon Linux requires ffmpeg to be compiled to obtain correct binaries"
         cd $SCRIPT_HOME
         cp ffmpeg-2.8.16.tar.gz /opt
         cd /opt
         tar -xzvf ffmpeg-2.8.16.tar.gz
         cd /opt/ffmpeg-2.8.16
         ./configure --enable-shared
         make
         make install        
         cp /usr/local/lib/libavcodec.so.56.60.100 /lib64
         cd /lib64
         ln -s libavcodec.so.56.60.100 libavcodec.so.56
         cd /usr/local/src/rtpengine/daemon
      else
         yum install -y ffmpeg ffmpeg-devel
         #yum install -y ffmpeg ffmpeg-devel.x86_64
      fi

      yum install -y hiredis-devel

      cd /usr/local/src/rtpengine/daemon 
      if [ "$debug_mode" == "true" ];then echo "debug: make rtpengine";fi
      make
      if [ "$debug_mode" == "true" ];then echo "debug: rtpengine make complete";fi
      cp rtpengine /usr/local/bin/

      cd /usr/local/src/rtpengine/kernel-module 
      if [ "$debug_mode" == "true" ];then echo "debug: make kernel-module";fi
      make 
      if [ "$debug_mode" == "true" ];then echo "debug: kernel-module make complete";fi
      if [ "$debug_mode" == "true" ];then echo "debug: replace kernel module";fi
      rmmod xt_RTPENGINE.ko
      insmod xt_RTPENGINE.ko
      if [ "$debug_mode" == "true" ];then echo "debug: kernel module replaced";fi
      cd /usr/local/src/rtpengine/iptables-extension 
      if [ "$debug_mode" == "true" ];then echo "debug: make iptables-extenstion";fi
      make
      if [ "$debug_mode" == "true" ];then echo "debug: iptables-extenstion make complete";fi
      cp libxt_RTPENGINE.so /lib64/xtables/
      #configure rtpengine.service with public and private IP Addresses of Kamailio Server
      cd $SCRIPT_HOME
      cp rtpengine.service.blueprint rtpengine.service.tmp
      sed -i "s/PRIVATE-IP/$kamailio_private_ip/g" rtpengine.service.tmp
      sed -i "s/PUBLIC-IP/$kamailio_public_ip/g" rtpengine.service.tmp
      if [ "$debug_mode" == "true" ];then echo "debug: install rtpengine service";fi
      mv rtpengine.service.tmp /etc/systemd/system/rtpengine.service
      chmod 755 /etc/systemd/system/rtpengine.service
      if [ "$debug_mode" == "true" ];then echo "debug: rtpengine service installed";fi
   else
      print_message "Info" "rtpengine service is already available"
   fi 
   filefound=$(which rtpengine)
   if [ $? == "0" ] && [ -a /etc/systemd/system/rtpengine.service ]; then
      print_message "Notify" "Starting rtpengine"
      chkconfig rtpengine on
      service rtpengine start
      if [ $? == "0" ]; then
         print_message "Success" "rtpengine has been started"
         print_message "Info" "To disable Kamailio rtpengine, just turn the service off ('service rtpengine stop')"
      fi 
   else
      print_message "Error" "rtpengine could not be installed/started"
   fi
fi
echo

#determine if Kamailio and Kamailio tools exists; these must exists in order to perform the following 
#table configurations and system setup.
if [ ! -f /usr/local/sbin/kamdbctl ] || [ ! -f /usr/local/sbin/kamailio ]; then
  echo
  print_message "Error" "Exiting: Kamailio has not been fully installed, cannot continue."
  echo
  exit 2;
fi

echo
if [ $database_installed == true ]; then
  #
  # Create Kamailio Database table using kamailio's kamdbctl tool
  #

  clear
  print_message "Info" "*************************** IMPORTANT ***************************"
  print_message "Info" "                      Read Before Continuing"
  echo
  print_message "Info" "You will now be prompted to create the Kamailio and Asterisk databases."
  print_message "Info" "When Kamailio is installing its required database and tables, you will "
  print_message "Info" "be asked whether or not to create various sub-system tables."
  print_message "Info" "(presence related tables, rtpproxy rtpengine tables, uid_uri_db tables)."
  print_message "Info" "You can answer these questions either way, depending on your requirements."
  print_message "Info" "However, in general it is safe to answer 'no' to these questions."
  echo
  read -p "Continue (Press Enter Key)" dummy_input
  echo

  invalid_answer=true

  if [ "$database" == "MySQL" ] && [ $database_server_detected == false ]; then
     print_message "Info" "Changing password policy to level LOW from (default) level MEDIUM"
     mysql --connect-expired-password -u root <mysql_change_password_policy.sql 
     if [ $? -eq 0 ]; then
        print_message "Success" "Password policy has been updated"
     else
        print_message "Warning" "Could not change password policy"
        error_exists=true
     fi
  fi

  while [ ${invalid_answer} == true ]; do
    read -p "Create kamailio databases and create kamailio's asterisk tables [Y/N/A(abort)]:" create_databases 
    case $create_databases in
    [yY] ) 
      sed -i "s/# DBENGINE=MYSQL/DBENGINE=MYSQL/g" /usr/local/etc/kamailio/kamctlrc
      sed -i "s/# SIP_DOMAIN=kamailio.org/SIP_DOMAIN=$kamailio_private_ip/g" /usr/local/etc/kamailio/kamctlrc
      sed -i "s/# DBRWPW=\"kamailiorw\"/DBRWPW=\"$pw\"/g" /usr/local/etc/kamailio/kamctlrc
      sed -i "s/# CHARSET=\"latin1\"/CHARSET=\"latin1\"/g" /usr/local/etc/kamailio/kamctlrc

      #Create main kamailio database and tables
      if [ ! -d /var/lib/mysql/kamailio ] ; then
        print_message "Notify"  "Creating kamailio database using $database"
        kamdbctl create
        if [ "$?" -eq "0" ]; then
           print_message "Success"  "kamailio database has been created"
        else
           /usr/local/sbin/kamdbctl create
           if [ "$?" -eq "0" ]; then
              print_message "Success"  "kamailio database has been created"
           else
              print_message "Error"  "kamdbctl was not located, kamilio databse could not be updated"
           fi
        fi

        # set password
        if [ "$debug_mode" == "true" ];then echo "debug: setting password in tables";fi
        cp create_additional_kamailio_tables_mariadb_blueprint.sql create_additional_kamailio_tables_mariadb.sql
        cp create_additional_kamailio_tables_blueprint.sql create_additional_kamailio_tables.sql
        cp create_asterisk_db_and_tables_mariadb_blueprint.sql create_asterisk_db_and_tables_mariadb.sql
        cp create_asterisk_db_and_tables_blueprint.sql create_asterisk_db_and_tables.sql
        cp mysql_change_password_policy_blueprint.sql  mysql_change_password_policy.sql
        sed -i "s/DBPW/${pw}/g" create_asterisk_db_and_tables.sql
        sed -i "s/DBPW/${pw}/g" create_additional_kamailio_tables_mariadb.sql
        sed -i "s/DBPW/${pw}/g" create_asterisk_db_and_tables_mariadb.sql
        sed -i "s/DBPW/${pw}/g" mysql_change_password_policy.sql
        #sed -i "s/DBPW/${pw}/g" asterisk-kamailio-data/Data/upload_data.sql
        sed -i "s/DBPW/${pw}/g" create_additional_kamailio_tables.sql

        #create additional kamailio tables and give db privileges
        if [ "$debug_mode" == "true" ];then echo "debug: creating additional kamailio tables";fi
        if [ "$database" == "MySQL" ]; then
           print_message "Info"  "Creating additional kamailio tables using MySQL"
           mysql -u root <create_additional_kamailio_tables.sql >/dev/null
           dbrslt=$?
        elif [ "$database" == "MariaDB" ]; then
           print_message "Info"  "Creating additional kamailio tables using MariaDB"
           mysql -u root <create_additional_kamailio_tables_mariadb.sql >/dev/null
           dbrslt=$?
        else
           print_message "Error" "Could not create kamailio tables (Invalid Database)"
           dbrslt=1
        fi
        if [ $dbrslt -eq 0 ]; then
           print_message "Success" "kamailio tables have been created"
        else
           print_message "Error" "Could not create kamailio tables"
           error_exists=true
        fi
      else
        print_message "Notify"  "kamailio database already exists"
      fi

      #Create asterisk database, tables and give privileges
      #if [ ! -d /var/lib/mysql/asterisk ] ; then
        if [ "$database" == "MySQL" ]; then
           print_message "Info"  "Creating asterisk database using MySQL"
           mysql -u root <create_asterisk_db_and_tables.sql >/dev/null
        elif [ "$database" == "MariaDB" ]; then
           print_message "Info"  "Creating asterisk database using MariaDB"
           mysql -u root <create_asterisk_db_and_tables_mariadb.sql >/dev/null
        else
           print_message "Error" "Could not create asterisk tables (Invalid Database)"
        fi
        if [ $? -eq 0 ]; then
           print_message "Success" "asterisk tables have been created"
        else
           print_message "Error" "Could not create asterisk tables"
           error_exists=true
        fi
      #else
        #print_message "Notify"  "asterisk database already exists"
      #fi
      invalid_answer=false
      ;;
    [nN]* )
      print_message "Notify" "Bypassing creating database"
      invalid_answer=false
      ;;
    [aA] ) exit;
    esac
  done

  #
  # If requested, Insert default data
  #
  echo
  invalid_answer=true
  while [ ${invalid_answer} == true ]; do
    read -p "Insert default data into required tables [Y/N(continue with installation)/A(abort)]:" answer15
    case $answer15 in
    [yY] ) 
      #read -p "Enter Asterisk Secret Key:" asterisk_key 
      print_message "Notify"  "Databases were located and data is being inserted into kamailio, and asterisk tables"
      if [ -d $WORKING_DIR/asterisk-kamailio-data ] ; then
        cd $WORKING_DIR/asterisk-kamailio-data
        mkdir -p Data
        #cp the upload sql script to Data dir.
        cp -f upload_data_blueprint.sql Data/upload_data.sql
        #update dispatcher table with correct IP's/Ports
        cp -f dispatcher-blueprint.csv dispatcher.csv
        sed -i "s/ASTERISK-PRIVATE-IP/$asterisk_private_ip/g" dispatcher.csv 
        sed -i "s/ASTERISK-BACKUP-PRIVATE-IP/$asterisk_private_ip_backup/g" dispatcher.csv 
        sed -i "s/ASTERISK-PORT/$asterisk_port/g" dispatcher.csv 
        sed -i "s/ASTERISK-BACKUP-PORT/$asterisk_port/g" dispatcher.csv 
        mv -f dispatcher.csv Data/dispatcher.csv
        #update sipusers table with correct IP's/Ports
        cp -f sipusers-blueprint.csv sipusers.csv
        sed -i "s/KAMAILIO-PRIVATE-IP/$kamailio_private_ip/g" sipusers.csv 
        sed -i "s/KAMAILIO-PORT/$kamailio_port/g" sipusers.csv 
        sed -i "s/SECRET-KEY/$asterisk_key/g" sipusers.csv 
        #sed -i "s/KAMAILIO-DUAL-PORT/$kamailio_dual_port/g" sipusers.csv 
        mv -f sipusers.csv Data/sipusers.csv
        #update domain table with proxy domain
        cp -f domain-blueprint.csv domain.csv
        sed -i "s/KAMAILIO-DOMAIN/$kamailio_fqdn/g" domain.csv 
        mv -f domain.csv Data/domain.csv
	#insert into trusted table kamailio and Asterisk IP's
        cp trusted-blueprint.csv Data/trusted.csv
        grep -q -F '0|$asterisk_private_ip|ANY|\N|\N|\N|0|Asterisk' Data/trusted.csv || echo "0|$asterisk_private_ip|ANY|\N|\N|\N|0|Asterisk" >> Data/trusted.csv
        grep -q -F '0|$kamailio_private_ip|ANY|\N|\N|\N|0|Asterisk' Data/trusted.csv || echo "0|$kamailio_private_ip|ANY|\N|\N|\N|0|Kamailio" >> Data/trusted.csv
        grep -q -F '0|$asterisk_public_ip|ANY|\N|\N|\N|0|Asterisk' Data/trusted.csv || echo "0|$asterisk_public_ip|ANY|\N|\N|\N|0|Asterisk" >> Data/trusted.csv
        grep -q -F '0|$kamailio_public_ip|ANY|\N|\N|\N|0|Asterisk' Data/trusted.csv || echo "0|$kamailio_public_ip|ANY|\N|\N|\N|0|Kamailio" >> Data/trusted.csv
        cd Data
        # process main script to insert data into tables
        if [ "$debug_mode" == "true" ];then echo "debug: inserting default data into tables";fi
        mysql -u root <upload_data.sql >/dev/null
        if [ $? -eq 0 ]; then
           print_message "Success" "Kamailio tables have been populated"
        else
           print_message "Error" "Kamailio tables could not be loaded"
           error_exists=true
        fi
      else
        print_message "Warning"  "Could not locate asterisk-kamailio-data directory which contains data scripts"
      fi
      invalid_answer=false
      ;;
    [nN]* )
      print_message "Notify"  "Bypassing populating Default tables"
      invalid_answer=false
      ;;
    [aA] ) exit;
    esac
  done
fi

#make sure we are back in the working directory
cd $WORKING_DIR

#
#
#Prepare Kamailio to run as a Daemon 
#
#echo -e "\n"
echo
invalid_answer=true
while [ ${invalid_answer} == true ]; do
  read -p "Create daemon process(systemd)? [Y/N]" answer16
  case $answer16 in
  [yY] ) 
    print_message "Info"  "Creating daemon for Kamailio"
    ./create_daemon_process.sh
    systemctl daemon-reload
    systemctl enable kamailio.service
    #sysvinit
    #chkconfig kamailio --add 
    #chkconfig kamailio on
    #
    invalid_answer=false
    print_message "Success" "Kamailio Daemon Created"
    ;;
  [nN]* )
    invalid_answer=false
    ;;
  esac
done

#unset the password variable
unset MYSQL_PWD

echo
print_message "Success" " Installation Process is Complete!"
echo

read -p "The Following IMORTANT Notes are crucial to coniguration...Please Read Carefully!" cont

echo
echo
echo "+-------------------------------------------------------------------------------------------------+"
echo "+                                     *** IMPORTANT ***                                           +"
echo "+                                  Read NOTE 1, and NOTE 2                                        +"
echo "+-------------------------------------------------------------------------------------------------+"
echo "+                                                                                                 +"
echo "+  NOTE 1: pjsip.conf must be changed to add kamailio end-point, outbound proxy, and contact      +"
echo "+                                                                                                 +"
echo "+  Example -                                                                                      +"
echo "+                                                                                                 +"
echo "+  [kamailio](!)                                                                                  +"
echo "+  type=endpoint                                                                                  +"
echo "+  context=from-internal                                                                          +"
echo "+  transport=transport-tcp                                                                        +"
echo "+  media_address=$asterisk_public_ip                                                              +"
echo "+  disallow=all                                                                                   +"
echo "+  allow=ulaw                                                                                     +"
echo "+  allow=vp8                                                                                      +"
echo "+  allow=h264                                                                                     +"
echo "+  allow=t140                                                                                     +"
echo "+  force_rport=yes                                                                                +"
echo "+  direct_media=no                                                                                +"
echo "+  rewrite_contact=yes                                                                            +"
echo "+  rtp_symmetric=yes                                                                              +"
echo "+  ice_support=yes                                                                                +"
echo "+  force_avp=yes                                                                                  +"
echo "+  use_avpf=yes                                                                                   +"
echo "+  dtmf_mode=auto                                                                                 +"
echo "+  media_encryption=dtls                                                                          +"
echo "+  dtls_verify=fingerprint                                                                        +"
echo "+  dtls_fingerprint=SHA-1                                                                         +"
echo "+  dtls_rekey=0                                                                                   +"
echo "+  dtls_cert_file=/etc/asterisk/keys/cert.pem                                                     +"
echo "+  dtls_ca_file=/etc/asterisk/keys/ca.crt                                                         +"
echo "+  dtls_setup=actpass                                                                             +"
echo "+  rtcp_mux=yes                                                                                   +"
echo "+  trust_id_inbound=yes                                                                           +"
echo "+  trust_id_outbound=yes                                                                          +"
echo "+  media_use_received_transport=yes                                                               +"
echo "+  message_context=internal-im                                                                    +"
echo "+                                                                                                 +"
echo "+  ;Add endpoint users to be registered in Kamailio                                               +"
echo "+  [kamailio](kamailio)                                                                           +"
echo "+  aors=kamailio                                                                       +"
echo "+                                                                                                 +"
echo "+  [kamailio]                                                                                     +"
echo "+  type=aor                                                                                       +"
echo "+  remove_existing=yes                                                                            +"
echo "+                                                                                                 +"
echo "+  [kamailio]                                                                                     +"
echo "+  type=identify                                                                                  +"
echo "+  endpoint=kamailio                                                                              +"
echo "+  match=$kamailio_private_ip                                                                     +"
echo "+                                                                                                 +"
echo "+  IMPORTANT! All endpoints with outbound activity must add the outbound_proxy option             +"
echo "+  EXCEPTION: endpoint-webrtc, and endpoint endpoint-aceapp                                       +"
echo "+  example: outbound proxy with loose routing(lr)                                                 +"
echo "+  outbound_proxy=sip:${kamailio_private_ip}\;lr                                                  +"
echo "+                                                                                                 +"
echo "+  The Following is not required when using Media-Server (Kurento)                                +"
echo "+  IMPORTANT! All extensions which connect through proxy require contact to the proxy             +"
echo "+  example: contact=sip:30001@FQDN:5060                                                           +"
echo "+                                                                                                 +"
echo "+                                                                                                 +"
echo "+-------------------------------------------------------------------------------------------------+"

echo "+-------------------------------------------------------------------------------------------------+"
echo "+                                                                                                 +"
echo "+  NOTE 2: database entries must be created for certain tables in asterisk and kamailio.          +"
echo "+          A directory called asterisk-kamailio-data was createded under the working              +"
echo "+          directory.  In this directory are table dumps that can be used as bacic                +"
echo "+          table initiations for this system to function.  The standared users 30001,..,          +"
echo "+          and the servers you chose during this installation will be inserted into the           +"
echo "+          the appropriate tables (if you chose to upload this data).                             +"
echo "+                                                                                                 +"
echo "+  kamailio:dispatcher – In this table, add all asterisk servers that will be used including      +"
echo "+  all asterisk server used for dispatching, and the failover server, should you want one.        +"
echo "+                                                                                                 +"
echo "+  kamailio:domain – In this table add the domains of the Proxy servers used in the               +"
echo "+                    dispatcher table.                                                            +"
echo "+                                                                                                 +"
echo "+  kamailio:address – In this table, add all ip-addresses for servers that will be communicating  +"
echo "+  with Asterisk and Kamailio (If authentication is being used)                                   +"
echo "+                                                                                                 +"
echo "+  kamailio:trusted – In this table add, all the ip-addresses of trusted servers.                 +"
echo "+  This will make sure that HOMER security does not stop traffic from a server in this list.      +"
echo "+                                                                                                 +"
echo "+  IMPORTANT!                                                                                     +"
echo "+  asterisk:sipusers – In this table, add all users that will be registering in Kamailio          +"
echo "+                                                                                                 +"
echo "+  asterisk:sipregs – In this table, enter Agent/VATRP endpoint number and the default            +"
echo "+  Asterisk Server that this endpoint is connected to                                             +"
echo "+                                                                                                 +"
echo "+-------------------------------------------------------------------------------------------------+"

echo
echo
print_message "Info" "(See file pjsip.conf-additions* for a templetes of above pjsip.conf required changes)"
print_message "Info" "(There is example of pjsip.conf with/without media server)"
print_message "Info" "(See Document - 'Kamailio Installation and Configuration' for futher details about Installation)"
echo

#
#Start Kamailio
#
echo 
invalid_answer=true
while [ $invalid_answer == true ]; do
  read -p "Start Kamailio? [Y/N]" answer17
  case $answer17 in
  [yY] ) 
    if [ -d /etc/ssl ]; then
       chmod 644 /etc/ssl/cert.pem
       print_message "Notify" "=> Starting Kamailio"
       service kamailio start
       ps -auxw | grep -P '\b'kamailio'(?!-)\b' > /dev/null
       if [ $? != 0 ]; then
          echo
          print_message "Error" "There has been an issue with starting Kamailio."
          echo "         Possible reasons:"
          echo "          - Make sure Asterisk or another process is not running on a same port that was chosen for Kamailio"
          echo "          -   suspect ports => 443, 8443, 5060"
          echo "          - A port being used by Kamailio is blocked, verify firewall"
          echo "          - The cert directory is missing(/etc/ssl/)"
          echo "          - cert.pem or key.pem are is missing in /etc/ssl"
          echo "          - The key (/etc/ssl/cert.pem) pointed to by tls in Kamailio.cfg has incorrect permissions"
          echo "            kamailio user needs read permission to asterisk.pem (640) "
          echo "              => Once resloved, run 'service kamailio start' or 'systemctl start kamailio'"
          echo
          error_exists=true
       else
          print_message "Success" "Kamailio has been started"
       fi
       invalid_answer=false
    else
       print_message "Warning" "Asterisk certificates are missing (/etc/ssl), cannot start Kamailio"
       error_exists=true
       invalid_answer=false
    fi
    ;;
  [nN]* )
    invalid_answer=false
    ;;
  esac
done

echo
echo
if [  "$error_exists" == "true" ]; then
  print_message "Warning" " Process Complete with errors or warnings!"
  exit 1
else
  print_message "Success" " Process Complete with Success!"
fi
echo
