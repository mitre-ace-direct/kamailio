cat > /etc/default/kamailio<< EOF 
#
# Kamailio startup options
#

# Set to yes to enable kamailio, once configured properly.
RUN_KAMAILIO=yes

# User to run as
USER=kamailio

# Group to run as
GROUP=kamailio

# Amount of shared memory to allocate for the running Kamailio server (in Mb)
SHM_MEMORY=64

# Amount of private memory to allocate for the running Kamailio server (in Mb)
PKG_MEMORY=8

PIDFILE=/var/run/kamailio/kamailio.pid
CFGFILE=/usr/local/etc/kamailio/kamailio.cfg

# Enable the server to leave a core file when it crashes.
# Set this to 'yes' to enable kamailio to leave a core file when it crashes
# or 'no' to disable this feature. This option is case sensitive and only
# accepts 'yes' and 'no' and only in lowercase letters.
# On some systems (e.g. Ubuntu 6.10, Debian 4.0) it is necessary to specify
# a directory for the core files to get a dump. Look into the kamailio
# init file for an example configuration.
#DUMP_CORE=no

# Add extra command line parameters in the EXTRA_OPTIONS variable
# EXTRA_OPTIONS="-a no"
EOF

##############################################################################

#   Create pid file directory
if [[ ! -e /var/run/kamailio ]]; then
    mkdir -p /var/run/kamailio 
fi

#   Add Kamailio user and group
echo
response=$(grep -c '^kamailio:' /etc/passwd)
echo
if [ $response == "0" ]; then
    #http://www.commandlinefu.com/commands/view/5595/determine-next-available-uid
    uid=$(awk -F: '{uid[$3]=1}END{for(x=5000; x<=6000; x++) {if(uid[x] != ""){}else{print x; exit;}}}' /etc/passwd)
    groupadd -g $uid kamailio 
    useradd -u $uid -g $uid -d /var/run/kamailio -M -s /bin/false kamailio 
fi
chown kamailio:kamailio -R /var/run/kamailio

#   Create Kamailio Systemd file for starting and stopping kamailio service.
cat >/etc/systemd/system/kamailio.service<< EOF 
[Unit]
Description=Kamailio SIP Proxy Server
After=syslog.target network.target mysql.service
[Service]
Type=forking
EnvironmentFile=-/etc/default/kamailio
# ExecStart requires a full absolute path
ExecStart=/usr/local/sbin/kamailio -P \$PIDFILE -f \$CFGFILE -m \$SHM_MEMORY -M \$PKG_MEMORY -u \$USER -g \$GROUP
ExecStopPost=/bin/rm -f \$PIDFILE
Restart=on-abort
[Install]
WantedBy=multi-user.target
EOF
