# Kamailio SIP Proxy Server Installation


## Prerequisites
The installation scripts requires the following:

* Root privilages

* The machine operating system must be CentOS, RedHat, Fedora, or Amazon Linux 2.  The script uses sysvinit style services managemnet calls, so most (non Debian) OS's should be able to execute the commands in the script.

* The Private IP Address, and Port of the Asterisk and Kamalio Servers.
  Note: Kamailio will default to the IP Address of the Server it is being installed on and ports will default to 5060.
  Note: Asterisk port will default to 5060.

* If installing MySQL, the Port for MySQL is also required (Default port is 3306, use 13306 if it is desired to use a sql gui).


## Instructions for use of AD_kamailio-install.sh
1. Open the parent directory where the installation repository will be placed; you can install from any directory.

2. Clone the repository
For example:
```bash
[user@installation-directroy ~]$ git clone ssh://git@git.codev.mitre.org/acrdemo/kamailio.git
```

3. If using a local proxy for yum, update the file tmp_proxy to include that proxy e.g. http://proxy-ip:port, if you do not do this
   you will be prompted during the script execution.

4. Run the script as root. => # sudo ./AD_kamailio-install.sh

5. The script will prompt you through the installation.

6. Modify pjsip.conf as denoted in the installation instructions that
   are shown upon completion of this script, and view the example pjsip changes in pjsip.conf-additions.

7. Verify /usr/local/etc/kamailio/kamailio.cfg SECRET-KEY with Asterisk auth password.

8. Verify that the correct cert and private-key are installed on the kamailio server in the default directory of
   /etc/ssl, or in a directory as stated in the kamailio configuration file (default location is **/usr/local/etc/kamailio**).
   
   
### Starting Proxies
* Start kamailio => 'service kamailio start'
* Start rtpengine => 'service rtpengine start', note that rtpengine is a service and should already be running


### Restarting Proxies
* Restart kamailio option 1=> 'service kamailio restart'
* Restart kamailio option 2=> './restart-kamailio.sh' from /usr/local/etc/kamailio
* Restart rtpengine => 'service rtpengine restart'


### logging
* There are two log files which are used kamailio.log(local0.*) and retpengine.log(localx.*, where x is defaulted to 1), both are in /var/log.
  These are configured in /etc/rsyslog.conf.
  * Add an entry in /etc/rsyslog.conf for each logfile and then restart rsyslog => 'service rsyslog restart'
* If log files get hung perform a logging restart => 'service rsyslog restart'
* IMPORTANT NOTE: If rtpengine log level is set high...> 2, log files can become huge.  It is recommended
                  to create a cron job to clear out kamailio.log and rtpengine.log regularly (at least once a day).
                  How often will depend on use and the rtpengine log level.


### Help
* Look in /usr/local/etc/kamailio for scripts to help with various task such as wiping prior installs
* To check kamailio.cfg status => './check_kamailio_cfg.sh' found in /usr/local/etc/kamailio
* Verify rtpenigne and sip proxy are communicating => Restart Kamailio and look in /var/log/rtpengine.log 
  for ping/pongs
  (Note: In order to see the ping/pongs, logging level must be 7).

### Re-install from scratch
* To re-install from scratch, run the script wipe_all_apps.sh  WARNING - (KAMAILIO, RTPENGINE, and LOCAL-DATABASE) will be removed
