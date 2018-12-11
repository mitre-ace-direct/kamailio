# Kamailio SIP Proxy Server Installation 
This is the README.md file for the installation of the SIP Proxy Server (Kamailio) 

## Prerequisites
The installation scripts requires the following:

* Root privilages

* The machine operating system must be CentOS, RedHat, Fedora, or Amazon Linux 2.  The script uses sysvinit style services managemnet calls, so most (non Debian) OS's should be able to execute the commands in the script.

* The Private IP Address, and Port of the Asterisk and Kamalio Servers.
  Note: Kamailio will default to the IP Address of the Server it is being installed on and ports will default to 5060.

* If installing MySQL, the Port for MySQL is also required (if the Default port (3306) is not being used).


## Instructions for Use of kamailio-install.sh
1. Open the parent directory where the installation repository will be placed; you can install from any directory.

2. Clone the repository as yourself but not centos
```sh
For example:
[user@nstallation-directroy ~]$ git clone ssh://git@git.codev.mitre.org/acrdemo/kamailio.git
```
The Git source to be used is 'ssh://git@git.codev.mitre.org/acrdemo/kamailio.git', and the latest version should be used for the Git branch, such as 'master'.

3. Run the script as root. => # ./kamailio-install.sh

4. The script will prompt you through the installation.

5. Modify pjsip.conf as denoted in the installation instructions that
   are shown upon completion of this script.

