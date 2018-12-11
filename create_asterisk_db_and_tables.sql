CREATE DATABASE IF NOT EXISTS asterisk; 

USE asterisk;

CREATE TABLE IF NOT EXISTS `sipusers` (
 `id` INT(11) NOT NULL AUTO_INCREMENT,
 `name` VARCHAR(80) NOT NULL DEFAULT '',
 `host` VARCHAR(31) NOT NULL DEFAULT '',
 `nat` VARCHAR(5) NOT NULL DEFAULT 'no',
 `type` enum('user','peer','friend') NOT NULL DEFAULT 'friend',
 `accountcode` VARCHAR(20) DEFAULT NULL,
 `amaflags` VARCHAR(13) DEFAULT NULL,
 `call-limit` SMALLINT(5) UNSIGNED DEFAULT NULL,
 `callgroup` VARCHAR(10) DEFAULT NULL,
 `callerid` VARCHAR(80) DEFAULT NULL,
 `cancallforward` CHAR(3) DEFAULT 'yes',
 `canreinvite` CHAR(3) DEFAULT 'yes',
 `context` VARCHAR(80) DEFAULT NULL,
 `defaultip` VARCHAR(15) DEFAULT NULL,
 `dtmfmode` VARCHAR(7) DEFAULT NULL,
 `fromuser` VARCHAR(80) DEFAULT NULL,
 `fromdomain` VARCHAR(80) DEFAULT NULL,
 `insecure` VARCHAR(4) DEFAULT NULL,
 `language` CHAR(2) DEFAULT NULL,
 `mailbox` VARCHAR(50) DEFAULT NULL,
 `md5secret` VARCHAR(80) DEFAULT NULL,
 `deny` VARCHAR(95) DEFAULT NULL,
 `permit` VARCHAR(95) DEFAULT NULL,
 `mask` VARCHAR(95) DEFAULT NULL,
 `musiconhold` VARCHAR(100) DEFAULT NULL,
 `pickupgroup` VARCHAR(10) DEFAULT NULL,
 `qualify` CHAR(3) DEFAULT NULL,
 `regexten` VARCHAR(80) DEFAULT NULL,
 `restrictcid` CHAR(3) DEFAULT NULL,
 `rtptimeout` CHAR(3) DEFAULT NULL,
 `rtpholdtimeout` CHAR(3) DEFAULT NULL,
 `secret` VARCHAR(80) DEFAULT NULL,
 `setvar` VARCHAR(100) DEFAULT NULL,
 `disallow` VARCHAR(100) DEFAULT NULL,
 `allow` VARCHAR(100) DEFAULT NULL,
 `fullcontact` VARCHAR(80) NOT NULL DEFAULT '',
 `ipaddr` VARCHAR(15) NOT NULL DEFAULT '',
 `port` mediumint(5) UNSIGNED NOT NULL DEFAULT '0',
 `regserver` VARCHAR(100) DEFAULT NULL,
 `regseconds` INT(11) NOT NULL DEFAULT '0',
 `lastms` INT(11) NOT NULL DEFAULT '0',
 `username` VARCHAR(80) NOT NULL DEFAULT '',
 `defaultuser` VARCHAR(80) NOT NULL DEFAULT '',
 `subscribecontext` VARCHAR(80) DEFAULT NULL,
 `useragent` VARCHAR(20) DEFAULT NULL,
 `sippasswd` VARCHAR(80) DEFAULT NULL,
 PRIMARY KEY  (`id`),
 UNIQUE KEY `name_uk` (`name`)
);
 
CREATE TABLE IF NOT EXISTS `sipregs` (
 `id` INT(11) NOT NULL AUTO_INCREMENT,
 `name` VARCHAR(80) NOT NULL DEFAULT '',
 `fullcontact` VARCHAR(80) NOT NULL DEFAULT '',
 `ipaddr` VARCHAR(15) NOT NULL DEFAULT '',
 `port` mediumint(5) UNSIGNED NOT NULL DEFAULT '0',
 `username` VARCHAR(80) NOT NULL DEFAULT '',
 `regserver` VARCHAR(100) DEFAULT NULL,
 `regseconds` INT(11) NOT NULL DEFAULT '0',
 PRIMARY KEY  (`id`),
 UNIQUE KEY `name` (`name`)
);
 
CREATE TABLE IF NOT EXISTS `voiceboxes` (
 `uniqueid` INT(4) NOT NULL AUTO_INCREMENT,
 `customer_id` VARCHAR(10) DEFAULT NULL,
 `context` VARCHAR(10) NOT NULL,
 `mailbox` VARCHAR(10) NOT NULL,
 `password` VARCHAR(12) NOT NULL,
 `fullname` VARCHAR(150) DEFAULT NULL,
 `email` VARCHAR(50) DEFAULT NULL,
 `pager` VARCHAR(50) DEFAULT NULL,
 `tz` VARCHAR(10) DEFAULT 'central',
 `attach` enum('yes','no') NOT NULL DEFAULT 'yes',
 `saycid` enum('yes','no') NOT NULL DEFAULT 'yes',
 `dialout` VARCHAR(10) DEFAULT NULL,
 `callback` VARCHAR(10) DEFAULT NULL,
 `review` enum('yes','no') NOT NULL DEFAULT 'no',
 `operator` enum('yes','no') NOT NULL DEFAULT 'no',
 `envelope` enum('yes','no') NOT NULL DEFAULT 'no',
 `sayduration` enum('yes','no') NOT NULL DEFAULT 'no',
 `saydurationm` tinyint(4) NOT NULL DEFAULT '1',
 `sendvoicemail` enum('yes','no') NOT NULL DEFAULT 'no',
 `delete` enum('yes','no') NULL DEFAULT 'no',
 `nextaftercmd` enum('yes','no') NOT NULL DEFAULT 'yes',
 `forcename` enum('yes','no') NOT NULL DEFAULT 'no',
 `forcegreetings` enum('yes','no') NOT NULL DEFAULT 'no',
 `hidefromdir` enum('yes','no') NOT NULL DEFAULT 'yes',
 `stamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 PRIMARY KEY  (`uniqueid`),
 KEY `mailbox_context` (`mailbox`,`context`)
); 
 
CREATE TABLE IF NOT EXISTS `voicemessages` (
 `id` INT(11) NOT NULL AUTO_INCREMENT,
 `msgnum` INT(11) NOT NULL DEFAULT '0',
 `dir` VARCHAR(80) DEFAULT '',
 `context` VARCHAR(80) DEFAULT '',
 `macrocontext` VARCHAR(80) DEFAULT '',
 `callerid` VARCHAR(40) DEFAULT '',
 `origtime` VARCHAR(40) DEFAULT '',
 `duration` VARCHAR(20) DEFAULT '',
 `mailboxuser` VARCHAR(80) DEFAULT '',
 `mailboxcontext` VARCHAR(80) DEFAULT '',
 `recording` longblob,
 `flag` VARCHAR(128) DEFAULT '',
 PRIMARY KEY  (`id`),
 KEY `dir` (`dir`)
);
 
 
CREATE TABLE IF NOT EXISTS version (
    TABLE_NAME VARCHAR(32) NOT NULL,
    table_version INT UNSIGNED DEFAULT 0 NOT NULL
);
INSERT INTO version (TABLE_NAME, table_version) VALUES ('sipusers','6');

CREATE TABLE IF NOT EXISTS `cdr` (
`calldate` datetime NOT NULL default CURRENT_TIMESTAMP, 
`clid` varchar(80) NOT NULL default '',
`src` varchar(80) NOT NULL default '',
`dst` varchar(80) NOT NULL default '',
`dcontext` varchar(80) NOT NULL default '',
`channel` varchar(80) NOT NULL default '',
`dstchannel` varchar(80) NOT NULL default '',
`lastapp` varchar(80) NOT NULL default '',
`lastdata` varchar(80) NOT NULL default '',
`duration` int(11) NOT NULL default '0',
`billsec` int(11) NOT NULL default '0',
`disposition` varchar(45) NOT NULL default '',
`amaflags` int(11) NOT NULL default '0',
`accountcode` varchar(20) NOT NULL default '',
`userfield` varchar(255) NOT NULL default '',
`uniqueid` VARCHAR(32) NOT NULL default '',
`linkedid` VARCHAR(32) NOT NULL default '',
`sequence` VARCHAR(32) NOT NULL default '',
`peeraccount` VARCHAR(32) NOT NULL default '' );

ALTER TABLE `cdr` ADD INDEX ( `calldate` );
ALTER TABLE `cdr` ADD INDEX ( `dst` );
ALTER TABLE `cdr` ADD INDEX ( `accountcode` );

GRANT ALL PRIVILEGES ON asterisk.* TO 'asterisk'@'%' IDENTIFIED BY '2tZTp&b49#TSFYc2';
GRANT ALL PRIVILEGES ON asterisk.* TO 'asterisk'@'localhost' IDENTIFIED BY '2tZTp&b49#TSFYc2';
GRANT ALL PRIVILEGES ON asterisk.* TO 'kamailio'@'%' IDENTIFIED BY '2tZTp&b49#TSFYc2';
GRANT ALL PRIVILEGES ON asterisk.* TO 'kamailio'@'localhost' IDENTIFIED BY '2tZTp&b49#TSFYc2';

FLUSH PRIVILEGES;
