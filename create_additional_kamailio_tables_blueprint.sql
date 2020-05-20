use kamailio;

CREATE TABLE IF NOT EXISTS `sip_trace` (
  `id` bigint(20) NOT NULL auto_increment,
  `date` datetime NOT NULL default CURRENT_TIMESTAMP,
  `callid` varchar(254) NOT NULL default '',
  `traced_user` varchar(128) NOT NULL default '',
  `msg` text NOT NULL,
  `method` varchar(50) NOT NULL default '',
  `status` varchar(254) NOT NULL default '',
  `fromip` varchar(50) NOT NULL default '',
  `toip` varchar(50) NOT NULL default '',
  `fromtag` varchar(64) NOT NULL default '',
  `direction` varchar(4) NOT NULL default '',
  PRIMARY KEY  (`id`),
  INDEX user_idx (traced_user),
  INDEX date_id (date),
  INDEX ip_idx (fromip),
  KEY `call_id` (`callid`)
);

INSERT INTO version VALUES("sip_trace",4);

GRANT ALL PRIVILEGES ON kamailio.* TO 'asterisk'@'%' IDENTIFIED BY 'DBPW';
GRANT ALL PRIVILEGES ON kamailio.* TO 'kamailio'@'%' IDENTIFIED BY 'DBPW';
GRANT ALL PRIVILEGES ON kamailio.* TO 'asterisk'@'localhost' IDENTIFIED BY 'DBPW';
GRANT ALL PRIVILEGES ON kamailio.* TO 'kamailio'@'localhost' IDENTIFIED BY 'DBPW';

ALTER TABLE trusted ADD comment VARCHAR(20);

FLUSH PRIVILEGES;
