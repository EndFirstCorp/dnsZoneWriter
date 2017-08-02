
# DNS Zone Writer
[![Build Status](https://travis-ci.org/EndFirstCorp/dnsZoneWriter.svg?branch=master)](https://travis-ci.org/EndFirstCorp/dnsZoneWriter) [![Coverage Status](https://coveralls.io/repos/github/EndFirstCorp/dnsZoneWriter/badge.svg?branch=master)](https://coveralls.io/github/EndFirstCorp/dnsZoneWriter?branch=master)

A NSD configuration writer written in Go that manages DNS configuration on both master and slave servers

## Getting Started
    go get https://github.com/robarchibald/dnsZoneWriter

 1. Update dnsZoneWriter.conf with the following information 
	- DbServer - database server
	- DbPort - database server port
	- DbUser - database username
	- DbDatabase - name of database used
	- DbPassword - database password
	- NsdDir - location of NSD server install (/etc/nsd on Ubuntu)
	- ZoneFileDirectory - location of NSD Zone files ($NsdDir/zones on Ubuntu)
	- ZonePassword - password used for master/slave replication
	- DKIMKeyFilePath - location of DKIM key file
	- TLSPublicKeyPath - server public key file
	- DNSMasterIP - IP address of the Master server
	- DNSSlaveIPs - IP addresses of the Slave server(s)
	- SigningAlgorithm - algorithm used to sign zone files for DNSSec (RSASHA256)
	- DNSSecKeyDir - directory that keys will be stored
 2. Run dnsZoneWriter executable. If database hasn't yet been created, it will be created on first run. NOTE: Currently dnsZoneWriter is expecting a Postgres database
 3. Update database with desired domains, A, NS, MX, and CNAME records
 4. Run dnsZoneWriter executable again. Zone files should be created or updated