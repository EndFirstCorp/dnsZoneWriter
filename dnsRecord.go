package main

import (
	"fmt"
	"strings"
	"time"
)

type DnsRecord struct {
	Name       string
	TTL        string
	Class      string
	RecordType string
	Data       string
}

func NewARecord(name string, ipAddress string) *DnsRecord {
	return NewDnsRecord(name, "A", ipAddress)
	//z.AddSshfpRecords(name)
}

func NewDnsRecord(name string, recordType string, data string) *DnsRecord {
	return &DnsRecord{name, "", "IN", recordType, data}
}

func NewMxRecord(domain string, mxName string, priority int16) *DnsRecord {
	if strings.HasSuffix(mxName, ".") {
		return NewDnsRecord(domain+".", "MX", fmt.Sprintf("%d %s", priority, mxName))
	} else {
		return NewDnsRecord(domain+".", "MX", fmt.Sprintf("%d %s.%s.", priority, mxName, domain))
	}
}

func NewSoaRecord(domain string, primaryNameServer string, hostmaster string, refresh time.Duration, retry time.Duration, expire time.Duration, negativeTTL time.Duration) *DnsRecord {
	return NewDnsRecord(domain+".", "SOA",
		fmt.Sprintf("%s.%s. %s.%s. (SERIALNUMBER %d %d %d %d)", primaryNameServer, domain, hostmaster, domain,
			int(refresh.Seconds()), int(retry.Seconds()), int(expire.Seconds()), int(negativeTTL.Seconds())))
}

func NewDkimRecord(name string, dkimValue string) *DnsRecord {
	recordName := "mail._domainkey"
	if name != "" {
		recordName += "." + name
	}
	return NewDnsRecord(recordName, "TXT", dkimValue)
}

func NewNsRecord(domain string, nsName string) *DnsRecord {
	return NewDnsRecord(domain+".", "NS", nsName+"."+domain+".")
}

/* while this is technically "working", there is no way to ensure that the output from the ssh-keyscan is not being returned from a MITM attacker.
// The only way to fully ensure this is returning a valid result is to check SSH public key fingerprints from the console (not through SSH) with
// ssh-keygen -r *key.pub http://www.phcomp.co.uk/Tutorials/Unix-And-Linux/ssh-check-server-fingerprint.html
func NewSshfpRecords(domain string, name string) []*DnsRecord {
	fqdn := name + "." + domain
	if name == "" {
		fqdn = domain
	}
	data, err := commander.Output("ssh-keyscan", "-p", "822", fqdn)
	if err != nil {
		log.Fatal(err)
	}
	return NewDnsRecord(domain+".", "SSHFP", "2 1 "+string(data))
}*/

func NewTlsaRecord(port int, tlsaKey string) *DnsRecord {
	return NewDnsRecord(fmt.Sprintf("_%d._tcp", port), "TLSA", "3 0 1 "+tlsaKey)
}

func NewSpfRecord(name string, allow string) *DnsRecord {
	return NewDnsRecord(name, "TXT", "\"v=spf1 "+allow+" -all\"")
}

func NewDmarcRecord(name string, policy string) *DnsRecord {
	recordName := "_dmarc"
	if name != "" {
		recordName += "." + name
	}
	return NewDnsRecord(recordName, "TXT", "\"v=DMARC1; p="+policy+"\"")
}

func (r *DnsRecord) ToString() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", r.Name, r.TTL, r.Class, r.RecordType, r.Data)
}
