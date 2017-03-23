package main

import (
	"fmt"
	"strings"
	"time"
)

type dnsRecord struct {
	Name       string
	TTL        string
	Class      string
	RecordType string
	Data       string
}

func newARecord(name string, ipAddress string) *dnsRecord {
	return newDNSRecord(name, "A", ipAddress)
	//z.AddSshfpRecords(name)
}

func newDNSRecord(name string, recordType string, data string) *dnsRecord {
	return &dnsRecord{name, "", "IN", recordType, data}
}

func newMxRecord(domain string, name string, value string, priority int16) *dnsRecord {
	if name == "" {
		name = domain + "."
	} else if !strings.HasSuffix(name, ".") {
		name = name + "." + domain + "."
	}
	if strings.HasSuffix(value, ".") {
		return newDNSRecord(name, "MX", fmt.Sprintf("%d %s", priority, value))
	}
	return newDNSRecord(name, "MX", fmt.Sprintf("%d %s.%s.", priority, value, domain))
}

func newSoaRecord(domain string, primaryNameServer string, hostmaster string, refresh time.Duration, retry time.Duration, expire time.Duration, negativeTTL time.Duration) *dnsRecord {
	return newDNSRecord(domain+".", "SOA",
		fmt.Sprintf("%s.%s. %s.%s. (SERIALNUMBER %d %d %d %d)", primaryNameServer, domain, hostmaster, domain,
			int(refresh.Seconds()), int(retry.Seconds()), int(expire.Seconds()), int(negativeTTL.Seconds())))
}

func newDkimRecord(name string, dkimValue string) *dnsRecord {
	recordName := name + "._domainkey"
	if name == "" {
		recordName = "mail._domainkey"
	}
	return newDNSRecord(recordName, "TXT", dkimValue)
}

func newNsRecord(domain, name, value string) *dnsRecord {
	if name == "" {
		name = domain + "."
	} else if !strings.HasSuffix(name, ".") {
		name = name + "." + domain + "."
	}
	// could be pointing to another domain, so don't add domain
	if strings.HasSuffix(value, ".") {
		return newDNSRecord(name, "NS", value)
	}
	return newDNSRecord(name, "NS", value+"."+domain+".")
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

func newTlsaRecord(port int, tlsaKey string) *dnsRecord {
	return newDNSRecord(fmt.Sprintf("_%d._tcp", port), "TLSA", "3 0 1 "+tlsaKey)
}

func newSpfRecord(domain, name string, allow string) *dnsRecord {
	if name == "" {
		name = domain + "."
	} else if !strings.HasSuffix(name, ".") {
		name = name + "." + domain + "."
	}
	return newDNSRecord(name, "TXT", fmt.Sprintf("\"v=spf1 %s -all\"", allow))
}

func newDmarcRecord(name string, policy string) *dnsRecord {
	recordName := "_dmarc"
	if name != "" {
		recordName += "." + name
	}
	return newDNSRecord(recordName, "TXT", "\"v=DMARC1; p="+policy+"; rua=mailto:dmarc-report@endfirst.com\"")
}

func newCNameRecord(name, canonicalName string) *dnsRecord {
	return newDNSRecord(name, "CNAME", canonicalName)
}

func (r *dnsRecord) toString() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", r.Name, r.TTL, r.Class, r.RecordType, r.Data)
}
