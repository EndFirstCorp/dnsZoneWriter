package main

import (
	"testing"
	"time"
)

func TestNewDnsRecord(t *testing.T) {
	actual := newDNSRecord("name", "type", "data")
	if actual.Name != "name" || actual.TTL != "" || actual.Class != "IN" || actual.RecordType != "type" || actual.Data != "data" {
		t.Fatal("expected dns record doesn't match actual", actual)
	}
}

func TestNewARecord(t *testing.T) {
	actual := newARecord("mail", "123.45.67.89")
	if actual.Name != "mail" || actual.RecordType != "A" || actual.Data != "123.45.67.89" {
		t.Fatal("expected A record", actual)
	}
}

func TestNewMxRecord(t *testing.T) {
	actual := newMxRecord("domain", "mail", 1)
	if actual.Name != "domain." || actual.RecordType != "MX" || actual.Data != "1 mail.domain." {
		t.Fatal("expected MX record", actual)
	}
}

func TestNewMxRecordAbsolute(t *testing.T) {
	actual := newMxRecord("domain.com", "absolute.example.com.", 1)
	if actual.Name != "domain.com." || actual.RecordType != "MX" || actual.Data != "1 absolute.example.com." {
		t.Fatal("expected absolute MX record", actual)
	}
}

func TestNewSoaRecord(t *testing.T) {
	actual := newSoaRecord("domain", "ns1", "hostmaster", time.Second*5, time.Second*10, time.Second*15, time.Second*20)
	if actual.Name != "domain." || actual.RecordType != "SOA" || actual.Data != "ns1.domain. hostmaster.domain. (SERIALNUMBER 5 10 15 20)" {
		t.Fatal("expected SOA record", actual)
	}
}

func TestNewDkimRecord(t *testing.T) {
	actual := newDkimRecord("domain", "dkimValue")
	if actual.Name != "mail._domainkey.domain" || actual.RecordType != "TXT" || actual.Data != "dkimValue" {
		t.Fatal("expected SOA record", actual)
	}
}

func TestNewNsRecord(t *testing.T) {
	actual := newNsRecord("domain", "ns1")
	if actual.Name != "domain." || actual.RecordType != "NS" || actual.Data != "ns1.domain." {
		t.Fatal("expected NS record", actual)
	}
}

func TestNewTlsaRecord(t *testing.T) {
	actual := newTlsaRecord(1, "tlsakey")
	if actual.Name != "_1._tcp" || actual.RecordType != "TLSA" || actual.Data != "3 0 1 tlsakey" {
		t.Fatal("expected TLSA record", actual)
	}
}

func TestNewSpfRecord(t *testing.T) {
	actual := newSpfRecord("name", "allow")
	if actual.Name != "name" || actual.RecordType != "TXT" || actual.Data != "\"v=spf1 allow -all\"" {
		t.Fatal("expected SPF record", actual)
	}
}

func TestNewDmarcRecord(t *testing.T) {
	actual := newDmarcRecord("name", "policy")
	if actual.Name != "_dmarc.name" || actual.RecordType != "TXT" || actual.Data != "\"v=DMARC1; p=policy\"" {
		t.Fatal("expected DMARC record", actual)
	}
}

func TestNewCNameRecord(t *testing.T) {
	actual := newCNameRecord("name", "canonicalName")
	if actual.Name != "name" || actual.RecordType != "CNAME" || actual.Data != "canonicalName" {
		t.Fatal("expected CNAME record", actual)
	}
}

func TestToString(t *testing.T) {
	actual := newDNSRecord("name", "type", "data").toString()
	if actual != "name\t\tIN\ttype\tdata\n" {
		t.Fatal("expected ToString to match actual", actual)
	}
}
