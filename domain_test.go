package main

import (
	"os"
	"testing"
)

func TestBuildDnsRecords(t *testing.T) {
	ipAddress := "123.45.67.89"
	d := &Domain{Name: "example.com", IpAddress: ipAddress,
		NsRecords: []NsRecord{NsRecord{Name: "ns1"}},
		MxRecords: []MxRecord{MxRecord{Name: "mail1", Priority: 10}},
		ARecords:  []ARecord{ARecord{Name: "server", IpAddress: &ipAddress}}}
	d.BuildDnsRecords("mail.txt", "ssl_certificate.pem")
	if len(d.DnsRecords) != 13 || d.DnsRecords[0].RecordType != "SOA" || d.DnsRecords[1].RecordType != "A" || d.DnsRecords[2].Data != "\"v=spf1 mx -all\"" || d.DnsRecords[3].Data != "\"v=DMARC1; p=quarantine\"" ||
		d.DnsRecords[4].RecordType != "TLSA" || d.DnsRecords[5].RecordType != "TLSA" || d.DnsRecords[6].Name != "mail._domainkey" || d.DnsRecords[7].RecordType != "NS" || d.DnsRecords[8].RecordType != "MX" ||
		d.DnsRecords[9].Name != "mail._domainkey.mail1" || d.DnsRecords[10].RecordType != "A" || d.DnsRecords[11].Data != "\"v=spf1  -all\"" || d.DnsRecords[12].Data != "\"v=DMARC1; p=reject\"" {
		t.Fatalf("expected 13 dns records with specific values: %s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", d.DnsRecords[0], d.DnsRecords[1], d.DnsRecords[2], d.DnsRecords[3], d.DnsRecords[4], d.DnsRecords[5], d.DnsRecords[6], d.DnsRecords[7], d.DnsRecords[8], d.DnsRecords[9], d.DnsRecords[10], d.DnsRecords[11], d.DnsRecords[12])
	}
}

func TestAdd(t *testing.T) {
	d := &Domain{}
	record := NewARecord("name", "ip")
	d.add(record)
	if d.DnsRecords[0] != *record {
		t.Fatal("expected to have added Dns record", d.DnsRecords[0])
	}
}

func TestAddDomain(t *testing.T) {
	d := &Domain{}
	ipAddress := "50.43.43.48"
	d.addDomain("name", &ipAddress, nil)
	if len(d.DnsRecords) != 3 || d.DnsRecords[0].RecordType != "A" ||
		d.DnsRecords[1].Data != "\"v=spf1  -all\"" || d.DnsRecords[2].Data != "\"v=DMARC1; p=reject\"" {
		t.Fatal("expected to have added A record, SPF record and DMARC record", d.DnsRecords)
	}
}

func TestAddDomainDynamicMx(t *testing.T) {
	d := &Domain{MxRecords: []MxRecord{MxRecord{1, "name", 5}}}
	fqdn := "google-public-dns-a.google.com"
	d.addDomain("name", nil, &fqdn)
	if len(d.DnsRecords) != 3 || d.DnsRecords[0].RecordType != "A" ||
		d.DnsRecords[1].Data != "\"v=spf1 ip4:8.8.8.8 -all\"" || d.DnsRecords[2].Data != "\"v=DMARC1; p=quarantine\"" {
		t.Fatal("expected to have added A record, SPF record and DMARC record", d.DnsRecords)
	}
}

func TestGetIp(t *testing.T) {
	bogus := "bogus.domain"
	fqdn := "google-public-dns-a.google.com"
	nameToIp["google-public-dns-a.google.com"] = "" // ensure not filled yet
	ipResolve := getIp(nil, &fqdn)                  // should do a name resolution this time
	ipMap := getIp(nil, &fqdn)                      // should pull from map this time
	if ipResolve != "8.8.8.8" || ipMap != "8.8.8.8" || nameToIp["google-public-dns-a.google.com"] != "8.8.8.8" {
		t.Error("expected IP address to equal 8.8.8.8.  Has DNS changed?", ipResolve, ipMap)
	}
	if getIp(nil, &bogus) != "" {
		t.Error("expected no IP address returned for bogus address")
	}
}

func TestGetIpBogusName(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	fqdn := "12345"
	ip := getIp(nil, &fqdn)
	if ip != "" {
		t.Fatal("expected empty ip", ip)
	}
}

func TestGetTlsaKey(t *testing.T) {
	shell = &CommandHelper{}
	key := getTlsaKey("testData/ssl_certificate.pem")
	if key != "111006378afbe8e99bb02ba87390ca429fca2773f74d7f7eb5744f5ddf68014b" {
		t.Fatal("expected valid sha256 hash of the ssl certificate", key)
	}
}

func TestGetTlsaKeyNotFound(t *testing.T) {
	key := getTlsaKey("bogusfile")
	if key != "TLSA_KEY_FILE_NOT_FOUND_AT_bogusfile" {
		t.Fatal("expected error message", key)
	}
}

func TestGetDkimValue(t *testing.T) {
	value := getDkimValue("testData/mail.txt")
	expected := `( "v=DKIM1; k=rsa; s=email; "
          "p=1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012" )`
	if value != expected {
		t.Fatal("expected Dkim value to match value in mail.txt", value)
	}
}

func TestGetDkimValueNotFound(t *testing.T) {
	value := getDkimValue("bogusfile")
	expected := "DKIM_KEY_NOT_FOUND_AT_bogusfile"
	if value != expected {
		t.Fatal("expected error message", value)
	}
}

func TestDomainToString(t *testing.T) {
	ipAddress := "123.45.67.89"
	d := &Domain{Name: "example.com", IpAddress: ipAddress, NsRecords: []NsRecord{NsRecord{Name: "ns1"}}}
	d.BuildDnsRecords("bogus", "bogus")
	expected := `
$ORIGIN example.com.
$TTL 1800

example.com.		IN	SOA	ns1.example.com. hostmaster.example.com. (1234567 7200 1800 1209600 1800)
		IN	A	123.45.67.89
		IN	TXT	"v=spf1 mx -all"
_dmarc		IN	TXT	"v=DMARC1; p=quarantine"
_25._tcp		IN	TLSA	3 0 1 TLSA_KEY_FILE_NOT_FOUND_AT_bogus
_443._tcp		IN	TLSA	3 0 1 TLSA_KEY_FILE_NOT_FOUND_AT_bogus
mail._domainkey		IN	TXT	DKIM_KEY_NOT_FOUND_AT_bogus
example.com.		IN	NS	ns1.example.com.
`
	actual := d.ToString("1234567")
	if expected != actual {
		t.Fatal("expected doesn't match actual", actual)
	}
}

func TestWriteDomain(t *testing.T) {
	ipAddress := "123.45.67.89"
	d := &Domain{Name: "example.com", IpAddress: ipAddress, NsRecords: []NsRecord{NsRecord{Name: "ns1"}}}
	d.BuildDnsRecords("bogus", "bogus")

	os.Remove("example.com.txt")
	d.WriteZone("testData") // create file
	d.WriteZone("testData") // no update
}

func TestSignZone(t *testing.T) {
	shell = &MockCommander{}
	d := &Domain{Name: "example.com", IpAddress: "123.45.67.89", NsRecords: []NsRecord{NsRecord{Name: "ns1"}}}
	err := d.SignZone("testData", "testData", "ALG")
	if err != nil {
		t.Error("expected success", err)
	}

	shell = &MockErrCommander{}
	err = d.SignZone("testData", "testData", "ALG")
	if err == nil {
		t.Error("expected failure")
	}
}

func TestGetSerialNumberRevision(t *testing.T) {
	actual := getSerialNumberRevision("2016010100", "2016010100")
	if actual != "2016010101" {
		t.Fatal("expected serial number to increment")
	}
}
