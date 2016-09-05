package main

import (
	"os"
	"testing"
)

func TestBuildDnsRecords(t *testing.T) {
	ipAddress := "123.45.67.89"
	d := &domain{Name: "example.com",
		NsRecords:    []nsRecord{nsRecord{Name: "ns1"}},
		MxRecords:    []mxRecord{mxRecord{Name: "mail1", Priority: 10}},
		ARecords:     []aRecord{aRecord{Name: "", IPAddress: &ipAddress}, aRecord{Name: "server", IPAddress: &ipAddress}},
		CNameRecords: []cnameRecord{cnameRecord{Name: "cname", CanonicalName: "cname.example.com"}}}
	d.BuildDNSRecords("mail.txt", "ssl_certificate.pem")
	if len(d.DNSRecords) != 14 || d.DNSRecords[0].RecordType != "SOA" || d.DNSRecords[1].RecordType != "TLSA" || d.DNSRecords[2].RecordType != "TLSA" || d.DNSRecords[3].Name != "mail._domainkey" || d.DNSRecords[4].RecordType != "NS" || d.DNSRecords[5].RecordType != "MX" ||
		d.DNSRecords[6].Name != "mail._domainkey.mail1" || d.DNSRecords[7].RecordType != "A" || d.DNSRecords[8].Data != "\"v=spf1 mx -all\"" || d.DNSRecords[9].Data != "\"v=DMARC1; p=quarantine\"" ||
		d.DNSRecords[10].RecordType != "A" || d.DNSRecords[11].Data != "\"v=spf1  -all\"" || d.DNSRecords[12].Data != "\"v=DMARC1; p=reject\"" || d.DNSRecords[13].Data != "cname.example.com" {
		t.Fatalf("expected 14 dns records with specific values: %s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", d.DNSRecords[0], d.DNSRecords[1], d.DNSRecords[2], d.DNSRecords[3], d.DNSRecords[4], d.DNSRecords[5], d.DNSRecords[6], d.DNSRecords[7], d.DNSRecords[8], d.DNSRecords[9], d.DNSRecords[10], d.DNSRecords[11], d.DNSRecords[12], d.DNSRecords[13])
	}
}

func TestAdd(t *testing.T) {
	d := &domain{}
	record := newARecord("name", "ip")
	d.Add(record)
	if d.DNSRecords[0] != *record {
		t.Fatal("expected to have added Dns record", d.DNSRecords[0])
	}
}

func TestAddDomain(t *testing.T) {
	d := &domain{}
	ipAddress := "50.43.43.48"
	d.AddDomain("name", &ipAddress, nil)
	if len(d.DNSRecords) != 3 || d.DNSRecords[0].RecordType != "A" ||
		d.DNSRecords[1].Data != "\"v=spf1  -all\"" || d.DNSRecords[2].Data != "\"v=DMARC1; p=reject\"" {
		t.Fatal("expected to have added A record, SPF record and DMARC record", d.DNSRecords)
	}
}

func TestAddDomainDynamicMx(t *testing.T) {
	d := &domain{MxRecords: []mxRecord{mxRecord{1, "name", 5}}}
	fqdn := "google-public-dns-a.google.com"
	d.AddDomain("name", nil, &fqdn)
	if len(d.DNSRecords) != 3 || d.DNSRecords[0].RecordType != "A" ||
		d.DNSRecords[1].Data != "\"v=spf1 ip4:8.8.8.8 -all\"" || d.DNSRecords[2].Data != "\"v=DMARC1; p=quarantine\"" {
		t.Fatal("expected to have added A record, SPF record and DMARC record", d.DNSRecords)
	}
}

func TestGetIp(t *testing.T) {
	bogus := "bogus.domain"
	fqdn := "google-public-dns-a.google.com"
	nameToIP["google-public-dns-a.google.com"] = "" // ensure not filled yet
	ipResolve := getIP(nil, &fqdn)                  // should do a name resolution this time
	ipMap := getIP(nil, &fqdn)                      // should pull from map this time
	if ipResolve != "8.8.8.8" || ipMap != "8.8.8.8" || nameToIP["google-public-dns-a.google.com"] != "8.8.8.8" {
		t.Error("expected IP address to equal 8.8.8.8.  Has DNS changed?", ipResolve, ipMap)
	}
	if getIP(nil, &bogus) != "" {
		t.Error("expected no IP address returned for bogus address")
	}
}

func TestGetIpBogusName(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	fqdn := "12345"
	ip := getIP(nil, &fqdn)
	if ip != "" {
		t.Fatal("expected empty ip", ip)
	}
}

func TestGetTlsaKey(t *testing.T) {
	shell = &commandHelper{}
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
	d := &domain{Name: "example.com", ARecords: []aRecord{aRecord{Name: "", IPAddress: &ipAddress}}, NsRecords: []nsRecord{nsRecord{Name: "ns1"}}}
	d.BuildDNSRecords("bogus", "bogus")
	expected := `
$ORIGIN example.com.
$TTL 1800

example.com.		IN	SOA	ns1.example.com. hostmaster.example.com. (1234567 7200 1800 1209600 1800)
_25._tcp		IN	TLSA	3 0 1 TLSA_KEY_FILE_NOT_FOUND_AT_bogus
_443._tcp		IN	TLSA	3 0 1 TLSA_KEY_FILE_NOT_FOUND_AT_bogus
mail._domainkey		IN	TXT	DKIM_KEY_NOT_FOUND_AT_bogus
example.com.		IN	NS	ns1.example.com.
example.com.		IN	A	123.45.67.89
example.com.		IN	TXT	"v=spf1 mx -all"
_dmarc.example.com.		IN	TXT	"v=DMARC1; p=quarantine"
`
	actual := d.String("1234567")
	if expected != actual {
		t.Fatal("expected doesn't match actual", actual)
	}
}

func TestWriteDomain(t *testing.T) {
	ipAddress := "123.45.67.89"
	d := &domain{Name: "example.com", ARecords: []aRecord{aRecord{Name: "", IPAddress: &ipAddress}}, NsRecords: []nsRecord{nsRecord{Name: "ns1"}}}
	d.BuildDNSRecords("bogus", "bogus")

	os.Remove("example.com.txt")
	d.WriteZone("testData") // create file
	d.WriteZone("testData") // no update
}

func TestSignZone(t *testing.T) {
	shell = &mockCommander{}
	d := &domain{Name: "example.com", NsRecords: []nsRecord{nsRecord{Name: "ns1"}}}
	err := d.SignZone("testData", "testData", "ALG")
	if err != nil {
		t.Error("expected success", err)
	}

	shell = &mockErrCommander{}
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
