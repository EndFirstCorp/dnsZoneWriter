package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/robarchibald/command"
)

func TestBuildDnsRecords(t *testing.T) {
	ipAddress := "123.45.67.89"
	d := &domain{Name: "example.com",
		NsRecords:    []nsRecord{nsRecord{Name: "ns1"}},
		MxRecords:    []mxRecord{mxRecord{Name: "mail1", Priority: 10}},
		ARecords:     []aRecord{aRecord{Name: "", IPAddress: ipAddress}, aRecord{Name: "server", IPAddress: ipAddress}},
		CNameRecords: []cnameRecord{cnameRecord{Name: "cname", CanonicalName: "cname.example.com"}}}
	d.BuildDNSRecords("mail.txt", "ssl_certificate.pem")
	if len(d.DNSRecords) != 13 || d.DNSRecords[0].RecordType != "SOA" || d.DNSRecords[1].RecordType != "TLSA" || d.DNSRecords[2].RecordType != "TLSA" ||
		d.DNSRecords[3].Name != "mail._domainkey" || d.DNSRecords[4].RecordType != "NS" || d.DNSRecords[5].RecordType != "MX" ||
		d.DNSRecords[6].Data != "\"v=spf1 include:_spf.endfirst.com -all\"" || d.DNSRecords[7].Name != "_dmarc.example.com." ||
		d.DNSRecords[8].RecordType != "A" || d.DNSRecords[9].RecordType != "A" ||
		d.DNSRecords[10].Name != "_dmarc.server" || d.DNSRecords[11].Data != "\"v=spf1  -all\"" || d.DNSRecords[12].RecordType != "CNAME" {
		for _, record := range d.DNSRecords {
			t.Log(record.RecordType, record.Name, record.Data)
		}
		t.Fatalf("expected 13 dns records with specific values. Actually have %d", len(d.DNSRecords))
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

func TestGetIp(t *testing.T) {
	bogus := "bogus.domain"
	fqdn := "google-public-dns-a.google.com"
	nameToIP["google-public-dns-a.google.com"] = "" // ensure not filled yet
	ipResolve := getIP("", fqdn)                    // should do a name resolution this time
	ipMap := getIP("", fqdn)                        // should pull from map this time
	if ipResolve != "8.8.8.8" || ipMap != "8.8.8.8" || nameToIP["google-public-dns-a.google.com"] != "8.8.8.8" {
		t.Error("expected IP address to equal 8.8.8.8.  Has DNS changed?", ipResolve, ipMap)
	}
	if getIP("", bogus) != "" {
		t.Error("expected no IP address returned for bogus address")
	}
}

func TestGetIpBogusName(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	ip := getIP("", "12345")
	if ip != "" {
		t.Fatal("expected empty ip", ip)
	}
}

func TestGetTlsaKey(t *testing.T) {
	command.SetExec()
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
	value := getDkimValue("testData/example1.com/mail.txt")
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
	d := &domain{Name: "example.com", ARecords: []aRecord{aRecord{Name: "", IPAddress: "123.45.67.89"}}, NsRecords: []nsRecord{nsRecord{Name: "", Value: "ns1"}}}
	d.BuildDNSRecords("bogus", "bogus")
	expected := `
$ORIGIN example.com.
$TTL 1800

example.com.		IN	SOA	ns1.example.com. hostmaster.example.com. (1234567 7200 1800 1209600 1800)
_25._tcp		IN	TLSA	3 0 1 TLSA_KEY_FILE_NOT_FOUND_AT_bogus
_443._tcp		IN	TLSA	3 0 1 TLSA_KEY_FILE_NOT_FOUND_AT_bogus
mail._domainkey		IN	TXT	"DKIM_KEY_NOT_FOUND_AT_bogus"
example.com.		IN	NS	ns1.example.com.
example.com.		IN	MX	10 mail1.endfirst.com.
example.com.		IN	MX	20 mail2.endfirst.com.
example.com.		IN	TXT	"v=spf1 include:_spf.endfirst.com -all"
_dmarc.example.com.		IN	TXT	"v=DMARC1; p=quarantine; rua=mailto:dmarc-report@endfirst.com"
example.com.		IN	A	123.45.67.89
`
	actual := d.String("1234567")
	if expected != actual {
		t.Fatal("expected doesn't match actual", actual)
	}
}

func TestWriteZone(t *testing.T) {
	d := &domain{Name: "example.com", ARecords: []aRecord{aRecord{Name: "", IPAddress: "123.45.67.89"}}, NsRecords: []nsRecord{nsRecord{Value: "ns1"}}}
	d.BuildDNSRecords("bogus", "bogus")

	clean("testData/example.com.txt*")
	os.Remove("testData/example.com.txt.signed")

	d.WriteZone("testData") // create file. not signed
	_, sn := getFileMatch("testData/example.com.txt", `SOA.*\((\d*)`)
	if sn != time.Now().Format("2006010200") {
		t.Error("expected serial number expiration date to match current time", sn, time.Now().Format("2006010200"))
	}

	writeSigned("example.com", time.Now().AddDate(0, 1, 0).Format("20060102000000"))
	d.WriteZone("testData") // no update
	_, sn1 := getFileMatch("testData/example.com.txt", `SOA.*\((\d*)`)
	if sn != sn1 {
		t.Error("expected serial number to stay the same")
	}

	writeSigned("example.com", time.Now().AddDate(0, 0, 1).Format("20060102000000"))
	d.WriteZone("testData") // signature is old, so write
	_, sn2 := getFileMatch("testData/example.com.txt", `SOA.*\((\d*)`)
	if sn2 != getSerialNumberRevision(sn1, sn1) {
		t.Error("expected new revision to be created due to expiration")
	}
}

func TestSignZone(t *testing.T) {
	command.SetMock(&command.MockShellCmd{})
	d := &domain{Name: "example.com", NsRecords: []nsRecord{nsRecord{Name: "ns1"}}}
	err := d.SignZone("testData", "testData", "ALG")
	if err != nil {
		t.Error("expected success", err)
	}

	command.SetMock(&command.MockShellCmd{CombinedOutputErr: fmt.Errorf("fail")})
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

func writeSigned(domain string, expiration string) {
	data := `example.com. 1800  IN  RRSIG SOA 8 2 1800 ` + expiration + ` 20160921090003 27633 example.com. xjGi+bWLxqHthk3cNVy7jA8XXFA5V7l8FWhGsTLdOC+h3vWazbyDzFdMEuS2OIghZHOcKDCQQ2rnlKFFZn8lHtktQhG0V4u9nji8s4BjqTlqe+DcRxeWTckSOazn2twVgOhGbD/eqlY4xDn8k5GZJd2KkaW+XeXQdRDERukv`
	ioutil.WriteFile("testData/"+domain+".txt.signed", []byte(data), 644)
}
