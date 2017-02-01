package main

import (
	"errors"
	"github.com/robarchibald/command"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestNewDnsZoneWriter(t *testing.T) {
	w, _ := newDNSZoneWriter("testData/testConfig.conf", newMockIPAddresser("", nil))
	if w.IsMaster == true || w.DbDatabase != "dnsConfig" {
		t.Error("expected to create from config file")
	}

	_, err := newDNSZoneWriter("testData/testConfig.conf", newMockIPAddresser("", errors.New("fail")))
	if err == nil {
		t.Error("expected error due to IP address error")
	}

	w, _ = newDNSZoneWriter("testData/testConfig.conf", newMockIPAddresser("10.1.0.6", nil))
	if w.IsMaster != true {
		t.Error("expected to be master since IP address = master")
	}

	_, err = newDNSZoneWriter("bogus", newMockIPAddresser("", nil))
	if err == nil {
		t.Error("expected error due to bogus config file")
	}

	_, err = newDNSZoneWriter("dnsZoneWriter.conf", newMockIPAddresser("", nil))
	if err == nil {
		t.Error("expected error due to missing zones folder")
	}
}

func TestUpdateZoneDate(t *testing.T) {
	os.Remove("testData/example1.com.txt")
	db := &mockBackend{getDomainsErr: errors.New("fail")}
	w := &dnsZoneWriter{}
	err := w.UpdateZoneData(db)
	if err == nil {
		t.Error("expected error from db fetch")
	}

	db = &mockBackend{domains: []domain{domain{Name: "example1.com", NsRecords: []nsRecord{nsRecord{Name: "ns1"}}}}}
	w = &dnsZoneWriter{ZoneFileDirectory: "testData", NsdDir: "testData"}
	err = w.UpdateZoneData(db)
	if err != nil {
		t.Error("expected success", err)
	}
	if _, err := os.Stat("testData/example1.com.txt"); os.IsNotExist(err) {
		t.Error("expected example1.com.txt to be created")
	}

	db = &mockBackend{domains: []domain{domain{Name: "&?\\/#@*^%bogus", NsRecords: []nsRecord{nsRecord{Name: "ns1"}}}}}
	err = w.UpdateZoneData(db)
	if err == nil {
		t.Error("expected failure with bogus domain name")
	}
}

func TestGetZones(t *testing.T) {
	// fail creating schema
	db := &mockBackend{createSchemaErr: errors.New("fail")}
	w := &dnsZoneWriter{}
	_, err := w.GetZones(db)
	if err == nil {
		t.Error("expected error")
	}

	// fail getting domains
	db = &mockBackend{getDomainsErr: errors.New("fail")}
	_, err = w.GetZones(db)
	if err == nil {
		t.Error("expected error")
	}

	// get domains, but fail to build DNS records (no name server)
	db = &mockBackend{domains: []domain{domain{Name: "example.com"}}}
	_, err = w.GetZones(db)
	if err == nil {
		t.Error("expected error")
	}

	// success
	domains := []domain{domain{Name: "example.com", NsRecords: []nsRecord{nsRecord{}}}}
	db = &mockBackend{domains: domains}
	actual, err := w.GetZones(db)
	if err != nil || len(actual) != 1 || len(actual[0].DNSRecords) == 0 {
		t.Error("expected success", err, actual, domains)
	}
}

func TestWriteAll(t *testing.T) {
	// isMaster=true so restart
	os.Remove("testData/example2.com.txt")
	zones := []domain{domain{Name: "example2.com"}}
	w := &dnsZoneWriter{IsMaster: true, ZoneFileDirectory: "testData", NsdDir: "testData"}
	err := w.WriteAll(zones)
	if err == nil {
		t.Error("expected failure due to NSD restart")
	}

	// success
	os.Remove("testData/example3.com.txt")
	zones = []domain{domain{Name: "example3.com"}}
	w = &dnsZoneWriter{ZoneFileDirectory: "testData", NsdDir: "testData"}
	err = w.WriteAll(zones)
	if err != nil {
		t.Error("expected success", err)
	}
	if _, err := os.Stat("testData/example3.com.txt"); os.IsNotExist(err) {
		t.Error("expected example3.com.txt to be created")
	}

	// bad zone name
	zones = []domain{domain{Name: "&?\\/#@*^%bogus"}}
	err = w.WriteAll(zones)
	if err == nil {
		t.Error("expected error", err)
	}

	// bad zone directory
	os.Remove("testData/example4.com.txt")
	zones = []domain{domain{Name: "example4.com"}}
	w = &dnsZoneWriter{NsdDir: "&?\\/#@*^%bogus", ZoneFileDirectory: "testData"}
	err = w.WriteAll(zones)
	if err == nil {
		t.Error("expected error", err)
	}
}

func TestReloadNsdServer(t *testing.T) {
	command.SetMock(&command.MockShellCmd{})
	err := reloadNsdServer()
	if err != nil {
		t.Error("expected success")
	}
}

func TestGetSigningKeyPrefixes(t *testing.T) {
	command.SetMock(&command.MockShellCmd{OutputVal: []byte("keygenOutput")})
	ksk, zsk, err := getSigningKeyPrefixes("example.com", "ALG", "testData")
	if err != nil || !strings.HasSuffix(zsk, "example.com.ALG.ZSK") || !strings.HasSuffix(ksk, "example.com.ALG.KSK") {
		t.Error("expected success", err, ksk, zsk)
	}

	ksk, zsk, err = getSigningKeyPrefixes("example1.com", "ALG", "testData")
	if err == nil {
		t.Error("expected failure on create of ZSK files")
	}

	_, _, err = getSigningKeyPrefixes("example.com", "RSA", ".")
	if err == nil {
		t.Error("expected failure")
	}
}

func TestKeysExist(t *testing.T) {
	if !keysExist("testData/example1.com.ALG.KSK") {
		t.Error("expected to report found")
	}

	if keysExist("testData/example2.com.ALG.KSK") {
		t.Error("expected to report missing")
	}

	if keysExist("testData/example3.com.ALG.KSK") {
		t.Error("expected to report missing")
	}
}

func TestRenameKeyFiles(t *testing.T) {
	ioutil.WriteFile("testData/generated12345.ds", []byte{}, 644)
	ioutil.WriteFile("testData/generated12345.key", []byte{}, 644)
	ioutil.WriteFile("testData/generated12345.private", []byte{}, 644)
	os.Remove("testData/example4.com.ALG.KSK.ds")
	os.Remove("testData/example4.com.ALG.KSK.key")
	os.Remove("testData/example4.com.ALG.KSK.private")
	err := renameKeyFiles("testData", "generated12345", "example4.com", "ALG", "KSK")
	if err != nil {
		t.Error("expected success", err)
	}

	err = renameKeyFiles("testData", "example3.com.ALG.KSK", "example3.com", "ALG", "KSK")
	if err == nil {
		t.Error("expected error due to example3.com.ALG.KSK.ds being missing")
	}

	err = renameKeyFiles("testData", "example2.com.ALG.KSK", "example2.com", "ALG", "KSK")
	if err == nil {
		t.Error("expected error due to example2.com.ALG.KSK.key being missing")
	}
}

/********************** MOCKS ***********************/
func newMockIPAddresser(ipAddress string, err error) *mockIPAddresser {
	return &mockIPAddresser{Addresses: []string{ipAddress}, Err: err}
}

type mockIPAddresser struct {
	ipAddresser
	Addresses []string
	Err       error
}

func (a *mockIPAddresser) GetIPAddresses() ([]string, error) {
	return a.Addresses, a.Err
}

type mockBackend struct {
	domains         []domain
	getDomainsErr   error
	createSchemaErr error
}

func newMockBackend(domains []domain) *mockBackend {
	return &mockBackend{domains: domains}
}

func (b *mockBackend) CreateSchema() error {
	return b.createSchemaErr
}

func (b *mockBackend) GetDomains() ([]domain, error) {
	return b.domains, b.getDomainsErr
}
