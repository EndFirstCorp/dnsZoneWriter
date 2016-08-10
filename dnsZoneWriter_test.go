package main

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestNewDnsZoneWriter(t *testing.T) {
	w, _ := NewDnsZoneWriter("testData/testConfig.conf", NewMockIpAddresser("", nil))
	if w.IsMaster == true || w.DbDatabase != "dnsConfig" {
		t.Error("expected to create from config file")
	}

	_, err := NewDnsZoneWriter("testData/testConfig.conf", NewMockIpAddresser("", errors.New("fail")))
	if err == nil {
		t.Error("expected error due to IP address error")
	}

	w, _ = NewDnsZoneWriter("testData/testConfig.conf", NewMockIpAddresser("10.1.0.6", nil))
	if w.IsMaster != true {
		t.Error("expected to be master since IP address = master")
	}

	_, err = NewDnsZoneWriter("bogus", NewMockIpAddresser("", nil))
	if err == nil {
		t.Error("expected error due to bogus config file")
	}

	_, err = NewDnsZoneWriter("dnsZoneWriter.conf", NewMockIpAddresser("", nil))
	if err == nil {
		t.Error("expected error due to missing zones folder")
	}
}

func TestUpdateZoneDate(t *testing.T) {
	os.Remove("testData/example1.com.txt")
	db := &MockBackend{getDomainsErr: errors.New("fail")}
	w := &DnsZoneWriter{}
	err := w.UpdateZoneData(db)
	if err == nil {
		t.Error("expected error from db fetch")
	}

	db = &MockBackend{domains: []Domain{Domain{Name: "example1.com", NsRecords: []NsRecord{NsRecord{Name: "ns1"}}}}}
	w = &DnsZoneWriter{ZoneFileDirectory: "testData", NsdDir: "testData"}
	err = w.UpdateZoneData(db)
	if err != nil {
		t.Error("expected success", err)
	}
	if _, err := os.Stat("testData/example1.com.txt"); os.IsNotExist(err) {
		t.Error("expected example1.com.txt to be created")
	}

	db = &MockBackend{domains: []Domain{Domain{Name: "&?\\/#@*^%bogus", NsRecords: []NsRecord{NsRecord{Name: "ns1"}}}}}
	err = w.UpdateZoneData(db)
	if err == nil {
		t.Error("expected failure with bogus domain name")
	}
}

func TestGetZones(t *testing.T) {
	// fail creating schema
	db := &MockBackend{createSchemaErr: errors.New("fail")}
	w := &DnsZoneWriter{}
	_, err := w.getZones(db)
	if err == nil {
		t.Error("expected error")
	}

	// fail getting domains
	db = &MockBackend{getDomainsErr: errors.New("fail")}
	_, err = w.getZones(db)
	if err == nil {
		t.Error("expected error")
	}

	// get domains, but fail to build DNS records (no name server)
	db = &MockBackend{domains: []Domain{Domain{Name: "example.com"}}}
	_, err = w.getZones(db)
	if err == nil {
		t.Error("expected error")
	}

	// success
	domains := []Domain{Domain{Name: "example.com", NsRecords: []NsRecord{NsRecord{}}}}
	db = &MockBackend{domains: domains}
	actual, err := w.getZones(db)
	if err != nil || len(actual) != 1 {
		t.Error("expected success", err, actual, domains)
	}
}

func TestWriteAll(t *testing.T) {
	// isMaster=true so restart
	os.Remove("testData/example2.com.txt")
	zones := []Domain{Domain{Name: "example2.com"}}
	w := &DnsZoneWriter{IsMaster: true, ZoneFileDirectory: "testData", NsdDir: "testData"}
	err := w.writeAll(zones)
	if err == nil {
		t.Error("expected failure due to NSD restart")
	}

	// success
	os.Remove("testData/example3.com.txt")
	zones = []Domain{Domain{Name: "example3.com"}}
	w = &DnsZoneWriter{ZoneFileDirectory: "testData", NsdDir: "testData"}
	err = w.writeAll(zones)
	if err != nil {
		t.Error("expected success", err)
	}
	if _, err := os.Stat("testData/example3.com.txt"); os.IsNotExist(err) {
		t.Error("expected example3.com.txt to be created")
	}

	// bad zone name
	zones = []Domain{Domain{Name: "&?\\/#@*^%bogus"}}
	err = w.writeAll(zones)
	if err == nil {
		t.Error("expected error", err)
	}

	// bad zone directory
	os.Remove("testData/example4.com.txt")
	zones = []Domain{Domain{Name: "example4.com"}}
	w = &DnsZoneWriter{NsdDir: "&?\\/#@*^%bogus", ZoneFileDirectory: "testData"}
	err = w.writeAll(zones)
	if err == nil {
		t.Error("expected error", err)
	}
}

func TestRestartNsdServer(t *testing.T) {
	shell = &MockCommander{}
	err := restartNsdServer()
	if err != nil {
		t.Error("expected success")
	}
}

func TestGetSigningKeyPrefixes(t *testing.T) {
	shell = &MockCommander{Return: "keygenOutput"}
	ksk, zsk, err := getSigningKeyPrefixes("example.com", "ALG", "testData")
	if err != nil || !strings.HasSuffix(zsk, "example.com.ALG.ZSK") || !strings.HasSuffix(ksk, "example.com.ALG.KSK") {
		t.Error("expected success", err, ksk, zsk)
	}

	shell = &MockCommander{Return: "keygenOutput"}
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
func NewMockIpAddresser(ipAddress string, err error) *MockIpAddresser {
	return &MockIpAddresser{Addresses: []string{ipAddress}, Err: err}
}

type MockIpAddresser struct {
	IPAddresser
	Addresses []string
	Err       error
}

func (a *MockIpAddresser) GetIPAddresses() ([]string, error) {
	return a.Addresses, a.Err
}

type MockBackend struct {
	domains         []Domain
	getDomainsErr   error
	createSchemaErr error
}

func NewMockBackend(domains []Domain) *MockBackend {
	return &MockBackend{domains: domains}
}

func (b *MockBackend) CreateSchema() error {
	return b.createSchemaErr
}

func (b *MockBackend) GetDomains() ([]Domain, error) {
	return b.domains, b.getDomainsErr
}

type MockCommander struct {
	Return string
}

func (c *MockCommander) Command(name string, arg ...string) Runner {
	return &MockCmdRunner{ByteReturn: []byte(c.Return)}
}

func (c *MockCommander) PipeCommands(r1 Runner, r2 Runner) string {
	return c.Return
}

type MockErrCommander struct {
}

func (c *MockErrCommander) Command(name string, arg ...string) Runner {
	return &MockCmdRunner{ErrReturn: errors.New("fail")}
}

func (c *MockErrCommander) PipeCommands(r1 Runner, r2 Runner) string {
	return ""
}

type MockCmdRunner struct {
	ByteReturn []byte
	ErrReturn  error
}

func (r *MockCmdRunner) CombinedOutput() ([]byte, error) {
	return r.ByteReturn, r.ErrReturn
}

func (r *MockCmdRunner) Output() ([]byte, error) {
	return r.ByteReturn, r.ErrReturn
}

func (r *MockCmdRunner) SetWorkingDir(path string) {
}
