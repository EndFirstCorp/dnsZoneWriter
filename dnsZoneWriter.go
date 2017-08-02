package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/robarchibald/command"
	"github.com/robarchibald/configReader"
)

type dnsZoneWriter struct {
	DbServer                  string
	DbPort                    string
	DbUser                    string
	DbDatabase                string
	DbPassword                string
	NsdDir                    string
	ZoneFileDirectory         string
	ZonePassword              string
	DKIMKeysPath              string
	TLSPublicKeyPath          string
	PostfixVirtualDomainsPath string
	DNSMasterIP               string
	DNSSlaveIPs               string
	IsMaster                  bool
	DNSSecKeyDir              string
	SigningAlgorithm          string
}

func main() {
	w, err := newDNSZoneWriter("dnsZoneWriter.conf", &ipAddressHelper{})
	if err != nil {
		log.Fatal(err)
	}
	db, err := newDb(w.DbServer, w.DbPort, w.DbUser, w.DbPassword, w.DbDatabase)
	if err != nil {
		log.Fatal("Unable to connect to database " + err.Error())
	}
	if err := w.UpdateZoneData(db); err != nil {
		log.Fatal(err)
	}

}

func newDNSZoneWriter(configPath string, addresser ipAddresser) (*dnsZoneWriter, error) {
	w := &dnsZoneWriter{}
	err := configReader.ReadFile(configPath, w)
	if err != nil {
		return nil, err
	}
	ips, err := addresser.GetIPAddresses()
	if err != nil {
		return nil, err
	}
	w.IsMaster = w.CheckIfMaster(ips)
	if _, err := os.Stat(w.ZoneFileDirectory); os.IsNotExist(err) {
		return nil, err
	}
	return w, nil
}

func (w *dnsZoneWriter) CheckIfMaster(ips []string) bool {
	for _, ipAddress := range ips {
		if ipAddress == w.DNSMasterIP {
			return true
		}
	}
	return false
}

func (w *dnsZoneWriter) UpdateZoneData(db dnsBackend) error {
	zones, err := w.GetZones(db)
	if err != nil {
		return errors.New("Unable to get zones from database " + err.Error())
	}
	if err := w.WriteAll(zones); err != nil {
		return (err)
	}
	return nil
}

func (w *dnsZoneWriter) GetZones(db dnsBackend) ([]domain, error) {
	if err := db.CreateSchema(); err != nil {
		return nil, err
	}
	domains, err := db.GetDomains()
	if err != nil {
		return nil, errors.New("Unable to retrieve domains from database " + err.Error())
	}
	domains, err = w.IncludePostfixVirtualDomains(domains)
	if err != nil {
		return nil, errors.New("Unable to merge with virtual domains" + err.Error())
	}

	for i := range domains {
		domains[i].BuildDNSRecords(path.Join(w.DKIMKeysPath, domains[i].Name, "mail.txt"), w.TLSPublicKeyPath)
	}

	return domains, nil
}

func (w *dnsZoneWriter) IncludePostfixVirtualDomains(domains []domain) ([]domain, error) {
	dMap := make(map[string]int)
	for i := range domains {
		dMap[domains[i].Name] = i
	}
	if w.PostfixVirtualDomainsPath == "" {
		return domains, nil
	}
	data, err := ioutil.ReadFile(w.PostfixVirtualDomainsPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, name := range lines {
		name = strings.TrimSpace(name)
		if len(name) == 0 {
			continue
		}
		_, ok := dMap[name]
		if !ok {
			domains = append(domains, domain{Name: name})
		}
	}
	return domains, nil
}

func (w *dnsZoneWriter) WriteAll(zones []domain) error {
	updated, err := w.WriteZones(zones)
	if err != nil {
		return err
	}
	if updated {
		err := w.WriteZoneConfig(zones, w.ZonePassword)
		if err != nil {
			return err
		}
		if w.IsMaster {
			time.Sleep(time.Second) // wait 1 second so config files can finish closing
			return reloadNsdServer()
		}
	}
	return nil
}

func (w *dnsZoneWriter) WriteZones(zones []domain) (bool, error) {
	zonesUpdated := false
	for _, zone := range zones {
		updated, err := zone.WriteZone(w.ZoneFileDirectory)
		if err != nil {
			return false, err
		}
		if updated {
			zonesUpdated = true
			zone.SignZone(w.ZoneFileDirectory, w.DNSSecKeyDir, w.SigningAlgorithm)
		}
	}
	return zonesUpdated, nil
}

func (w *dnsZoneWriter) WriteZoneConfig(zones []domain, password string) error {
	config := fmt.Sprintf("key:\n  name: \"sec_key\"\n  algorithm: hmac-sha256\n  secret: \"%s\"", password)

	for _, zone := range zones {
		config += fmt.Sprintf("\n\nzone:\n  name: %s\n  zonefile: %s\n\n", zone.Name, zone.Name+".txt.signed")
		if w.IsMaster {
			config += fmt.Sprintf("  notify: %s sec_key\n  provide-xfr: %s sec_key", w.DNSSlaveIPs, w.DNSSlaveIPs)
		} else {
			config += fmt.Sprintf("  allow-notify: %s sec_key\n  request-xfr: AXFR %s@53 sec_key", w.DNSMasterIP, w.DNSMasterIP)
		}
	}
	return ioutil.WriteFile(filepath.Join(w.NsdDir, "zones.conf"), []byte(config), 0640)
}

func reloadNsdServer() error {
	output, err := command.Command("/usr/sbin/service", "nsd", "reload").CombinedOutput()
	if err != nil {
		return errors.New("Unable to reload NSD server " + err.Error() + ". " + string(output))
	}
	return nil
}

func getSigningKeyPrefixes(domain string, signingAlgorithm string, keyDir string) (kskPrefix string, zskPrefix string, err error) {
	prefix := filepath.Join(keyDir, domain+"."+signingAlgorithm)
	ksk := prefix + ".KSK"
	zsk := prefix + ".ZSK"
	// (re)create keys if any of the private, ds or key files aren't present
	if !keysExist(ksk) {
		if err := createSigningKeys(keyDir, domain, signingAlgorithm, "KSK"); err != nil {
			return "", "", err
		}
	}

	if !keysExist(zsk) {
		if err := createSigningKeys(keyDir, domain, signingAlgorithm, "ZSK"); err != nil {
			return "", "", err
		}
	}

	return ksk, zsk, nil
}

func keysExist(filePrefix string) bool {
	if _, err := os.Stat(filePrefix + ".private"); os.IsNotExist(err) {
		return false
	} else if _, err := os.Stat(filePrefix + ".ds"); os.IsNotExist(err) {
		return false
	} else if _, err := os.Stat(filePrefix + ".key"); os.IsNotExist(err) {
		return false
	}
	return true
}

func createSigningKeys(keyDir string, domain string, signingAlgorithm string, keyType string) error {
	var cmd command.Cmder
	if keyType == "KSK" {
		cmd = command.Command("/usr/bin/ldns-keygen", "-a", signingAlgorithm, "-b", "2048", "-k", domain)
	} else {
		cmd = command.Command("/usr/bin/ldns-keygen", "-a", signingAlgorithm, "-b", "1024", domain)
	}
	cmd.SetWorkingDir(keyDir)

	output, err := cmd.Output()
	if err != nil {
		return errors.New("Unable to create signing files " + err.Error())
	}
	return renameKeyFiles(keyDir, strings.TrimSpace(string(output)), domain, signingAlgorithm, keyType)
}

func renameKeyFiles(keyDir string, signingPrefix string, domain string, signingAlgorithm string, keyType string) error {
	oldPrefix := filepath.Join(keyDir, signingPrefix)
	newPrefix := filepath.Join(keyDir, domain+"."+signingAlgorithm+"."+keyType)
	if err := os.Rename(oldPrefix+".private", newPrefix+".private"); err != nil {
		return errors.New("Rename failed: " + err.Error())
	}
	if err := os.Rename(oldPrefix+".ds", newPrefix+".ds"); err != nil {
		return errors.New("Rename failed: " + err.Error())
	}
	if err := os.Rename(oldPrefix+".key", newPrefix+".key"); err != nil {
		return errors.New("Rename failed: " + err.Error())
	}
	return nil
}
