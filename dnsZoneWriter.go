package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/robarchibald/configReader"
)

type DnsZoneWriter struct {
	DbServer          string
	DbPort            string
	DbUser            string
	DbDatabase        string
	DbPassword        string
	NsdDir            string
	ZoneFileDirectory string
	ZonePassword      string
	DkimKeyFilePath   string
	TlsPublicKeyPath  string
	DnsMasterIp       string
	DnsSlaveIps       string
	IsMaster          bool
	DnssecKeyDir      string
	SigningAlgorithm  string
}

var shell Commander = &CommandHelper{}

func main() {
	w, err := NewDnsZoneWriter("dnsZoneWriter.conf", &IPAddressHelper{})
	if err != nil {
		log.Fatal(err)
	}
	db, err := NewDb(w.DbServer, w.DbPort, w.DbUser, w.DbPassword, w.DbDatabase)
	if err != nil {
		log.Fatal("Unable to connect to database " + err.Error())
	}
	if err := w.UpdateZoneData(db); err != nil {
		log.Fatal(err)
	}

}

func NewDnsZoneWriter(configPath string, addresser IPAddresser) (*DnsZoneWriter, error) {
	w := &DnsZoneWriter{}
	err := configReader.ReadFile(configPath, w)
	if err != nil {
		return nil, err
	}
	ips, err := addresser.GetIPAddresses()
	if err != nil {
		return nil, err
	}
	w.IsMaster = w.checkIfMaster(ips)
	if _, err := os.Stat(w.ZoneFileDirectory); os.IsNotExist(err) {
		return nil, err
	}
	return w, nil
}

func (w *DnsZoneWriter) checkIfMaster(ips []string) bool {
	for _, ipAddress := range ips {
		if ipAddress == w.DnsMasterIp {
			return true
		}
	}
	return false
}

func (w *DnsZoneWriter) UpdateZoneData(db DnsBackend) error {
	zones, err := w.getZones(db)
	if err != nil {
		return errors.New("Unable to get zones from database " + err.Error())
	}
	if err := w.writeAll(zones); err != nil {
		return (err)
	}
	return nil
}

func (w *DnsZoneWriter) getZones(db DnsBackend) ([]Domain, error) {
	if err := db.CreateSchema(); err != nil {
		return nil, err
	}
	domains, err := db.GetDomains()
	if err != nil {
		return nil, errors.New("Unable to retrieve domains from database " + err.Error())
	}

	for _, domain := range domains {
		if err := domain.BuildDnsRecords(w.DkimKeyFilePath, w.TlsPublicKeyPath); err != nil {
			return nil, err
		}
	}

	return domains, nil
}

func (w *DnsZoneWriter) writeAll(zones []Domain) error {
	updated, err := w.writeZones(zones)
	if err != nil {
		return err
	}
	if updated {
		err := w.writeZoneConfig(zones, w.ZonePassword)
		if err != nil {
			return err
		}
		if w.IsMaster {
			return restartNsdServer()
		}
	}
	return nil
}

func (w *DnsZoneWriter) writeZones(zones []Domain) (bool, error) {
	zonesUpdated := false
	for _, zone := range zones {
		updated, err := zone.WriteZone(w.ZoneFileDirectory)
		if err != nil {
			return false, err
		}
		if updated {
			zonesUpdated = true
			zone.SignZone(w.ZoneFileDirectory, w.DnssecKeyDir, w.SigningAlgorithm)
		}
	}
	return zonesUpdated, nil
}

func (w *DnsZoneWriter) writeZoneConfig(zones []Domain, password string) error {
	config := fmt.Sprintf(`key:\n  name: "sec_key"\n  algorithm: hmac-sha256\n  secret: "%s"`, password)

	for _, zone := range zones {
		config += fmt.Sprintf("\n\nzone:\n  name: %s\n  zonefile: %s\n\n", zone.Name, zone.Name+".txt.signed")
		if w.IsMaster {
			config += fmt.Sprintf("  notify: %s sec_key\n  provide-xfr: %s sec_key", w.DnsSlaveIps, w.DnsSlaveIps)
		} else {
			config += fmt.Sprintf("  allow-notify: %s sec_key\n  request-xfr: AXFR %s@53 sec_key", w.DnsMasterIp, w.DnsMasterIp)
		}
	}
	return ioutil.WriteFile(filepath.Join(w.NsdDir, "zones.conf"), []byte(config), 640)
}

func restartNsdServer() error {
	output, err := shell.Command("/usr/sbin/service", "nsd", "restart").CombinedOutput()
	if err != nil {
		return errors.New("Unable to restart NSD server " + err.Error() + ". " + string(output))
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
	var cmd Runner
	if keyType == "KSK" {
		cmd = shell.Command("/usr/bin/ldns-keygen", "-a", signingAlgorithm, "-b", "2048", "-k", domain)
	} else {
		cmd = shell.Command("/usr/bin/ldns-keygen", "-a", signingAlgorithm, "-b", "1024", domain)
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
