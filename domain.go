package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultTTL time.Duration = 30 * time.Minute
const refresh time.Duration = 2 * time.Hour
const retry time.Duration = 30 * time.Minute
const expire time.Duration = 24 * 7 * 2 * time.Hour // 2 weeks
const negativeTTL time.Duration = 30 * time.Minute
const hostmaster string = "hostmaster"

var nameToIp map[string]string = make(map[string]string)

func (d *Domain) BuildDnsRecords(dkimKeyFilePath string, sslCertificatePath string) error {
	d.DefaultTTL = defaultTTL
	dkimValue := getDkimValue(dkimKeyFilePath)
	tlsaKey := getTlsaKey(sslCertificatePath)

	if len(d.NsRecords) == 0 {
		return errors.New("One or more NS records is required")
	}
	d.add(NewSoaRecord(d.Name, d.NsRecords[0].Name, hostmaster, refresh, retry, expire, negativeTTL))
	d.addDomainRecords("", d.IpAddress, "mx", "quarantine")
	d.add(NewTlsaRecord(25, tlsaKey))
	d.add(NewTlsaRecord(443, tlsaKey))
	d.add(NewDkimRecord("", dkimValue))

	for _, nameServer := range d.NsRecords {
		d.add(NewNsRecord(d.Name, nameServer.Name))
	}
	for _, mailServer := range d.MxRecords {
		d.add(NewMxRecord(d.Name, mailServer.Name, mailServer.Priority))
		// add dkim record if not a fqdn on a different domain
		if !strings.HasSuffix(mailServer.Name, ".") || strings.Contains(mailServer.Name, d.Name+".") {
			d.add(NewDkimRecord(mailServer.Name, dkimValue))
		}
	}
	for _, server := range d.ARecords {
		d.addDomain(server.Name, server.IpAddress, server.DynamicFqdn)
	}
	return nil
}

func (d *Domain) add(record *DnsRecord) {
	d.DnsRecords = append(d.DnsRecords, *record)
}

func (d *Domain) addDomain(name string, ipAddress *string, dynamicFqdn *string) {
	ip := getIp(ipAddress, dynamicFqdn)
	spfAllow := ""
	dmarcPolicy := "reject"
	if isMx(name, d.MxRecords) {
		spfAllow = "ip4:" + ip
		dmarcPolicy = "quarantine"
	}
	d.addDomainRecords(name, ip, spfAllow, dmarcPolicy)
}

func (d *Domain) addDomainRecords(name string, ipAddress string, spfAllow string, dmarcPolicy string) {
	if ipAddress != "" {
		d.add(NewARecord(name, ipAddress))
	}
	d.add(NewSpfRecord(name, spfAllow))
	d.add(NewDmarcRecord(name, dmarcPolicy))
}

func isMx(name string, mailServers []MxRecord) bool {
	for _, mx := range mailServers {
		if mx.Name == name {
			return true
		}
	}
	return false
}

func getIp(ipAddress *string, dynamicFqdn *string) string {
	if ipAddress != nil {
		return *ipAddress
	}

	fqdn := *dynamicFqdn
	savedIp := nameToIp[fqdn]
	if savedIp != "" {
		return savedIp
	}

	resolvedIp, _ := net.LookupIP(fqdn)
	if len(resolvedIp) == 0 {
		return ""
	}
	nameToIp[fqdn] = resolvedIp[0].String()
	return nameToIp[fqdn]
}

func getTlsaKey(filePath string) string {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "TLSA_KEY_FILE_NOT_FOUND_AT_" + filePath
	}
	c1 := shell.Command("openssl", "x509", "-in", filePath, "-outform", "DER")
	c2 := shell.Command("openssl", "dgst", "-sha256")
	return shell.PipeCommands(c1, c2)
}

func getDkimValue(filePath string) string {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "DKIM_KEY_NOT_FOUND_AT_" + filePath
	}
	keyfile := string(data)
	publicKey := keyfile[strings.Index(keyfile, "(") : strings.LastIndex(keyfile, ")")+1]
	return publicKey
}

func (d *Domain) ToString(serialNumber string) string {
	var buffer bytes.Buffer
	buffer.WriteString("\n")
	buffer.WriteString(fmt.Sprintf("$ORIGIN %s.\n", d.Name))
	buffer.WriteString(fmt.Sprintf("$TTL %d\n", int(d.DefaultTTL.Seconds())))
	buffer.WriteString("\n")
	for _, record := range d.DnsRecords {
		buffer.WriteString(record.ToString())
	}
	return strings.Replace(buffer.String(), "SERIALNUMBER", serialNumber, 1)
}

func (d *Domain) WriteZone(folder string) (bool, error) {
	filename := filepath.Join(folder, d.Name+".txt")
	currentZone, currentSerialNumber, err := loadZoneFile(filename)
	if err != nil {
		return false, err
	}

	newSerialNumber := time.Now().Format("2006010200")
	if currentZone == "" || currentZone != d.ToString(currentSerialNumber) {
		newSerialNumber = getSerialNumberRevision(currentSerialNumber, newSerialNumber)

		ioutil.WriteFile(filename, []byte(d.ToString(newSerialNumber)), 644)
		return true, nil
	}
	return false, nil
}

func (d *Domain) SignZone(zoneDir string, keyDir string, signingAlgorithm string) error {
	date := time.Now().Add(time.Hour * 24 * 30).Format("20060102") // add 30 days to current time
	kskFile, zskFile, err := getSigningKeyPrefixes(d.Name, signingAlgorithm, keyDir)
	if err != nil {
		return err
	}
	cmd := shell.Command("/usr/bin/ldns-signzone", "-e", date, "-n", filepath.Join(zoneDir, d.Name+".txt"), kskFile, zskFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New("Error signing zone: " + err.Error() + " " + string(output))
	}
	return nil
}

func loadZoneFile(filename string) (zoneData string, serialNumber string, err error) {
	var fileData []byte
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		fileData, err = ioutil.ReadFile(filename)
		if err != nil {
			return "", "", fmt.Errorf("Error: unable to read %s to compare with new DNS data. %s\n", filename, err.Error())
		}
	}
	zoneData = string(fileData)
	re := regexp.MustCompile(`SOA.*\((\d*)`)
	submatches := re.FindStringSubmatch(zoneData)
	if len(submatches) < 2 {
		return zoneData, "", nil
	}
	return zoneData, submatches[1], nil
}

func getSerialNumberRevision(currentSerialNumber string, newSerialNumber string) string {
	if len(currentSerialNumber) == 10 && currentSerialNumber[0:8] == newSerialNumber[0:8] {
		serialInt, _ := strconv.Atoi(currentSerialNumber)
		serialInt++
		return strconv.Itoa(serialInt)
	}
	return newSerialNumber
}
