package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/robarchibald/command"
	"io"
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

var nameToIP = make(map[string]string)

type domain struct {
	ID           int16
	Name         string
	DefaultTTL   time.Duration
	DNSRecords   []dnsRecord
	ARecords     []aRecord
	CNameRecords []cnameRecord
	DKIMRecords  []dkimRecord
	DMARCRecords []dmarcRecord
	MxRecords    []mxRecord
	NsRecords    []nsRecord
	SPFRecords   []spfRecord
	SRVRecords   []srvRecord
	TXTRecords   []txtRecord
	hasDMARC     map[string]bool
	hasSPF       map[string]bool
}

func (d *domain) BuildDNSRecords(dkimKeyFilePath string, sslCertificatePath string) error {
	d.hasDMARC = make(map[string]bool)
	d.hasSPF = make(map[string]bool)
	d.DefaultTTL = defaultTTL
	dkimValue := getDkimValue(dkimKeyFilePath)
	tlsaKey := getTlsaKey(sslCertificatePath)

	d.getDefaults()
	d.Add(newSoaRecord(d.Name, d.NsRecords[0].Value, hostmaster, refresh, retry, expire, negativeTTL))
	d.Add(newTlsaRecord(25, tlsaKey))
	d.Add(newTlsaRecord(443, tlsaKey))
	d.Add(newDkimRecord("", dkimValue))

	for _, nameServer := range d.NsRecords {
		d.Add(newNsRecord(d.Name, nameServer.Name, nameServer.Value))
	}
	for _, mailServer := range d.MxRecords {
		d.Add(newMxRecord(d.Name, mailServer.Name, mailServer.Value, mailServer.Priority))
	}
	for _, spf := range d.SPFRecords {
		d.AddSPFRecord(spf.Name, spf.Value)
	}
	for _, dkim := range d.DKIMRecords {
		d.Add(newDkimRecord(dkim.Name, dkimValue))
	}
	for _, dmarc := range d.DMARCRecords {
		d.AddDMARCRecord(dmarc.Name, dmarc.Value)
	}

	for _, server := range d.ARecords {
		name := server.Name
		if server.Name == "" {
			name = d.Name + "."
		}
		d.AddARecord(name, server.IPAddress, server.DynamicFQDN)
		d.AddDMARCRecord(name, "reject") // reject if not specified earlier
		d.AddSPFRecord(name, "")         // reject all mail
	}
	for _, cname := range d.CNameRecords {
		d.Add(newCNameRecord(cname.Name, cname.CanonicalName))
	}
	return nil
}

func (d *domain) getDefaults() {
	if len(d.NsRecords) == 0 {
		d.NsRecords = getDefaultNs()
	}
	if len(d.MxRecords) == 0 {
		d.MxRecords = getDefaultMx()
	}
	if len(d.SPFRecords) == 0 {
		d.SPFRecords = getDefaultSPF(d.Name)
	}
	if len(d.DMARCRecords) == 0 {
		d.DMARCRecords = getDefaultDMARC(d.Name)
	}
}

func getDefaultMx() []mxRecord {
	return []mxRecord{mxRecord{Name: "", Value: "mail1.endfirst.com.", Priority: 10}, mxRecord{Name: "", Value: "mail2.endfirst.com.", Priority: 20}}
}

func getDefaultNs() []nsRecord {
	return []nsRecord{nsRecord{Name: "", Value: "ns1.endfirst.com.", SortOrder: 1}, nsRecord{Name: "", Value: "ns2.endfirst.com.", SortOrder: 1}}
}

func getDefaultSPF(domain string) []spfRecord {
	return []spfRecord{spfRecord{Name: domain + ".", Value: "include:_spf.endfirst.com"}}
}

func getDefaultDMARC(domain string) []dmarcRecord {
	return []dmarcRecord{dmarcRecord{Name: domain + ".", Value: "quarantine"}}
}

func (d *domain) Add(record *dnsRecord) {
	d.DNSRecords = append(d.DNSRecords, *record)
}

func (d *domain) AddARecord(name, ipAddress, dynamicFqdn string) {
	ip := getIP(ipAddress, dynamicFqdn)
	if ip != "" {
		d.Add(newARecord(name, ip))
	}
}

func (d *domain) AddSPFRecord(name, allow string) {
	if !d.hasSPF[name] {
		d.Add(newSpfRecord(name, allow))
		d.hasSPF[name] = true
	}
}

func (d *domain) AddDMARCRecord(name, policy string) {
	if !d.hasDMARC[name] {
		d.Add(newDmarcRecord(name, policy))
		d.hasDMARC[name] = true
	}
}

func getIP(ipAddress, dynamicFqdn string) string {
	if ipAddress != "" {
		return ipAddress
	}

	savedIP := nameToIP[dynamicFqdn]
	if savedIP != "" {
		return savedIP
	}

	resolvedIP, _ := net.LookupIP(dynamicFqdn)
	if len(resolvedIP) == 0 {
		return ""
	}
	nameToIP[dynamicFqdn] = resolvedIP[0].String()
	return nameToIP[dynamicFqdn]
}

func getTlsaKey(filePath string) string {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "TLSA_KEY_FILE_NOT_FOUND_AT_" + filePath
	}
	c1 := command.Command("openssl", "x509", "-in", filePath, "-outform", "DER")
	c2 := command.Command("openssl", "dgst", "-sha256")
	return command.PipeCommands(c1, c2)
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

func (d *domain) String(serialNumber string) string {
	var buffer bytes.Buffer
	buffer.WriteString("\n")
	buffer.WriteString(fmt.Sprintf("$ORIGIN %s.\n", d.Name))
	buffer.WriteString(fmt.Sprintf("$TTL %d\n", int(d.DefaultTTL.Seconds())))
	buffer.WriteString("\n")
	for _, record := range d.DNSRecords {
		buffer.WriteString(record.toString())
	}
	return strings.Replace(buffer.String(), "SERIALNUMBER", serialNumber, 1)
}

func (d *domain) WriteZone(folder string) (bool, error) {
	filename := filepath.Join(folder, d.Name+".txt")
	currentZone, currentSerialNumber := getFileMatch(filename, `SOA.*\((\d*)`)

	_, expiration := getFileMatch(filename+".signed", `\sRRSIG\s+SOA\s+\d+\s+\d+\s\d+\s+(\d{14})`)
	expireDate, err := time.Parse("20060102000000", expiration)
	if err != nil {
		expireDate = time.Now()
	}

	newSerialNumber := time.Now().Format("2006010200")
	if currentZone == "" || currentZone != d.String(currentSerialNumber) || expireDate.AddDate(0, 0, -3).Before(time.Now()) {
		newSerialNumber = getSerialNumberRevision(currentSerialNumber, newSerialNumber)

		err := ioutil.WriteFile(filename, []byte(d.String(newSerialNumber)), 644)
		if err != nil {
			return false, err
		}
		fmt.Println("Updated: " + filename)
		copyFileContents(filename, fmt.Sprintf("%s_%s", filename, time.Now().Format("20060102-150405")))
		cleanup(filename+"_*", 336) // 2 weeks
		return true, nil
	}
	return false, nil
}

func cleanup(searchglob string, hoursToKeep int) {
	matches, _ := filepath.Glob(searchglob)
	now := time.Now()
	for _, file := range matches {
		info, err := os.Stat(file)
		if err == nil && now.Sub(info.ModTime()) > time.Hour*time.Duration(hoursToKeep) {
			os.Remove(file)
		}
	}
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	io.Copy(out, in)
	err = out.Sync()
	return err
}

func (d *domain) SignZone(zoneDir string, keyDir string, signingAlgorithm string) error {
	date := time.Now().Add(time.Hour * 24 * 30).Format("20060102") // add 30 days to current time
	kskFile, zskFile, err := getSigningKeyPrefixes(d.Name, signingAlgorithm, keyDir)
	if err != nil {
		return err
	}
	cmd := command.Command("/usr/bin/ldns-signzone", "-e", date, "-n", filepath.Join(zoneDir, d.Name+".txt"), kskFile, zskFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New("Error signing zone: " + err.Error() + " " + string(output))
	}
	return nil
}

func getFileMatch(filename string, regex string) (fileText string, match string) {
	var fileData []byte
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", ""
	}
	fileText = string(fileData)
	re := regexp.MustCompile(regex)
	submatches := re.FindStringSubmatch(fileText)
	if len(submatches) < 2 {
		return "", ""
	}
	return fileText, submatches[1]
}

func getSerialNumberRevision(currentSerialNumber string, newSerialNumber string) string {
	if len(currentSerialNumber) == 10 && currentSerialNumber[0:8] == newSerialNumber[0:8] {
		serialInt, _ := strconv.Atoi(currentSerialNumber)
		serialInt++
		return strconv.Itoa(serialInt)
	}
	return newSerialNumber
}
