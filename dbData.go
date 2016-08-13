package main

import (
	"io/ioutil"
	"strconv"
	"time"

	"github.com/robarchibald/onedb"
)

type aRecord struct {
	DomainID    int16
	Name        string
	IPAddress   *string // nullable string
	DynamicFQDN *string // nullable string
}

type mxRecord struct {
	DomainID int16
	Name     string
	Priority int16
}

type nsRecord struct {
	DomainID  int16
	Name      string
	SortOrder int16
}

type domain struct {
	ID         int16
	Name       string
	DefaultTTL time.Duration
	IPAddress  string
	ARecords   []aRecord
	MxRecords  []mxRecord
	NsRecords  []nsRecord
	DNSRecords []dnsRecord
}

type dnsBackend interface {
	CreateSchema() error
	GetDomains() ([]domain, error)
}

type db struct {
	Db onedb.DBer
}

func newDb(host string, dbPort string, user string, password string, database string) (*db, error) {
	port, err := strconv.Atoi(dbPort)
	if err != nil {
		return nil, err
	}

	conn, err := onedb.NewPgx(host, uint16(port), user, password, database)
	if err != nil {
		return nil, err
	}

	return &db{conn}, nil
}

type code struct {
	Code int
}

func (d *db) CreateSchema() error {
	data := code{}
	err := d.Db.QueryStructRow("Select 1 as Code from information_schema.tables where table_schema = 'public' and table_name = 'domains'", &data)
	if err != nil && err.Error() != "no rows in result set" {
		return err
	}

	// schema already exists... exit
	if data.Code == 1 {
		return nil
	}

	schema, err := ioutil.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	err = d.Db.Execute(string(schema))
	return err
}

func (d *db) GetDomains() ([]domain, error) {
	domains := []domain{}
	aRecords, err := d.getARecords()
	if err != nil {
		return domains, err
	}
	mxRecords, err := d.getMxRecords()
	if err != nil {
		return domains, err
	}
	nsRecords, err := d.getNsRecords()
	if err != nil {
		return domains, err
	}

	err = d.Db.QueryStruct("select Id, Name, IpAddress from Domains", &domains)
	if err != nil {
		return domains, err
	}

	for i := range domains {
		for _, nsRecord := range nsRecords {
			if nsRecord.DomainID == domains[i].ID {
				domains[i].NsRecords = append(domains[i].NsRecords, nsRecord)
			}
		}
		for _, mxRecord := range mxRecords {
			if mxRecord.DomainID == domains[i].ID {
				domains[i].MxRecords = append(domains[i].MxRecords, mxRecord)
			}
		}
		for _, aRecord := range aRecords {
			if aRecord.DomainID == domains[i].ID {
				domains[i].ARecords = append(domains[i].ARecords, aRecord)
			}
		}
	}
	return domains, nil
}

func (d *db) getARecords() ([]aRecord, error) {
	aRecords := []aRecord{}
	return aRecords, d.Db.QueryStruct("select DomainId, Name, IpAddress, DynamicFqdn from ARecords", &aRecords)
}

func (d *db) getMxRecords() ([]mxRecord, error) {
	mxRecords := []mxRecord{}
	return mxRecords, d.Db.QueryStruct("select DomainId, Name, Priority from MxRecords", &mxRecords)
}

func (d *db) getNsRecords() ([]nsRecord, error) {
	nsRecords := []nsRecord{}
	return nsRecords, d.Db.QueryStruct("select DomainId, Name, SortOrder from NsRecords", &nsRecords)
}
