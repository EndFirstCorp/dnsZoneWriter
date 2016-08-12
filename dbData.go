package main

import (
	"io/ioutil"
	"strconv"
	"time"

	"github.com/robarchibald/onedb"
)

type ARecord struct {
	DomainId    int16
	Name        string
	IpAddress   *string // nullable string
	DynamicFqdn *string // nullable string
}

type MxRecord struct {
	DomainId int16
	Name     string
	Priority int16
}

type NsRecord struct {
	DomainId  int16
	Name      string
	SortOrder int16
}

type Domain struct {
	Id         int16
	Name       string
	DefaultTTL time.Duration
	IpAddress  string
	ARecords   []ARecord
	MxRecords  []MxRecord
	NsRecords  []NsRecord
	DnsRecords []DnsRecord
}

type DnsBackend interface {
	CreateSchema() error
	GetDomains() ([]Domain, error)
}

type Db struct {
	Db onedb.OneDBer
}

func NewDb(host string, dbPort string, user string, password string, database string) (*Db, error) {
	port, err := strconv.Atoi(dbPort)
	if err != nil {
		return nil, err
	}

	conn, err := onedb.NewPgxOneDB(host, uint16(port), user, password, database)
	if err != nil {
		return nil, err
	}

	return &Db{conn}, nil
}

type Code struct {
	Code int
}

func (d *Db) CreateSchema() error {
	data := Code{}
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

func (d *Db) GetDomains() ([]Domain, error) {
	domains := make([]Domain, 0)
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

	for i, _ := range domains {
		for _, nsRecord := range nsRecords {
			if nsRecord.DomainId == domains[i].Id {
				domains[i].NsRecords = append(domains[i].NsRecords, nsRecord)
			}
		}
		for _, mxRecord := range mxRecords {
			if mxRecord.DomainId == domains[i].Id {
				domains[i].MxRecords = append(domains[i].MxRecords, mxRecord)
			}
		}
		for _, aRecord := range aRecords {
			if aRecord.DomainId == domains[i].Id {
				domains[i].ARecords = append(domains[i].ARecords, aRecord)
			}
		}
	}
	return domains, nil
}

func (d *Db) getARecords() ([]ARecord, error) {
	aRecords := make([]ARecord, 0)
	return aRecords, d.Db.QueryStruct("select DomainId, Name, IpAddress, DynamicFqdn from ARecords", &aRecords)
}

func (d *Db) getMxRecords() ([]MxRecord, error) {
	mxRecords := make([]MxRecord, 0)
	return mxRecords, d.Db.QueryStruct("select DomainId, Name, Priority from MxRecords", &mxRecords)
}

func (d *Db) getNsRecords() ([]NsRecord, error) {
	nsRecords := make([]NsRecord, 0)
	return nsRecords, d.Db.QueryStruct("select DomainId, Name, SortOrder from NsRecords", &nsRecords)
}
