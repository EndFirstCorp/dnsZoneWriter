package main

import (
	"errors"
	"testing"

	"github.com/robarchibald/onedb"
)

func TestNewDb(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	_, err := newDb("localhost", "1111", "test", "test", "test")
	if err == nil {
		t.Fatal("expected error due to bogus port")
	}
}

func TestCreateSchema(t *testing.T) {
	// error on query
	d := db{Db: onedb.NewMock(nil, nil)}
	err := d.CreateSchema()
	if err == nil {
		t.Error("expected error due to row query error")
	}

	// schema exists
	d = db{Db: onedb.NewMock(nil, nil, exists{"1"})}
	err = d.CreateSchema()
	if err != nil {
		t.Error("expected success since schema already exists")
	}

	// failed execute
	reader := onedb.NewMock(nil, errors.New("fail"), exists{})
	d = db{Db: reader}
	err = d.CreateSchema()
	if err == nil {
		t.Error("expected error due to failed execute", err)
	}

	// successful create
	d = db{Db: onedb.NewMock(nil, nil, exists{})}
	err = d.CreateSchema()
	if err != nil {
		t.Error("expected success creating schema", err)
	}
}

func TestGetDomains(t *testing.T) {
	domainRecords := []domainResult{
		domainResult{Name: "domain", ID: 1,
			A:     `[{"domainid":1,"name":"arecord","ipaddress":"","dynamicfqdn":""}]`,
			MX:    `[{"domainid":1,"name":"mxrecord","value":"","priority":0}]`,
			NS:    `[{"domainid":1,"name":"nsrecord","value":"","sortorder":0}]`,
			CNAME: `[{"domainid":1,"name":"cname1","canonicalname":""}]`,
		},
		domainResult{Name: "domain2", ID: 1,
			A:     `[{"domainid":2,"name":"arecord2","ipaddress":"","dynamicfqdn":""}]`,
			MX:    `[{"domainid":2,"name":"mxrecord2","value":"","priority":0}]`,
			NS:    `[{"domainid":2,"name":"nsrecord2","value":"","sortorder":0}]`,
			CNAME: `[{"domainid":2,"name":"cname2","canonicalname":""}]`,
		},
	}
	// fail on getARecords
	d := db{Db: onedb.NewMock(nil, nil)}
	_, err := d.GetDomains()
	if err == nil {
		t.Error("expected error since there's no A Records in the Mock reader")
	}

	d = db{Db: onedb.NewMock(nil, nil, domainRecords)}
	domains, err := d.GetDomains()
	if len(domains) != 2 || domains[0].Name != "domain" || domains[1].Name != "domain2" ||
		len(domains[1].ARecords) != 1 || len(domains[0].ARecords) != 1 || domains[0].ARecords[0].Name != "arecord" || domains[1].ARecords[0].Name != "arecord2" ||
		len(domains[1].MxRecords) != 1 || len(domains[0].MxRecords) != 1 || domains[0].MxRecords[0].Name != "mxrecord" || domains[1].MxRecords[0].Name != "mxrecord2" ||
		len(domains[1].NsRecords) != 1 || len(domains[0].NsRecords) != 1 || domains[0].NsRecords[0].Name != "nsrecord" || domains[1].NsRecords[0].Name != "nsrecord2" ||
		len(domains[1].CNameRecords) != 1 || len(domains[0].CNameRecords) != 1 || domains[0].CNameRecords[0].Name != "cname1" || domains[1].CNameRecords[0].Name != "cname2" {
		t.Error("expected 2 domains with correct A, MX, NS and CName records", domains)
	}

	_, err = d.GetDomains()
	if err == nil {
		t.Error("expected error since there is no data left in the reader")
	}
}
