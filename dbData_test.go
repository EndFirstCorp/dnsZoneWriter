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
	d = db{Db: onedb.NewMock(nil, nil, code{1})}
	err = d.CreateSchema()
	if err != nil {
		t.Error("expected success since schema already exists")
	}

	// failed execute
	reader := onedb.NewMock(nil, errors.New("fail"), code{0})
	d = db{Db: reader}
	err = d.CreateSchema()
	if err == nil {
		t.Error("expected error due to failed execute", err)
	}

	// successful create
	d = db{Db: onedb.NewMock(nil, nil, code{0})}
	err = d.CreateSchema()
	if err != nil {
		t.Error("expected success creating schema", err)
	}
}

func TestGetDomains(t *testing.T) {
	aRecords := []aRecord{aRecord{Name: "arecord", DomainID: 1}, aRecord{Name: "arecord2", DomainID: 2}}
	mxRecords := []mxRecord{mxRecord{Name: "mxrecord", DomainID: 1}, mxRecord{Name: "mxrecord2", DomainID: 2}}
	nsRecords := []nsRecord{nsRecord{Name: "nsrecord", DomainID: 1}, nsRecord{Name: "nsrecord2", DomainID: 2}}
	cnameRecords := []cnameRecord{cnameRecord{Name: "cname1", DomainID: 1}, cnameRecord{Name: "cname2", DomainID: 2}}
	domainRecords := []domain{domain{Name: "domain", ID: 1}, domain{Name: "domain2", ID: 2}}
	// fail on getARecords
	d := db{Db: onedb.NewMock(nil, nil)}
	_, err := d.GetDomains()
	if err == nil {
		t.Error("expected error since there's no A Records in the Mock reader")
	}

	// fail on getMxRecords
	d = db{Db: onedb.NewMock(nil, nil, aRecords)}
	_, err = d.GetDomains()
	if err == nil {
		t.Error("expected error since there's no MX Records in the Mock reader")
	}

	// fail on getNsRecords
	d = db{Db: onedb.NewMock(nil, nil, aRecords, mxRecords)}
	_, err = d.GetDomains()
	if err == nil {
		t.Error("expected error since there's no NS Records in the Mock reader")
	}

	// fail on getCNameRecords
	d = db{Db: onedb.NewMock(nil, nil, aRecords, mxRecords, nsRecords)}
	_, err = d.GetDomains()
	if err == nil {
		t.Error("expected error since there's no CNames in the Mock reader")
	}

	// fail on get domains
	d = db{Db: onedb.NewMock(nil, nil, aRecords, mxRecords, nsRecords, cnameRecords)}
	_, err = d.GetDomains()
	if err == nil {
		t.Error("expected error since there's no domains in the Mock reader")
	}

	d = db{Db: onedb.NewMock(nil, nil, aRecords, mxRecords, nsRecords, cnameRecords, domainRecords)}
	domains, _ := d.GetDomains()
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

func TestGetARecords(t *testing.T) {
	reader := onedb.NewMock(nil, nil, []aRecord{aRecord{Name: "arecord"}})
	db := db{Db: reader}
	aRecords, err := db.getARecords()
	if err != nil || len(aRecords) != 1 || aRecords[0].Name != "arecord" {
		t.Error("expected successful query", aRecords)
	}
}

func TestGetMxRecords(t *testing.T) {
	reader := onedb.NewMock(nil, nil, []mxRecord{mxRecord{Name: "mxrecord"}})
	db := db{Db: reader}
	mxRecords, err := db.getMxRecords()
	if err != nil || len(mxRecords) != 1 || mxRecords[0].Name != "mxrecord" {
		t.Error("expected successful query", mxRecords)
	}
}

func TestGetNsRecords(t *testing.T) {
	reader := onedb.NewMock(nil, nil, []nsRecord{nsRecord{Name: "nsrecord"}})
	db := db{Db: reader}
	nsRecords, err := db.getNsRecords()
	if err != nil || len(nsRecords) != 1 || nsRecords[0].Name != "nsrecord" {
		t.Error("expected successful query", nsRecords)
	}
}
