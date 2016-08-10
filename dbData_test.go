package main

import (
	"errors"
	"testing"

	"github.com/robarchibald/easyDbReader"
)

func TestNewDb(t *testing.T) {
	_, err := NewDb("localhost", "1111", "test", "test", "test")
	if err == nil {
		t.Fatal("expected error due to bogus port")
	}
}

type Code struct {
	Code int
}

func TestCreateSchema(t *testing.T) {
	// error on query
	db := Db{Db: easyDbReader.NewMockDbReader()}
	err := db.CreateSchema()
	if err == nil {
		t.Error("expected error due to row query error")
	}

	// schema exists
	db = Db{Db: easyDbReader.NewMockDbReader(&Code{1})}
	err = db.CreateSchema()
	if err != nil {
		t.Error("expected success since schema already exists")
	}

	// failed execute
	reader := easyDbReader.NewMockDbReader(&Code{0})
	reader.ExecErr = errors.New("fail")
	db = Db{Db: reader}
	err = db.CreateSchema()
	if err == nil {
		t.Error("expected error due to failed execute", err)
	}

	// successful create
	db = Db{Db: easyDbReader.NewMockDbReader(&Code{0})}
	err = db.CreateSchema()
	if err != nil {
		t.Error("expected success creating schema", err)
	}
}

func TestGetDomains(t *testing.T) {
	aRecords := []ARecord{ARecord{Name: "arecord", DomainId: 1}, ARecord{Name: "arecord2", DomainId: 2}}
	mxRecords := []MxRecord{MxRecord{Name: "mxrecord", DomainId: 1}, MxRecord{Name: "mxrecord2", DomainId: 2}}
	nsRecords := []NsRecord{NsRecord{Name: "nsrecord", DomainId: 1}, NsRecord{Name: "nsrecord2", DomainId: 2}}
	domainRecords := []Domain{Domain{Name: "domain", Id: 1}, Domain{Name: "domain2", Id: 2}}
	// fail on getARecords
	db := Db{Db: easyDbReader.NewMockDbReader()}
	_, err := db.GetDomains()
	if err == nil {
		t.Error("expected error since there's no data in the Mock reader")
	}

	// fail on getMxRecords
	db = Db{Db: easyDbReader.NewMockDbReader(aRecords)}
	_, err = db.GetDomains()
	if err == nil {
		t.Error("expected error since there's only one dataset in the Mock reader")
	}

	// fail on getNsRecords
	db = Db{Db: easyDbReader.NewMockDbReader(aRecords, mxRecords)}
	_, err = db.GetDomains()
	if err == nil {
		t.Error("expected error since there's only one dataset in the Mock reader")
	}

	// fail on get domains
	db = Db{Db: easyDbReader.NewMockDbReader(aRecords, mxRecords, nsRecords)}
	_, err = db.GetDomains()
	if err == nil {
		t.Error("expected error since there's only one dataset in the Mock reader")
	}

	db = Db{Db: easyDbReader.NewMockDbReader(aRecords, mxRecords, nsRecords, domainRecords)}
	domains, _ := db.GetDomains()
	if len(domains) != 2 || domains[0].Name != "domain" || domains[1].Name != "domain2" ||
		len(domains[1].ARecords) != 1 || len(domains[0].ARecords) != 1 || domains[0].ARecords[0].Name != "arecord" || domains[1].ARecords[0].Name != "arecord2" ||
		len(domains[1].MxRecords) != 1 || len(domains[0].MxRecords) != 1 || domains[0].MxRecords[0].Name != "mxrecord" || domains[1].MxRecords[0].Name != "mxrecord2" ||
		len(domains[1].NsRecords) != 1 || len(domains[0].NsRecords) != 1 || domains[0].NsRecords[0].Name != "nsrecord" || domains[1].NsRecords[0].Name != "nsrecord2" {
		t.Error("expected 2 domains with correct A, MX and NS records", domains)
	}

	_, err = db.GetDomains()
	if err == nil {
		t.Error("expected error since there is no data left in the reader")
	}
}

func TestGetARecords(t *testing.T) {
	reader := easyDbReader.NewMockDbReader([]ARecord{ARecord{Name: "arecord"}})
	db := Db{Db: reader}
	aRecords, err := db.getARecords()
	if err != nil || len(aRecords) != 1 || aRecords[0].Name != "arecord" {
		t.Error("expected successful query", aRecords)
	}
}

func TestGetMxRecords(t *testing.T) {
	reader := easyDbReader.NewMockDbReader([]MxRecord{MxRecord{Name: "mxrecord"}})
	db := Db{Db: reader}
	mxRecords, err := db.getMxRecords()
	if err != nil || len(mxRecords) != 1 || mxRecords[0].Name != "mxrecord" {
		t.Error("expected successful query", mxRecords)
	}
}

func TestGetNsRecords(t *testing.T) {
	reader := easyDbReader.NewMockDbReader([]NsRecord{NsRecord{Name: "nsrecord"}})
	db := Db{Db: reader}
	nsRecords, err := db.getNsRecords()
	if err != nil || len(nsRecords) != 1 || nsRecords[0].Name != "nsrecord" {
		t.Error("expected successful query", nsRecords)
	}
}
