package main

import (
	"encoding/json"
	"github.com/robarchibald/onedb"
	"io/ioutil"
	"strconv"
)

type aRecord struct {
	DomainID    int16
	Name        string
	IPAddress   string
	DynamicFQDN string
}

type cnameRecord struct {
	DomainID      int16
	Name          string
	CanonicalName string
}

type dkimRecord struct {
	DomainID int16
	Name     string
	Value    string
}

type dmarcRecord struct {
	DomainID int16
	Name     string
	Value    string
}

type mxRecord struct {
	DomainID int16
	Name     string
	Value    string
	Priority int16
}

type nsRecord struct {
	DomainID  int16
	Name      string
	Value     string
	SortOrder int16
}

type spfRecord struct {
	DomainID int16
	Name     string
	Value    string
}

type srvRecord struct {
	DomainID int16
	Name     string
	Value    string
}

type txtRecord struct {
	DomainID int16
	Service  string
	Protocol string
	Priority int16
	Weight   int16
	Port     int16
	Target   string
}

type domainResult struct {
	ID    int16
	Name  string
	A     string
	CNAME string
	DKIM  string
	DMARC string
	MX    string
	NS    string
	SPF   string
	SRV   string
	TXT   string
}

const domainQuery string = `select d.id, d.name, 
array_to_json(array_agg(distinct a)) as a, 
array_to_json(array_agg(distinct c)) as cname, 
array_to_json(array_agg(distinct dk)) as dkim, 
array_to_json(array_agg(distinct dm)) as dmarc, 
array_to_json(array_agg(distinct m)) as mx, 
array_to_json(array_agg(distinct n)) as ns, 
array_to_json(array_agg(distinct spf)) as spf, 
array_to_json(array_agg(distinct srv)) as srv, 
array_to_json(array_agg(distinct t)) as txt
from domains d
left outer join arecords a on a.domainid = d.id
left outer join cnamerecords c on c.domainid = d.id
left outer join dkimrecords dk on dk.domainid = d.id
left outer join dmarcrecords dm on dm.domainid = d.id
left outer join mxrecords m on m.domainid = d.id
left outer join nsrecords n on n.domainid = d.id
left outer join spfrecords spf on spf.domainid = d.id
left outer join srvrecords srv on srv.domainid = d.id
left outer join txtrecords t on t.domainid = d.id
group by d.id, d.name
`

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

type exists struct {
	Found string
}

func (d *db) CreateSchema() error {
	item := exists{}
	err := d.Db.QueryStructRow(onedb.NewSqlQuery("Select '1' as Found from information_schema.tables where table_schema = 'public' and table_name = 'domains'"), &item)
	if err != nil && err.Error() != "no rows in result set" {
		return err
	}

	// schema already exists... exit
	if item.Found == "1" {
		return nil
	}

	schema, err := ioutil.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	err = d.Db.Execute(onedb.NewSqlQuery(string(schema)))
	return err
}

func (d *db) GetDomains() ([]domain, error) {
	res := []domainResult{}
	err := d.Db.QueryStruct(onedb.NewSqlQuery(domainQuery), &res)
	if err != nil {
		return nil, err
	}
	unmarshal := func(jsonTxt string, result interface{}) error {
		if jsonTxt != "[null]" && jsonTxt != "" {
			if err := json.Unmarshal([]byte(jsonTxt), result); err != nil {
				return err
			}
		}
		return nil
	}

	domains := make([]domain, len(res))
	for i := range res {
		domain := domain{ID: res[i].ID, Name: res[i].Name}
		if err := unmarshal(res[i].A, &domain.ARecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].CNAME, &domain.CNameRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].DKIM, &domain.DKIMRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].DMARC, &domain.DMARCRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].MX, &domain.MxRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].NS, &domain.NsRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].SPF, &domain.SPFRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].SRV, &domain.SRVRecords); err != nil {
			return nil, err
		}
		if err := unmarshal(res[i].TXT, &domain.TXTRecords); err != nil {
			return nil, err
		}
		domains[i] = domain
	}
	return domains, nil
}
