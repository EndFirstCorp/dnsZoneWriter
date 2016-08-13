package main

import (
	"errors"
	"net"
)

type ipAddresser interface {
	GetIPAddresses() ([]string, error)
}

type ipAddressHelper struct {
	ipAddresser
}

func (h *ipAddressHelper) GetIPAddresses() ([]string, error) {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("Unable to get IP addresses " + err.Error())
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if !ip.IsLoopback() {
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}
