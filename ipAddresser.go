package main

import (
	"errors"
	"net"
)

type IPAddresser interface {
	GetIPAddresses() ([]string, error)
}

type IPAddressHelper struct {
	IPAddresser
}

func (h *IPAddressHelper) GetIpAddresses() ([]string, error) {
	ips := make([]string, 0)
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
