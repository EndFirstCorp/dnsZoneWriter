package main

import (
	"testing"
)

func TestIpAddressHelper(t *testing.T) {
	h := &ipAddressHelper{}
	addr, err := h.GetIPAddresses()
	if err != nil || len(addr) == 0 {
		t.Error("expected to get back ip addresses")
	}
}
