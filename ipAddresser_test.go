package main

import (
	"testing"
)

func TestIpAddressHelper(t *testing.T) {
	h := &IPAddressHelper{}
	addr, err := h.GetIpAddresses()
	if err != nil || len(addr) == 0 {
		t.Error("expected to get back ip addresses")
	}
}
