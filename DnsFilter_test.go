package filter

import "testing"

var testFilter *DnsFilter

func TestNewDnsFilter(t *testing.T) {
	var err error
	testFilter, err = NewDnsFilter(
		WithZones("google.com"))
	if err != nil {
		t.Error(err)
	}
	if testFilter == nil {
		t.Error("dnsfilter should not be nil")
	}
}

func TestDnsFilter_AddZones(t *testing.T) {
	err := testFilter.AddZones("google.be", "google.fr", "test.google.com")
	if err != nil {
		t.Error(err)
	}
}

func TestDnsFilter_IsHostnameAllowed(t *testing.T) {
	if !testFilter.IsHostnameAllowed("google.co.uk") {
		t.Error("google.co.uk was not allowed")
	}
	if !testFilter.IsHostnameAllowed("lesoir.be") {
		t.Error("lesoir.be was not allowed")
	}
	if testFilter.IsHostnameAllowed("google.com") {
		t.Error("google.com was allowed")
	}
	if testFilter.IsHostnameAllowed("google.fr") {
		t.Error("google.fr was allowed")
	}
	if testFilter.IsHostnameAllowed("test.google.fr") {
		t.Error("google.fr was allowed")
	}
}

func BenchmarkIpFilter_IsIpAllowed(b *testing.B) {
	var allowed bool
	for i := 0; i < b.N; i++ {
		allowed = testFilter.IsHostnameAllowed("test.google.com")
		if allowed {
			b.Error("240.0.0.3 was allowed during benchmark")
		}
	}
}
