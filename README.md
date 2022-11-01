# Golang DnsFilter

This library for testing individual hostnames against a zone blocklist.

An HTTP source can be provided for regular updates of the blocklist.

## Basic usage

```golang
package main

import (
	filter "github.com/LeakIX/golang-dnsfilter"
	"log"
	"time"
)

func main() {
	// Create a new filter, updating its blocklist from remote every 60 seconds :
	dnsFilter, err := filter.NewDnsFilter(
		filter.WithZones("google.com", "google.fr"),
		filter.WithHttpRefresh("https://some.website/blocked-dns.txt", 60*time.Second))
	if err != nil {
		log.Fatalln(err)
	}
	// Add a range to the filter
	err = dnsFilter.AddZone("google.co.uk")
	if err != nil {
		log.Fatalln(err)
	}
	// Handle HTTP refresh errors
	go func() {
		for {
			err := <- dnsFilter.HttpErrorChan
			log.Println(err)
		}
	}()
	if dnsFilter.IsHostnameAllowed("test.google.com") {
		// 127.0.0.1 is allowed
	} else {
		// 127.0.0.1 is not allowed
	}
}
```
