package filter

import (
	"bufio"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DnsFilter struct {
	refreshUrl      string
	refreshInterval time.Duration
	filterLock      sync.RWMutex
	denyList        []string
	HttpErrorChan   chan error
}

type Option func(filter *DnsFilter) error

func NewDnsFilter(opts ...Option) (*DnsFilter, error) {
	filter := &DnsFilter{
		HttpErrorChan: make(chan error),
	}
	for _, opt := range opts {
		err := opt(filter)
		if err != nil {
			return nil, err
		}
	}
	return filter, nil
}

func WithZones(zones ...string) Option {
	return func(filter *DnsFilter) error {
		return filter.AddZones(zones...)
	}
}

func WithHttpRefresh(refreshUrl string, refreshInterval time.Duration) Option {
	return func(filter *DnsFilter) error {
		filter.refreshUrl = refreshUrl
		filter.refreshInterval = refreshInterval
		go filter.startUpdatesRanges()
		return nil
	}
}

func (filter *DnsFilter) AddZones(zones ...string) (err error) {
	for _, zone := range zones {
		err = filter.AddZone(zone)
		if err != nil {
			return err
		}
	}
	return nil
}

func (filter *DnsFilter) AddZone(zone string) (err error) {
	if !filter.IsHostnameAllowed(zone) {
		return nil
	}
	log.Printf("adding %s in blocklist", zone)
	filter.filterLock.Lock()
	defer filter.filterLock.Unlock()
	filter.denyList = append(filter.denyList, zone)
	return nil
}

func (filter *DnsFilter) IsHostnameAllowed(hostname string) bool {
	filter.filterLock.RLock()
	defer filter.filterLock.RUnlock()
	for _, zone := range filter.denyList {
		if zone == hostname || strings.HasSuffix(hostname, "."+zone) {
			return false
		}
	}
	return true
}

var ErrHttpRefreshZone = errors.New("network error refreshing blocklist from http source")
var ErrHttpRefreshStatus = errors.New("bad http status from http blocklist source")

func (filter *DnsFilter) startUpdatesRanges() {
	for {
		err := filter.updateRanges()
		if err != nil {
			select {
			case filter.HttpErrorChan <- err:
			default:
				log.Println(err)
			}
		}
		time.Sleep(filter.refreshInterval)
	}
}

func (filter *DnsFilter) updateRanges() error {
	resp, err := http.Get(filter.refreshUrl)
	if err != nil {
		return ErrHttpRefreshZone
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ErrHttpRefreshStatus
	}
	reader := bufio.NewScanner(resp.Body)
	for reader.Scan() {
		err = filter.AddZone(reader.Text())
		if err != nil {
			select {
			case filter.HttpErrorChan <- err:
			default:
				log.Println(err)
			}
		}
	}
	return nil
}
