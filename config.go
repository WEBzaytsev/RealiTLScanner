package main

import "context"

// ScanConfig contains all scanning parameters
type ScanConfig struct {
	Port       int
	Thread     int
	Timeout    int
	EnableIPv6 bool
	Verbose    bool
}

// ScanResult represents the scan result for one host
type ScanResult struct {
	IP         string
	Origin     string
	Domain     string
	Issuer     string
	GeoCode    string
	Feasible   bool
	TLSVersion string
	ALPN       string
}

// ScanCallbacks contains callback functions for GUI
type ScanCallbacks struct {
	OnResult    func(result ScanResult)
	OnProgress  func(current, total int)
	OnLog       func(level, message string)
	OnGeoStatus func(status string)
}

// Scanner manages the scanning process
type Scanner struct {
	Config    *ScanConfig
	Callbacks *ScanCallbacks
	Geo       *Geo
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewScanner creates a new Scanner instance
func NewScanner(config *ScanConfig, callbacks *ScanCallbacks) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Notify about GeoIP initialization start
	if callbacks != nil && callbacks.OnGeoStatus != nil {
		callbacks.OnGeoStatus("Checking GeoIP database...")
	}
	
	geo := NewGeo()
	
	// Notify about completion
	if callbacks != nil && callbacks.OnGeoStatus != nil {
		if geo.geoReader != nil {
			callbacks.OnGeoStatus("GeoIP ready")
		} else {
			callbacks.OnGeoStatus("GeoIP unavailable")
		}
	}
	
	return &Scanner{
		Config:    config,
		Callbacks: callbacks,
		Geo:       geo,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Stop stops the scanning process
func (s *Scanner) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// Context returns the scanning context
func (s *Scanner) Context() context.Context {
	return s.ctx
}
