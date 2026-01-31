package main

import "context"

// ScanConfig содержит все параметры сканирования
type ScanConfig struct {
	Port       int
	Thread     int
	Timeout    int
	EnableIPv6 bool
	Verbose    bool
}

// ScanResult представляет результат сканирования одного хоста
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

// ScanCallbacks содержит callback функции для GUI
type ScanCallbacks struct {
	OnResult    func(result ScanResult)
	OnProgress  func(current, total int)
	OnLog       func(level, message string)
	OnGeoStatus func(status string)
}

// Scanner управляет процессом сканирования
type Scanner struct {
	Config    *ScanConfig
	Callbacks *ScanCallbacks
	Geo       *Geo
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewScanner создает новый экземпляр Scanner
func NewScanner(config *ScanConfig, callbacks *ScanCallbacks) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Уведомить о начале инициализации GeoIP
	if callbacks != nil && callbacks.OnGeoStatus != nil {
		callbacks.OnGeoStatus("Checking GeoIP database...")
	}
	
	geo := NewGeo()
	
	// Уведомить о завершении
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

// Stop останавливает сканирование
func (s *Scanner) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// Context возвращает контекст сканирования
func (s *Scanner) Context() context.Context {
	return s.ctx
}
