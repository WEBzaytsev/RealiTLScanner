package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

func ScanTLS(host Host, out chan<- string, geo *Geo, config *ScanConfig) {
	if host.IP == nil {
		ip, err := LookupIP(host.Origin, config.EnableIPv6)
		if err != nil {
			slog.Debug("Failed to get IP from the origin", "origin", host.Origin, "err", err)
			return
		}
		host.IP = ip
	}
	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(config.Port))
	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(config.Timeout)*time.Second)
	if err != nil {
		slog.Debug("Cannot dial", "target", hostPort)
		return
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	if err != nil {
		slog.Error("Error setting deadline", "err", err)
		return
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}
	if host.Type == HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}
	c := tls.Client(conn, tlsCfg)
	err = c.Handshake()
	if err != nil {
		slog.Debug("TLS handshake failed", "target", hostPort)
		return
	}
	state := c.ConnectionState()
	alpn := state.NegotiatedProtocol
	domain := state.PeerCertificates[0].Subject.CommonName
	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	log := slog.Info
	feasible := true
	geoCode := geo.GetGeo(host.IP)
	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		// not feasible
		log = slog.Debug
		feasible = false
	} else {
		out <- strings.Join([]string{host.IP.String(), host.Origin, domain, "\"" + issuers + "\"", geoCode}, ",") +
			"\n"
	}
	log("Connected to target", "feasible", feasible, "ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tls.VersionName(state.Version), "alpn", alpn, "cert-domain", domain, "cert-issuer", issuers,
		"geo", geoCode)
}

func ScanTLSWithCallbacks(host Host, scanner *Scanner) {
	if host.IP == nil {
		ip, err := LookupIP(host.Origin, scanner.Config.EnableIPv6)
		if err != nil {
			if scanner.Callbacks != nil && scanner.Callbacks.OnLog != nil {
				scanner.Callbacks.OnLog("debug", "Failed to get IP from "+host.Origin)
			}
			return
		}
		host.IP = ip
	}

	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(scanner.Config.Port))
	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(scanner.Config.Timeout)*time.Second)
	if err != nil {
		if scanner.Callbacks != nil && scanner.Callbacks.OnLog != nil && scanner.Config.Verbose {
			scanner.Callbacks.OnLog("debug", "Cannot dial "+hostPort)
		}
		return
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(time.Duration(scanner.Config.Timeout) * time.Second))
	if err != nil {
		return
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}
	if host.Type == HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}

	c := tls.Client(conn, tlsCfg)
	err = c.Handshake()
	if err != nil {
		if scanner.Callbacks != nil && scanner.Callbacks.OnLog != nil && scanner.Config.Verbose {
			scanner.Callbacks.OnLog("debug", "TLS handshake failed for "+hostPort)
		}
		return
	}

	state := c.ConnectionState()
	alpn := state.NegotiatedProtocol
	
	// Safely access certificate data
	if len(state.PeerCertificates) == 0 {
		if scanner.Callbacks != nil && scanner.Callbacks.OnLog != nil && scanner.Config.Verbose {
			scanner.Callbacks.OnLog("debug", "No peer certificates for "+hostPort)
		}
		return
	}
	
	domain := state.PeerCertificates[0].Subject.CommonName
	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	geoCode := scanner.Geo.GetGeo(host.IP)
	tlsVersion := tls.VersionName(state.Version)

	feasible := state.Version == tls.VersionTLS13 && alpn == "h2" && len(domain) > 0 && len(issuers) > 0

	result := ScanResult{
		IP:         host.IP.String(),
		Origin:     host.Origin,
		Domain:     domain,
		Issuer:     issuers,
		GeoCode:    geoCode,
		Feasible:   feasible,
		TLSVersion: tlsVersion,
		ALPN:       alpn,
	}

	if scanner.Callbacks != nil && scanner.Callbacks.OnResult != nil {
		scanner.Callbacks.OnResult(result)
	}
	
	// Log connection details
	if scanner.Callbacks != nil && scanner.Callbacks.OnLog != nil {
		logLevel := "info"
		if !feasible && !scanner.Config.Verbose {
			return // Skip logging non-feasible in non-verbose mode
		}
		if !feasible {
			logLevel = "debug"
		}
		
		logMsg := fmt.Sprintf("Connected: %s | %s | TLS:%s ALPN:%s | Domain:%s | Issuer:%s | Geo:%s | Feasible:%v",
			host.IP.String(), host.Origin, tlsVersion, alpn, domain, issuers, geoCode, feasible)
		scanner.Callbacks.OnLog(logLevel, logMsg)
	}
}
