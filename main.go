//
// Copyright (C) 2025 TrakRF
//
// SPDX-License-Identifier: Apache-2.0
//
// This file contains code derived from EdgeX Foundry device-rfid-llrp-go
// Copyright (C) 2020 Intel Corporation

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/bits"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Configuration from environment variables
type Config struct {
	Subnets           []string
	AsyncLimit        int
	TimeoutSeconds    int
	ScanPort          string
	HTTPPort          string
	MaxDurationSeconds int
}

// DiscoveredReader represents a discovered LLRP reader
type DiscoveredReader struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

// DiscoveryResponse is the JSON response for discovery requests
type DiscoveryResponse struct {
	Readers    []DiscoveredReader `json:"readers"`
	Scanned    int                `json:"scanned"`
	DurationMS int64              `json:"duration_ms"`
	Error      string             `json:"error,omitempty"`
}

// Global config
var config Config

func main() {
	// Load configuration from environment
	config = loadConfig()

	log.Printf("Starting LLRP Discovery Service")
	log.Printf("Configuration: %+v", config)

	// Setup HTTP handlers with CORS
	http.HandleFunc("/discover", corsMiddleware(handleDiscover))
	http.HandleFunc("/health", corsMiddleware(handleHealth))

	// Start HTTP server
	addr := ":" + config.HTTPPort
	log.Printf("Listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func loadConfig() Config {
	var subnets []string

	// Check if SUBNETS env var is set
	subnetsStr := os.Getenv("SUBNETS")
	if subnetsStr != "" {
		// Use manually configured subnets
		subnets = strings.Split(subnetsStr, ",")
		for i := range subnets {
			subnets[i] = strings.TrimSpace(subnets[i])
		}
		log.Printf("Using configured subnets: %v", subnets)
	} else {
		// Auto-detect network interfaces
		detected, err := detectNetworkSubnets()
		if err != nil {
			log.Printf("Failed to auto-detect network subnets: %v, using default", err)
			subnets = []string{"192.168.1.0/24"}
		} else {
			subnets = detected
			log.Printf("Auto-detected subnets: %v", subnets)
		}
	}

	asyncLimit, _ := strconv.Atoi(getEnv("ASYNC_LIMIT", "1000"))
	timeoutSeconds, _ := strconv.Atoi(getEnv("TIMEOUT_SECONDS", "5"))
	maxDurationSeconds, _ := strconv.Atoi(getEnv("MAX_DURATION_SECONDS", "300"))

	return Config{
		Subnets:           subnets,
		AsyncLimit:        asyncLimit,
		TimeoutSeconds:    timeoutSeconds,
		ScanPort:          getEnv("SCAN_PORT", "5084"),
		HTTPPort:          getEnv("HTTP_PORT", "8080"),
		MaxDurationSeconds: maxDurationSeconds,
	}
}

// detectNetworkSubnets discovers all non-loopback IPv4 subnets on the host
func detectNetworkSubnets() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// Common Docker bridge networks to skip
	dockerNetworks := []string{
		"172.17.0.0/16", // Default Docker bridge
		"172.18.0.0/16", // Additional Docker networks
		"172.19.0.0/16",
		"172.20.0.0/16",
	}

	var subnets []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip common Docker bridge interface names
		if strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "br-") {
			log.Printf("Skipping Docker bridge interface: %s", iface.Name)
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("Failed to get addresses for interface %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			// Check if it's an IP network
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Only process IPv4 addresses
			if ipNet.IP.To4() == nil {
				continue
			}

			// Skip link-local addresses (169.254.0.0/16)
			if ipNet.IP.IsLinkLocalUnicast() {
				continue
			}

			// Skip Docker bridge networks
			if isDockerNetwork(ipNet, dockerNetworks) {
				log.Printf("Skipping Docker network: %s", ipNet.String())
				continue
			}

			// Add the network CIDR
			subnet := ipNet.String()
			subnets = append(subnets, subnet)
			log.Printf("Detected interface %s with subnet %s", iface.Name, subnet)
		}
	}

	if len(subnets) == 0 {
		return nil, fmt.Errorf("no suitable network interfaces found")
	}

	return subnets, nil
}

// isDockerNetwork checks if an IP network overlaps with known Docker networks
func isDockerNetwork(ipNet *net.IPNet, dockerNetworks []string) bool {
	for _, dockerCIDR := range dockerNetworks {
		_, dockerNet, err := net.ParseCIDR(dockerCIDR)
		if err != nil {
			continue
		}
		// Check if this network is contained within or overlaps with a Docker network
		if dockerNet.Contains(ipNet.IP) {
			return true
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// corsMiddleware adds CORS headers to allow cross-origin requests
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow all origins for discovery service
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleDiscover(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Allow override of subnets via query parameter
	subnets := config.Subnets
	if subnetParam := r.URL.Query().Get("subnets"); subnetParam != "" {
		subnets = strings.Split(subnetParam, ",")
		for i := range subnets {
			subnets[i] = strings.TrimSpace(subnets[i])
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.MaxDurationSeconds)*time.Second)
	defer cancel()

	// Perform discovery
	readers, scanned, err := discover(ctx, subnets, config.AsyncLimit, time.Duration(config.TimeoutSeconds)*time.Second, config.ScanPort)

	duration := time.Since(start).Milliseconds()

	response := DiscoveryResponse{
		Readers:    readers,
		Scanned:    scanned,
		DurationMS: duration,
	}

	if err != nil {
		response.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Discovery completed: %d readers found, %d IPs scanned in %dms", len(readers), scanned, duration)
}

// discover performs the network discovery
// This function is derived from EdgeX Foundry device-rfid-llrp-go internal/driver/discover.go
func discover(ctx context.Context, subnets []string, asyncLimit int, timeout time.Duration, scanPort string) ([]DiscoveredReader, int, error) {
	if len(subnets) == 0 {
		return nil, 0, fmt.Errorf("no subnets configured")
	}

	// Parse CIDR subnets
	ipnets := make([]*net.IPNet, 0, len(subnets))
	var estimatedProbes int
	for _, cidr := range subnets {
		if cidr == "" {
			continue
		}

		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Unable to parse CIDR: %q, error: %v", cidr, err)
			continue
		}
		if ip == nil || ipnet == nil || ip.To4() == nil {
			log.Printf("Currently only IPv4 subnets are supported: %s", cidr)
			continue
		}

		ipnets = append(ipnets, ipnet)
		sz, _ := ipnet.Mask.Size()
		estimatedProbes += int(computeNetSz(sz))
	}

	if len(ipnets) == 0 {
		return nil, 0, fmt.Errorf("no valid subnets to scan")
	}

	// Adjust asyncLimit if needed
	if estimatedProbes < asyncLimit {
		asyncLimit = estimatedProbes
	}

	log.Printf("Estimated network probes: %d, async limit: %d, probe timeout: %v", estimatedProbes, asyncLimit, timeout)

	ipCh := make(chan uint32, asyncLimit)
	resultCh := make(chan DiscoveredReader)

	// Start worker pool
	var wgWorkers sync.WaitGroup
	wgWorkers.Add(asyncLimit)
	for i := 0; i < asyncLimit; i++ {
		go func() {
			defer wgWorkers.Done()
			ipWorker(ctx, ipCh, resultCh, scanPort, timeout)
		}()
	}

	// Start IP generators and result collector
	go func() {
		var wgGenerators sync.WaitGroup
		for _, ipnet := range ipnets {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wgGenerators.Add(1)
			go func(inet *net.IPNet) {
				defer wgGenerators.Done()
				ipGenerator(ctx, inet, ipCh)
			}(ipnet)
		}

		wgGenerators.Wait()
		close(ipCh)
		wgWorkers.Wait()
		close(resultCh)
	}()

	// Collect results
	readers := make([]DiscoveredReader, 0)
	for reader := range resultCh {
		readers = append(readers, reader)
	}

	return readers, estimatedProbes, nil
}

// computeNetSz computes the total amount of valid IP addresses for a given subnet size
// Derived from EdgeX Foundry device-rfid-llrp-go
func computeNetSz(subnetSz int) uint32 {
	if subnetSz >= 31 {
		return 1
	}
	return ^uint32(0)>>subnetSz - 1
}

// ipGenerator generates all valid IP addresses for a given subnet
// Derived from EdgeX Foundry device-rfid-llrp-go
func ipGenerator(ctx context.Context, inet *net.IPNet, ipCh chan<- uint32) {
	addr := inet.IP.To4()
	if addr == nil {
		return
	}

	mask := inet.Mask
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	} else if len(mask) != net.IPv4len {
		return
	}

	umask := binary.BigEndian.Uint32(mask)
	maskSz := bits.OnesCount32(umask)
	if maskSz <= 1 {
		return // skip point-to-point connections
	} else if maskSz >= 31 {
		ipCh <- binary.BigEndian.Uint32(inet.IP)
		return
	}

	netId := binary.BigEndian.Uint32(addr) & umask
	bcast := netId ^ (^umask)
	for ip := netId + 1; ip < bcast; ip++ {
		if netId&umask != ip&umask {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case ipCh <- ip:
		}
	}
}

// ipWorker processes IPs from the channel and probes them
// Derived from EdgeX Foundry device-rfid-llrp-go
func ipWorker(ctx context.Context, ipCh <-chan uint32, resultCh chan<- DiscoveredReader, scanPort string, timeout time.Duration) {
	ip := net.IP([]byte{0, 0, 0, 0})

	for {
		select {
		case <-ctx.Done():
			return
		case a, ok := <-ipCh:
			if !ok {
				return
			}

			binary.BigEndian.PutUint32(ip, a)
			ipStr := ip.String()

			select {
			case <-ctx.Done():
				return
			default:
			}

			if reader, err := probe(ipStr, scanPort, timeout); err == nil {
				resultCh <- reader
			}
		}
	}
}

// probe attempts to connect to a potential LLRP reader
// Simplified version derived from EdgeX Foundry device-rfid-llrp-go
func probe(host, port string, timeout time.Duration) (DiscoveredReader, error) {
	addr := host + ":" + port
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return DiscoveredReader{}, err
	}
	defer conn.Close()

	// Successfully connected - likely an LLRP reader
	log.Printf("Found LLRP reader at %s", addr)

	// Resolve hostname
	hostname := host
	if names, err := net.LookupAddr(host); err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	portInt, _ := strconv.Atoi(port)
	return DiscoveredReader{
		IP:       host,
		Hostname: hostname,
		Port:     portInt,
	}, nil
}
