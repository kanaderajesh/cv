// scanner.go
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HostConfig struct {
	Host      string   `json:"host"`
	Ports     []string `json:"ports"`                 // accepts "22", "80-90", etc.
	Send      string   `json:"send,omitempty"`        // optional probe to send after connect (raw string; use \r\n etc)
	TimeoutMs int      `json:"timeout_ms,omitempty"`  // per-connection timeout in milliseconds
	TLS       bool     `json:"tls,omitempty"`         // if true attempt TLS handshake and collect cert info
}

type Config struct {
	Concurrency int          `json:"concurrency,omitempty"`
	DefaultTimeoutMs int     `json:"default_timeout_ms,omitempty"`
	Hosts       []HostConfig `json:"hosts"`
}

// Result for each scan
type Result struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Open       bool   `json:"open"`
	Error      string `json:"error,omitempty"`
	Banner     string `json:"banner,omitempty"`
	TLSInfo    string `json:"tls_info,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

func parsePortSpecList(specs []string) ([]int, error) {
	portSet := make(map[int]struct{})
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "-") {
			parts := strings.SplitN(s, "-", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", s)
			}
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start in range %s: %v", s, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end in range %s: %v", s, err)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid range values: %s", s)
			}
			for p := start; p <= end; p++ {
				portSet[p] = struct{}{}
			}
		} else {
			p, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", s)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			portSet[p] = struct{}{}
		}
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func scanTCP(host string, port int, timeout time.Duration, sendProbe string, useTLS bool, maxRead int) Result {
	start := time.Now()
	res := Result{Host: host, Port: port, Open: false}
	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: timeout}
	if useTLS {
		// Perform TLS handshake
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true, // we only want cert info / handshake, not verify
		})
		if err != nil {
			res.Error = err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		defer conn.Close()
		res.Open = true

		// Probe after handshake if probe provided
		if sendProbe != "" {
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			_, err = conn.Write([]byte(sendProbe))
			if err != nil {
				res.Error = "write probe error: " + err.Error()
				res.DurationMs = time.Since(start).Milliseconds()
				return res
			}
		}

		// Try to read a small response if any (protocol-specific)
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, maxRead)
		n, _ := conn.Read(buf) // ignore read error - often nil if there's nothing
		if n > 0 {
			res.Banner = string(buf[:n])
		}

		// Add TLS cert summary
		if conn.ConnectionState().PeerCertificates != nil && len(conn.ConnectionState().PeerCertificates) > 0 {
			cert := conn.ConnectionState().PeerCertificates[0]
			res.TLSInfo = fmt.Sprintf("Subject:%s Issuer:%s NotBefore:%s NotAfter:%s", cert.Subject.String(), cert.Issuer.String(), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
		}
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	// Plain TCP
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		res.Error = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer conn.Close()
	res.Open = true

	// Optionally send probe
	if sendProbe != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = conn.Write([]byte(sendProbe))
		if err != nil {
			res.Error = "write probe error: " + err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
	}

	// Read any available banner (up to maxRead) with a read deadline
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		// Many services don't send anything; that's fine: we capture partial data if any.
		// We'll not treat read errors as fatal unless nothing was read.
		if n == 0 {
			res.Error = "read error: " + err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
	}
	if n > 0 {
		res.Banner = string(buf[:n])
	}

	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func worker(id int, jobs <-chan struct {
	host  HostConfig
	port  int
}, results chan<- Result, wg *sync.WaitGroup, defaultTimeout time.Duration) {
	defer wg.Done()
	const maxRead = 4096
	for job := range jobs {
		timeout := defaultTimeout
		if job.host.TimeoutMs > 0 {
			timeout = time.Millisecond * time.Duration(job.host.TimeoutMs)
		}
		res := scanTCP(job.host.Host, job.port, timeout, job.host.Send, job.host.TLS, maxRead)
		results <- res
	}
}

func main() {
	var configPath string
	var outFile string
	flag.StringVar(&configPath, "config", "scan_config.json", "path to JSON config file")
	flag.StringVar(&outFile, "out", "", "optional output file to write results as JSON")
	flag.Parse()

	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read config %s: %v\n", configPath, err)
		os.Exit(1)
	}

	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse config: %v\n", err)
		os.Exit(1)
	}

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	defaultTimeout := 5 * time.Second
	if cfg.DefaultTimeoutMs > 0 {
		defaultTimeout = time.Millisecond * time.Duration(cfg.DefaultTimeoutMs)
	}

	// Build job list
	type jobItem struct {
		host HostConfig
		port int
	}
	jobsChan := make(chan struct {
		host HostConfig
		port int
	}, 1000)

	resultsChan := make(chan Result, 1000)
	var wg sync.WaitGroup

	// Start workers
	workerCount := cfg.Concurrency
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go worker(i, jobsChan, resultsChan, &wg, defaultTimeout)
	}

	// enqueue jobs
	go func() {
		for _, h := range cfg.Hosts {
			ports, err := parsePortSpecList(h.Ports)
			if err != nil {
				// Send an error result for this host to resultsChan
				resultsChan <- Result{
					Host:  h.Host,
					Port:  0,
					Open:  false,
					Error: "invalid port spec: " + err.Error(),
				}
				continue
			}
			for _, p := range ports {
				jobsChan <- struct {
					host HostConfig
					port int
				}{host: h, port: p}
			}
		}
		close(jobsChan)
	}()

	// close resultsChan when workers done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// collect results
	var results []Result
	for r := range resultsChan {
		// truncate banner if too long in output
		if len(r.Banner) > 2000 {
			r.Banner = r.Banner[:2000] + "...(truncated)"
		}
		results = append(results, r)
		// print one-line quick summary
		status := "closed"
		if r.Open {
			status = "open"
		}
		fmt.Printf("%s:%d %s (%dms) %s\n", r.Host, r.Port, status, r.DurationMs, summaryBanner(r.Banner, r.TLSInfo, r.Error))
	}

	// dump json if requested
	outJSON, _ := json.MarshalIndent(results, "", "  ")
	if outFile != "" {
		if err := os.WriteFile(outFile, outJSON, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write out file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Results written to %s\n", outFile)
	} else {
		// print to stdout
		fmt.Println("\n=== JSON results ===")
		fmt.Println(string(outJSON))
	}
}

func summaryBanner(banner, tlsinfo, errstr string) string {
	if errstr != "" {
		return "err=" + errstr
	}
	if tlsinfo != "" {
		return "tls=" + tlsinfo
	}
	if banner != "" {
		// single-line banner preview
		b := strings.ReplaceAll(banner, "\r\n", " ")
		b = strings.ReplaceAll(b, "\n", " ")
		if len(b) > 80 {
			b = b[:80] + "..."
		}
		return "banner=\"" + b + "\""
	}
	return ""
}