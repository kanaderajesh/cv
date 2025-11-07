package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type Result struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Success    bool   `json:"success"`
	Attempts   int    `json:"attempts"`
	LastError  string `json:"error,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Username   string `json:"username"`
	KeyPath    string `json:"key_path"`
	FinishedAt string `json:"finished_at"`
}

func main() {
	var (
		hostsFile   string
		keyPath     string
		user        string
		port        int
		timeoutSec  int
		concurrency int
		retries     int
		retryDelay  time.Duration
		outFormat   string // text|json|csv
		outFile     string
		showProg    bool
	)

	cmd := &cobra.Command{
		Use:   "sshhandshake",
		Short: "Concurrent SSH handshake checker (no passphrase keys only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostsFile == "" {
				return errors.New("--hosts is required")
			}
			if keyPath == "" {
				return errors.New("--key is required")
			}
			hosts, err := loadHosts(hostsFile)
			if err != nil {
				return fmt.Errorf("load hosts: %w", err)
			}
			if len(hosts) == 0 {
				return errors.New("no hosts found in JSON")
			}

			// load unencrypted private key
			signer, err := loadPrivateKeyNoPass(keyPath)
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}

			cfg := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), // handshake probe
				Timeout:         time.Duration(timeoutSec) * time.Second,
			}

			// progress bar
			var bar *progressbar.ProgressBar
			if showProg {
				bar = progressbar.NewOptions(
					len(hosts),
					progressbar.OptionEnableColorCodes(true),
					progressbar.OptionSetDescription("Handshakes"),
					progressbar.OptionShowCount(),
					progressbar.OptionShowIts(),
					progressbar.OptionSetPredictTime(true),
					progressbar.OptionClearOnFinish(),
				)
			}

			results := runPool(hosts, port, cfg, concurrency, retries, retryDelay, bar)

			// output
			switch outFormat {
			case "json":
				return writeJSON(outFile, results)
			case "csv":
				return writeCSV(outFile, results)
			case "text":
				fallthrough
			default:
				printText(results)
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&hostsFile, "hosts", "f", "", "Path to JSON file: [\"192.168.1.10\",\"10.0.0.20\"]")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to SSH private key (unencrypted)")
	cmd.Flags().StringVarP(&user, "user", "u", "root", "SSH username")
	cmd.Flags().IntVarP(&port, "port", "p", 22, "SSH port (default 22)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 5, "Handshake timeout in seconds")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 100, "Number of concurrent handshakes")
	cmd.Flags().IntVar(&retries, "retries", 2, "Retries per host (total attempts = retries+1)")
	cmd.Flags().DurationVar(&retryDelay, "retry-delay", 500*time.Millisecond, "Delay between retries (e.g. 500ms, 1s)")
	cmd.Flags().StringVar(&outFormat, "out", "text", "Output format: text|json|csv")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file path (omit to write to stdout)")
	cmd.Flags().BoolVar(&showProg, "progress", true, "Show progress bar")

	_ = cmd.MarkFlagRequired("hosts")
	_ = cmd.MarkFlagRequired("key")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadHosts(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hosts []string
	if err := json.Unmarshal(b, &hosts); err != nil {
		return nil, fmt.Errorf("expected JSON array of strings: %w", err)
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func loadPrivateKeyNoPass(path string) (ssh.Signer, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Will error if key is encrypted (since user said no passphrase)
	return ssh.ParsePrivateKey(key)
}

func runPool(hosts []string, port int, cfg *ssh.ClientConfig, workers, retries int, retryDelay time.Duration, bar *progressbar.ProgressBar) []Result {
	type job struct {
		Idx  int
		Host string
	}
	jobs := make(chan job)
	results := make([]Result, len(hosts))
	var wg sync.WaitGroup

	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := handshakeWithRetry(j.Host, port, cfg, retries, retryDelay)
				results[j.Idx] = r
				if bar != nil {
					_ = bar.Add(1)
				}
			}
		}()
	}

	go func() {
		for i, h := range hosts {
			jobs <- job{Idx: i, Host: h}
		}
		close(jobs)
	}()

	wg.Wait()
	if bar != nil {
		_ = bar.Finish()
	}
	return results
}

func handshakeWithRetry(host string, port int, cfg *ssh.ClientConfig, retries int, retryDelay time.Duration) Result {
	totalAttempts := retries + 1
	var lastErr error
	var latency int64

	addr := formatHostPort(host, port)
	startAll := time.Now()

	for attempt := 1; attempt <= totalAttempts; attempt++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		err := dialOnce(ctx, addr, cfg)
		cancel()
		if err == nil {
			latency = time.Since(start).Milliseconds()
			return Result{
				Host:       host,
				Port:       port,
				Success:    true,
				Attempts:   attempt,
				LastError:  "",
				LatencyMS:  latency,
				Username:   cfg.User,
				KeyPath:    "<provided>",
				FinishedAt: time.Now().Format(time.RFC3339),
			}
		}
		lastErr = err
		if attempt < totalAttempts {
			time.Sleep(retryDelay)
		}
	}

	_ = startAll // kept if you want total time later
	return Result{
		Host:       host,
		Port:       port,
		Success:    false,
		Attempts:   totalAttempts,
		LastError:  lastErr.Error(),
		Username:   cfg.User,
		KeyPath:    "<provided>",
		FinishedAt: time.Now().Format(time.RFC3339),
	}
}

func dialOnce(ctx context.Context, addr string, cfg *ssh.ClientConfig) error {
	type dialRes struct {
		err error
	}

	ch := make(chan dialRes, 1)
	go func() {
		// ssh.Dial respects cfg.Timeout; ctx controls early cancel
		client, err := ssh.Dial("tcp", addr, cfg)
		if err == nil && client != nil {
			_ = client.Close()
		}
		ch <- dialRes{err: err}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		return r.err
	}
}

func formatHostPort(host string, port int) string {
	// Naive but robust enough for IPv6 literals
	if len(host) > 0 && contains(host, ":") && host[0] != '[' {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func writeJSON(path string, results []Result) error {
	w, closeFn, err := writer(path)
	if err != nil {
		return err
	}
	defer closeFn()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeCSV(path string, results []Result) error {
	w, closeFn, err := writer(path)
	if err != nil {
		return err
	}
	defer closeFn()

	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{"host", "port", "success", "attempts", "latency_ms", "username", "error", "finished_at"})
	for _, r := range results {
		row := []string{
			r.Host,
			fmt.Sprintf("%d", r.Port),
			fmt.Sprintf("%t", r.Success),
			fmt.Sprintf("%d", r.Attempts),
			fmt.Sprintf("%d", r.LatencyMS),
			r.Username,
			r.LastError,
			r.FinishedAt,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writer(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, func() {}, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}

func printText(results []Result) {
	ok, fail := 0, 0
	for _, r := range results {
		if r.Success {
			ok++
			if r.LatencyMS > 0 {
				fmt.Printf("[OK]   %s  (%d ms)\n", r.Host, r.LatencyMS)
			} else {
				fmt.Printf("[OK]   %s\n", r.Host)
			}
		} else {
			fail++
			fmt.Printf("[FAIL] %s  (%s)\n", r.Host, r.LastError)
		}
	}
	fmt.Printf("\nSummary: %d ok, %d failed, total %d\n", ok, fail, len(results))
}