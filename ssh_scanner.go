package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// common host key algorithms to try
var algos = []string{
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521",
	"ssh-rsa",           // legacy RSA
	"rsa-sha2-256",      // rsa-sha2-256 (modern)
	"rsa-sha2-512",      // rsa-sha2-512 (modern)
	"ssh-dss",           // DSA (rare/old)
}

type KeyInfo struct {
	Algo        string
	Fingerprint string
	OpenSSH     string
}

func fingerprintSHA256(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return base64.StdEncoding.EncodeToString(h[:])
}

// tryAlgo attempts an SSH handshake forcing a single host-key algorithm.
// It returns the public key presented by the server (if any).
func tryAlgo(addr string, algo string, timeout time.Duration) (ssh.PublicKey, error) {
	var captured ssh.PublicKey
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		captured = key
		// accept it (we're just enumerating)
		return nil
	}

	config := &ssh.ClientConfig{
		User:              "invalid", // no auth required for key exchange / host-key callback
		Auth:              []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: []string{algo},
		Timeout:           timeout,
	}

	// Dial TCP first to apply timeout for TCP connect
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	// set deadline so handshake won't hang
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	// Perform SSH handshake; we don't need a full client — NewClientConn performs handshake
	_, _, _, err = ssh.NewClientConn(conn, addr, config)
	// ssh.NewClientConn will likely return an error because auth will fail,
	// but the HostKeyCallback runs during the handshake so `captured` may be set.
	// We ignore the error here and just return captured key (or error if none).
	_ = conn.Close()

	if captured == nil {
		// return the error from NewClientConn if no key was captured
		return nil, err
	}
	return captured, nil
}

func scanHost(host string, timeout time.Duration) ([]KeyInfo, error) {
	addr := net.JoinHostPort(host, "22")
	var mu sync.Mutex
	found := map[string]KeyInfo{} // fingerprint -> KeyInfo (dedupe)
	var wg sync.WaitGroup

	for _, algo := range algos {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			key, err := tryAlgo(addr, a, timeout)
			if err != nil {
				// ignore negotiation failures; they're expected when algo unsupported
				return
			}
			if key == nil {
				return
			}
			fp := fingerprintSHA256(key)
			pub := string(ssh.MarshalAuthorizedKey(key)) // OpenSSH public key line (with newline)
			info := KeyInfo{
				Algo:        a,
				Fingerprint: "SHA256:" + fp,
				OpenSSH:     pub,
			}
			mu.Lock()
			// dedupe by fingerprint
			if _, ok := found[fp]; !ok {
				found[fp] = info
			}
			mu.Unlock()
		}(algo)
	}

	wg.Wait()
	// convert map to slice
	out := make([]KeyInfo, 0, len(found))
	for _, v := range found {
		out = append(out, v)
	}
	return out, nil
}

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "timeout for each handshake")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] host1 host2 ...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	hosts := flag.Args()
	if len(hosts) == 0 {
		fmt.Println("Please provide at least one host (IP or hostname).")
		flag.Usage()
		os.Exit(1)
	}

	for _, h := range hosts {
		fmt.Printf("Scanning %s:22 ...\n", h)
		keys, err := scanHost(h, *timeout)
		if err != nil {
			fmt.Printf("  error scanning host %s: %v\n", h, err)
			continue
		}
		if len(keys) == 0 {
			fmt.Printf("  no host keys detected (server may not support the tested algorithms or connection failed)\n")
			continue
		}
		for i, k := range keys {
			fmt.Printf("  Key #%d\n", i+1)
			fmt.Printf("    Algorithm : %s\n", k.Algo)
			fmt.Printf("    Fingerprint: %s\n", k.Fingerprint)
			fmt.Printf("    OpenSSH    : %s", k.OpenSSH) // already contains newline
		}
	}
}