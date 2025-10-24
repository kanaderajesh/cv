// ssh-runner.go
//
// Usage examples:
//   ./ssh-runner -nodes nodes.txt -cmds cmds.txt -user ubuntu -keyfile ~/.ssh/id_rsa -concurrency 10 -outdir results
//   ./ssh-runner -nodes nodes.txt -cmds cmds.txt -user ec2-user -keyenv SSH_KEY -vault "vaultAddr=https://vault.example:8200,token=..." -concurrency 5
//
// Notes:
//  - Nodes file: one hostname or IP per line (optionally with :port -> host:port).
//  - Commands file: one command per line.
//  - Private key sources: -keyfile (path), -keyenv (env var name contains PEM), or -vault (vault details follow simple format documented below).
//  - If multiple commands are given they will be executed sequentially on each node (but nodes execute in parallel up to concurrency limit).
//
// Vault usage (simple): -vault "addr=https://vault:8200,token=MYTOKEN,secret=secret/data/ssh-key,field=data.key"
//
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	// optional vault client; only used if vault option provided
	vault "github.com/hashicorp/vault/api"
)

var (
	nodesFile   = flag.String("nodes", "", "File containing node list (one host or host:port per line)")
	cmdsFile    = flag.String("cmds", "", "File containing commands (one command per line)")
	userFlag    = flag.String("user", "", "SSH user (required unless nodes file entries include user@host)")
	keyFile     = flag.String("keyfile", "", "Private key file path (PEM). Mutually exclusive with -keyenv and -vault")
	keyEnv      = flag.String("keyenv", "", "Environment variable name that holds PEM private key")
	vaultFlag   = flag.String("vault", "", "Vault fetch config string (e.g. addr=...,token=...,secret=secret/data/ssh-key,field=data.key)")
	outDir      = flag.String("outdir", "results", "Output directory to write command outputs")
	concurrency = flag.Int("concurrency", 10, "Max concurrent SSH sessions")
	portFlag    = flag.Int("port", 22, "Default SSH port to use if not specified with host:port")
	timeoutSec  = flag.Int("timeout", 30, "SSH command timeout in seconds")
	keepConn    = flag.Bool("keep-connection", true, "Keep a single SSH session per node for all commands (recommended)")
	quiet       = flag.Bool("quiet", false, "Reduce stdout log output")
)

func main() {
	flag.Parse()

	if *nodesFile == "" || *cmdsFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -nodes and -cmds are required")
		flag.Usage()
		os.Exit(2)
	}

	if *keyFile == "" && *keyEnv == "" && *vaultFlag == "" {
		fmt.Fprintln(os.Stderr, "ERROR: one of -keyfile, -keyenv or -vault must be provided")
		flag.Usage()
		os.Exit(2)
	}

	if *outDir == "" {
		*outDir = "results"
	}

	if !*quiet {
		fmt.Printf("Loading nodes from %s, commands from %s\n", *nodesFile, *cmdsFile)
	}

	nodes, err := loadLines(*nodesFile)
	exitOnErr(err, "loading nodes")
	cmds, err := loadLines(*cmdsFile)
	exitOnErr(err, "loading commands")
	if len(nodes) == 0 {
		exitOnErr(errors.New("no nodes found"), "nodes file empty")
	}
	if len(cmds) == 0 {
		exitOnErr(errors.New("no commands found"), "commands file empty")
	}

	// ensure outdir exists
	err = os.MkdirAll(*outDir, 0o755)
	exitOnErr(err, "creating output directory")

	// load key
	var signer ssh.Signer
	if *keyFile != "" {
		b, err := ioutil.ReadFile(expandPath(*keyFile))
		exitOnErr(err, "reading keyfile")
		signer, err = ssh.ParsePrivateKey(b)
		exitOnErr(err, "parsing private key from file")
	} else if *keyEnv != "" {
		val := os.Getenv(*keyEnv)
		if val == "" {
			exitOnErr(fmt.Errorf("environment variable %s is empty", *keyEnv), "loading key from env")
		}
		signer, err = ssh.ParsePrivateKey([]byte(val))
		exitOnErr(err, "parsing private key from env")
	} else {
		// vault
		pem, err := fetchKeyFromVault(*vaultFlag)
		exitOnErr(err, "fetching key from vault")
		signer, err = ssh.ParsePrivateKey([]byte(pem))
		exitOnErr(err, "parsing private key from vault")
	}

	// create SSH client config template
	sshConfig := &ssh.ClientConfig{
		User:            *userFlag,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // NOTE: for production, replace with proper host key verification
		Timeout:         time.Duration(*timeoutSec) * time.Second,
	}

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var overallErrs int64
	var mu sync.Mutex

	for _, rawNode := range nodes {
		node := strings.TrimSpace(rawNode)
		if node == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(node string) {
			defer wg.Done()
			defer func() { <-sem }()

			user, host, port := parseNode(node)
			config := *sshConfig // copy
			if user != "" {
				config.User = user
			} else if config.User == "" {
				// fallback
				exitOnErr(errors.New("no user provided via -user and nodes are not user@host"), "determining SSH user")
			}

			address := fmt.Sprintf("%s:%d", host, port)
			if !*quiet {
				fmt.Printf("[node] %s -> connect %s@%s\n", node, config.User, address)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
			defer cancel()

			// Create SSH client
			client, err := sshDialContext(ctx, "tcp", address, &config)
			if err != nil {
				mu.Lock()
				overallErrs++
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "ERROR: failed to connect to %s: %v\n", node, err)
				return
			}
			defer client.Close()

			if *keepConn {
				// run commands sequentially using the same client
				for i, cmd := range cmds {
					if strings.TrimSpace(cmd) == "" {
						continue
					}
					out, err := runCommandWithSession(ctx, client, cmd)
					saveErr := saveOutput(*outDir, node, cmd, out, i)
					if err != nil {
						fmt.Fprintf(os.Stderr, "ERROR: node=%s cmd=%q: %v\n", node, cmd, err)
						mu.Lock()
						overallErrs++
						mu.Unlock()
					}
					if saveErr != nil {
						fmt.Fprintf(os.Stderr, "ERROR: saving output for node=%s cmd=%q: %v\n", node, cmd, saveErr)
					}
				}
			} else {
				// create/close session per command (less efficient)
				var innerWg sync.WaitGroup
				for i, cmd := range cmds {
					i := i
					cmd := cmd
					if strings.TrimSpace(cmd) == "" {
						continue
					}
					innerWg.Add(1)
					go func() {
						defer innerWg.Done()
						ctx2, cancel2 := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
						defer cancel2()
						out, err := runCommandClient(ctx2, address, &config, cmd)
						saveErr := saveOutput(*outDir, node, cmd, out, i)
						if err != nil {
							fmt.Fprintf(os.Stderr, "ERROR: node=%s cmd=%q: %v\n", node, cmd, err)
							mu.Lock()
							overallErrs++
							mu.Unlock()
						}
						if saveErr != nil {
							fmt.Fprintf(os.Stderr, "ERROR: saving output for node=%s cmd=%q: %v\n", node, cmd, saveErr)
						}
					}()
				}
				innerWg.Wait()
			}

		}(node)
	}
	wg.Wait()

	if overallErrs > 0 {
		fmt.Fprintf(os.Stderr, "Completed with %d errors\n", overallErrs)
		os.Exit(1)
	}

	if !*quiet {
		fmt.Println("All done.")
	}
}

// loadLines reads a file and returns non-empty trimmed lines
func loadLines(path string) ([]string, error) {
	f, err := os.Open(expandPath(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

func exitOnErr(err error, context string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "FATAL (%s): %v\n", context, err)
	os.Exit(2)
}

// parseNode possibly extracts user@host:port
func parseNode(s string) (user, host string, port int) {
	port = *portFlag
	in := s
	// user@host:port or host:port or user@host
	if strings.Contains(in, "@") {
		parts := strings.SplitN(in, "@", 2)
		user = parts[0]
		in = parts[1]
	}
	if strings.Contains(in, ":") {
		parts := strings.SplitN(in, ":", 2)
		host = parts[0]
		p := parts[1]
		if p != "" {
			if parsed, err := strconvAtoi(p); err == nil {
				port = parsed
			}
		}
	} else {
		host = in
	}
	return
}

// strconvAtoi wraps strconv.Atoi but avoids import name in top list
func strconvAtoi(s string) (int, error) {
	return strconv.Atoi(s)
}

var invalidFileChar = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "empty"
	}
	// replace whitespace and unsafe characters
	s = invalidFileChar.ReplaceAllString(s, "_")
	// trim length
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

func saveOutput(outdir, node, cmd string, out []byte, cmdIndex int) error {
	nodeName := sanitizeFilename(node)
	cmdName := sanitizeFilename(cmd)
	// create filename: node_cmd.txt  (if same command repeated, append index)
	filename := fmt.Sprintf("%s_%s.txt", nodeName, cmdName)
	if cmdIndex >= 0 {
		// to be deterministic when same command repeats
		filename = fmt.Sprintf("%s_%s_%d.txt", nodeName, cmdName, cmdIndex)
	}
	path := filepath.Join(outdir, filename)
	return ioutil.WriteFile(path, out, 0o644)
}

// runCommandWithSession runs command using existing *ssh.Client and returns combined stdout+stderr
func runCommandWithSession(ctx context.Context, client *ssh.Client, cmd string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL) // best-effort
		return buf.Bytes(), ctx.Err()
	case err := <-done:
		return buf.Bytes(), err
	}
}

// runCommandClient creates a fresh client, runs a single command, and closes client
func runCommandClient(ctx context.Context, address string, config *ssh.ClientConfig, cmd string) ([]byte, error) {
	client, err := sshDialContext(ctx, "tcp", address, config)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return runCommandWithSession(ctx, client, cmd)
}

// sshDialContext uses context for dialing; fallback to normal ssh.Dial on ordinary timeout
func sshDialContext(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// Upgrade to ssh client connection
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// fetchKeyFromVault interprets a simple config string and fetches PEM from Vault secret path
// Example vaultFlag: "addr=https://vault.local:8200,token=abc,secret=secret/data/ssh-key,field=data.key"
func fetchKeyFromVault(cfg string) (string, error) {
	if cfg == "" {
		return "", errors.New("vault config empty")
	}
	parts := map[string]string{}
	for _, kv := range strings.Split(cfg, ",") {
		if strings.TrimSpace(kv) == "" {
			continue
		}
		p := strings.SplitN(kv, "=", 2)
		if len(p) != 2 {
			continue
		}
		parts[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
	}
	addr := parts["addr"]
	token := parts["token"]
	secretPath := parts["secret"]
	field := parts["field"]
	if addr == "" || token == "" || secretPath == "" || field == "" {
		return "", fmt.Errorf("vault config requires addr, token, secret, and field")
	}
	cfgClient := vault.DefaultConfig()
	cfgClient.Address = addr
	client, err := vault.NewClient(cfgClient)
	if err != nil {
		return "", err
	}
	client.SetToken(token)

	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no data at secret path %s", secretPath)
	}
	// field can be "data.key" nested -> navigate
	value, err := walkMapField(secret.Data, field)
	if err != nil {
		return "", err
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret field %s not a string", field)
	}
	return s, nil
}

func walkMapField(data map[string]interface{}, dotted string) (interface{}, error) {
	parts := strings.Split(dotted, ".")
	var cur interface{} = data
	for _, p := range parts {
		switch m := cur.(type) {
		case map[string]interface{}:
			cur = m[p]
		default:
			return nil, fmt.Errorf("unexpected structure when walking field %s", dotted)
		}
		if cur == nil {
			return nil, fmt.Errorf("field %s not found", dotted)
		}
	}
	return cur, nil
}

//
// imports used at top that weren't explicitly referenced above
//
import (
	"net"
	"strconv"
)