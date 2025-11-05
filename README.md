# cv
items sales report for CV
sample input file for portscanenr 
{
  "concurrency": 200,            // (optional) number of parallel workers (default fallback if omitted)
  "default_timeout_ms": 3000,    // (optional) default per-connection timeout in milliseconds
  "hosts": [
    {
      "host": "string",          // hostname or IP to scan (required)
      "ports": ["80","22-25"],   // array of port specs, each either "N" or "start-end" (required)
      "send": "string",          // (optional) probe string to send after connect (e.g. "HEAD / HTTP/1.0\r\n\r\n")
      "timeout_ms": 4000,        // (optional) per-host timeout in milliseconds (overrides default_timeout_ms)
      "tls": false               // (optional) if true perform TLS handshake and collect cert info
    }
  ]
}

scan_config.json
{
  "concurrency": 200,
  "default_timeout_ms": 3000,
  "hosts": [
    {
      "host": "scanme.nmap.org",
      "ports": ["22","80","443"]
    },
    {
      "host": "example.com",
      "ports": ["80","443"],
      "send": "HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n",
      "tls": true,
      "timeout_ms": 4000
    },
    {
      "host": "192.168.1.1",
      "ports": ["22-25", "80-82"]
    }
  ]
}
go build -o tcpscanner scanner.go
Run with explicit config file and output file:
./tcpscanner -config /path/to/scan_config.json -out results.json
go run scanner.go -config scan_config.json -out results.json








