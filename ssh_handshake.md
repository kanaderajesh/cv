# SSH Handshake Checker

A fast, concurrent SSH handshake validation tool written in Go using Cobra.  
This tool reads a list of IP addresses from a JSON file and attempts **only SSH handshakes** using an **unencrypted** private key.  
It does **not execute commands**, making it safe for fleet connectivity auditing.

---

## Features

| Feature | Description |
|--------|-------------|
| ✅ Bulk test SSH connectivity | Reads multiple hosts from a JSON list |
| ✅ No command execution | Only verifies SSH handshake success |
| ✅ Concurrency support | Scans large fleets quickly |
| ✅ Retry with delay | Handles transient network failures |
| ✅ Output formats | `text`, `json`, `csv` |
| ✅ Optional progress bar | Useful for large scans |
| ✅ IPv4 & IPv6 supported | Auto-detect address format |

---

## Requirements

- **Go 1.20+**
- **Private key must NOT have a passphrase**

If your key is encrypted, remove passphrase:

```bash
openssl rsa -in id_rsa_encrypted -out id_rsa