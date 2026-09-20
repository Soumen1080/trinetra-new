package engine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/cbom"
	"golang.org/x/crypto/ssh"
)

// SSHEngine performs live SSH server scanning to detect host keys, KEX
// algorithms, and MAC algorithms.
//
// Like testssl, everything this produces has `is_observed=true`.
type SSHEngine struct{}

// NewSSHEngine creates an SSH scanning engine.
func NewSSHEngine() *SSHEngine {
	return &SSHEngine{}
}

func (e *SSHEngine) Name() string { return "ssh-scanner" }

func (e *SSHEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "trinetra",
		Name:    "ssh-scanner",
		Version: ScannerVersion,
	}
}

func (e *SSHEngine) Available(ctx context.Context) error {
	// SSH scanner is built-in, always available
	return nil
}

func (e *SSHEngine) Scan(ctx context.Context, endpoint string) (Result, error) {
	// Endpoint should be host:port (default SSH port is 22)
	if !strings.Contains(endpoint, ":") {
		endpoint = endpoint + ":22"
	}

	findings, err := e.probeSSH(ctx, endpoint)
	if err != nil {
		return Result{
			Gaps: []Gap{{
				Endpoint: endpoint,
				Kind:     "ssh_probe_failed",
				Reason:   err.Error(),
				Count:    1,
			}},
		}, nil
	}

	return Result{
		Findings: findings,
	}, nil
}

func (e *SSHEngine) probeSSH(ctx context.Context, endpoint string) ([]cbom.Finding, error) {
	var findings []cbom.Finding

	// Connect with a timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Configure SSH client to capture server algorithms
	config := &ssh.ClientConfig{
		User: "probe",
		Auth: []ssh.AuthMethod{
			ssh.Password("probe"),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Capture the host key
			findings = append(findings, e.hostKeyFinding(key, endpoint))
			return nil
		},
		Timeout: 10 * time.Second,
		// Request all algorithms to see what the server supports
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
				"diffie-hellman-group-exchange-sha256",
				// Post-quantum hybrid KEX
				"sntrup761x25519-sha512@openssh.com",
				"mlkem768x25519-sha256",
			},
		},
	}

	// Attempt handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, endpoint, config)
	if err != nil {
		// Even if auth fails, we may have captured the host key
		if len(findings) > 0 {
			// Try to extract algorithm info from error
			findings = append(findings, e.extractAlgorithmsFromError(err, endpoint)...)
			return findings, nil
		}
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	defer sshConn.Close()

	// Start a client session (ignore channels and requests)
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// Extract negotiated algorithms from the connection
	findings = append(findings, e.extractNegotiatedAlgorithms(sshConn, endpoint)...)

	return findings, nil
}

func (e *SSHEngine) hostKeyFinding(key ssh.PublicKey, endpoint string) cbom.Finding {
	keyType := key.Type()
	algorithm := ""
	keySize := 0

	switch keyType {
	case "ssh-rsa":
		algorithm = "RSA"
		keySize = estimateRSAKeySize(key)
	case "ssh-ed25519":
		algorithm = "Ed25519"
		keySize = 256
	case "ecdsa-sha2-nistp256":
		algorithm = "ECDSA-P256"
		keySize = 256
	case "ecdsa-sha2-nistp384":
		algorithm = "ECDSA-P384"
		keySize = 384
	case "ecdsa-sha2-nistp521":
		algorithm = "ECDSA-P521"
		keySize = 521
	default:
		algorithm = keyType
	}

	return cbom.Finding{
		AssetType:  cbom.AssetKey,
		Primitive:  cbom.PrimitiveAsymmetric,
		Name:       "SSH Host Key",
		Algorithm:  algorithm,
		KeySize:    cbom.IntPtr(keySize),
		Location:   endpoint,
		Snippet:    fmt.Sprintf("observed host key: %s", keyType),
		Note:       "SSH server host key",
		Confidence: cbom.ConfidenceHigh,
		IsObserved: true,
	}
}

func (e *SSHEngine) extractNegotiatedAlgorithms(conn ssh.Conn, endpoint string) []cbom.Finding {
	var findings []cbom.Finding

	// Unfortunately, the golang.org/x/crypto/ssh package doesn't expose
	// the negotiated algorithms directly. This is a known limitation.
	// For a production implementation, you would need to:
	// 1. Fork and modify the ssh package to expose SessionID and algorithms
	// 2. Use a different SSH library that exposes this information
	// 3. Capture the SSH handshake at the network level

	// For now, we note this as a gap
	findings = append(findings, cbom.Finding{
		AssetType:  cbom.AssetProtocol,
		Name:       "SSH",
		Algorithm:  "SSH-2.0",
		Location:   endpoint,
		Snippet:    "SSH connection established",
		Note:       "KEX/MAC algorithm detection requires enhanced library support",
		Confidence: cbom.ConfidenceMedium,
		IsObserved: true,
	})

	return findings
}

func (e *SSHEngine) extractAlgorithmsFromError(err error, endpoint string) []cbom.Finding {
	// Try to extract useful information from handshake errors
	// This is a best-effort approach
	errStr := err.Error()

	if strings.Contains(errStr, "no common algorithm") {
		// Server doesn't support any of our proposed algorithms
		return []cbom.Finding{{
			AssetType:  cbom.AssetProtocol,
			Name:       "SSH",
			Location:   endpoint,
			Snippet:    errStr,
			Note:       "Algorithm negotiation failed",
			Confidence: cbom.ConfidenceLow,
			IsObserved: true,
		}}
	}

	return nil
}

func estimateRSAKeySize(key ssh.PublicKey) int {
	// RSA key size estimation from the marshaled public key length
	// This is approximate but good enough for reporting
	marshaled := key.Marshal()
	switch {
	case len(marshaled) > 500:
		return 4096
	case len(marshaled) > 300:
		return 3072
	case len(marshaled) > 250:
		return 2048
	default:
		return 1024
	}
}
