package network

import (
	"bufio"
	"crypto/tls"
	"net/http"

	"github.com/getaxal/verified-signer/common/vsock"
	log "github.com/sirupsen/logrus"
)

type VsockTLSRoundTripper struct {
	CID       uint32
	Port      uint32
	TLSConfig *tls.Config
}

// Implement the round trip function with TLS support.
func (v *VsockTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Ensure we're using HTTPS
	if req.URL.Scheme != "https" {
		req = req.Clone(req.Context())
		req.URL.Scheme = "https"
	}

	log.Infof("Sending HTTPS request to %s via vsock port: %d", req.URL.Host, v.Port)

	// Dial vsock connection
	conn, err := vsock.Dial(v.CID, v.Port, &vsock.Config{})
	if err != nil {
		log.Errorf("Unable to connect to vsock port %d: %v", v.Port, err)
		return nil, err
	}

	// Set ServerName based on the request's host if not already set
	if v.TLSConfig.ServerName == "" {
		v.TLSConfig = v.TLSConfig.Clone()
		v.TLSConfig.ServerName = req.URL.Host
	}

	// Create TLS connection
	tlsConn := tls.Client(conn, v.TLSConfig)
	defer tlsConn.Close()

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Errorf("TLS handshake failed: %v", err)
		conn.Close()
		return nil, err
	}

	// Send HTTP request over TLS connection
	if err := req.Write(tlsConn); err != nil {
		log.Errorf("Failed to write request over TLS: %v", err)
		return nil, err
	}

	// Read HTTP response over TLS
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		log.Errorf("Failed to read response over TLS: %v", err)
		return nil, err
	}

	return resp, nil
}
