package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

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

	// Add timeout to context if not present
	ctx := req.Context()
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req = req.WithContext(ctx)
	}

	// Dial vsock connection
	conn, err := vsock.Dial(v.CID, v.Port, &vsock.Config{})
	if err != nil {
		log.Errorf("Unable to connect to vsock port %d: %v", v.Port, err)
		return nil, err
	}

	// Set ServerName based on the request's host if not already set
	tlsConfig := v.TLSConfig
	if tlsConfig.ServerName == "" {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.ServerName = req.URL.Host
	}

	// Create TLS connection
	tlsConn := tls.Client(conn, tlsConfig)

	// Set deadline on the connection if we have one
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}

	// Perform TLS handshake with timeout
	if err := v.handshakeWithTimeout(ctx, tlsConn); err != nil {
		log.Errorf("TLS handshake failed: %v", err)
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	log.Infof("TLS handshake successful, sending HTTP request")

	// Send HTTP request over TLS connection
	if err := req.Write(tlsConn); err != nil {
		log.Errorf("Failed to write request over TLS: %v", err)
		tlsConn.Close()
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read HTTP response over TLS
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		log.Errorf("Failed to read response over TLS: %v", err)
		tlsConn.Close()
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// CRITICAL FIX: Wrap the response body to handle connection cleanup
	// Don't close the connection here - let the response body handle it
	resp.Body = &connectionAwareBody{
		ReadCloser: resp.Body,
		conn:       tlsConn,
	}

	log.Infof("Successfully received HTTP response, status: %d", resp.StatusCode)
	return resp, nil
}

// Helper function to perform TLS handshake with timeout
func (v *VsockTLSRoundTripper) handshakeWithTimeout(ctx context.Context, tlsConn *tls.Conn) error {
	type result struct {
		err error
	}

	resultChan := make(chan result, 1)

	go func() {
		err := tlsConn.Handshake()
		resultChan <- result{err: err}
	}()

	select {
	case res := <-resultChan:
		return res.err
	case <-ctx.Done():
		return fmt.Errorf("TLS handshake timeout: %w", ctx.Err())
	}
}

// connectionAwareBody wraps the response body and ensures the connection is closed
type connectionAwareBody struct {
	io.ReadCloser
	conn *tls.Conn
}

func (cab *connectionAwareBody) Close() error {
	// Close the response body first
	bodyErr := cab.ReadCloser.Close()

	// Then close the TLS connection
	connErr := cab.conn.Close()

	// Return the first error encountered
	if bodyErr != nil {
		log.Errorf("Error closing response body: %v", bodyErr)
		return bodyErr
	}
	if connErr != nil {
		log.Errorf("Error closing TLS connection: %v", connErr)
		return connErr
	}

	log.Infof("Successfully closed response body and TLS connection")
	return nil
}
