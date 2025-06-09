package network

import (
	"crypto/tls"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// This function initiates a custom HTTPS client that uses a vsock port to route its message to the server. Each Client can only be used for one url.
// vsockPort is the port at which requests are routed to. The servername is used for all TLS certifiate verification.
func InitHttpsClientWithTLSVsockTransport(vsockPort uint32, servername string) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: servername,
	}

	transport := &VsockHTTPSRoundTripper{
		CID:       3, // Host CID
		Port:      vsockPort,
		TLSConfig: tlsConfig,
	}

	log.Infof("HTTPS client initialized for server:%s with TLS VSock transport on port %d", servername, vsockPort)

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// This function initiates a custom HTTP client that uses a vsock port to route its message to the server. Each Client can only be used for one url.
// vsockPort is the port at which requests are routed to.
func InitHttpClientWithVsockTransport(vsockPort uint32) *http.Client {
	transport := &VsockHTTPRoundTripper{
		CID:  3, // Host CID
		Port: vsockPort,
	}

	log.Infof("HTTP client initialized for with VSock transport on port %d", vsockPort)

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}
