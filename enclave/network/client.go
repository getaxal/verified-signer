package network

import (
	"crypto/tls"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func InitHttpsClientWithTLSVsockTransport(vsockPort uint32, servername string) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: servername,
	}

	transport := &VsockTLSRoundTripper{
		CID:       3, // Host CID
		Port:      vsockPort,
		TLSConfig: tlsConfig,
	}

	log.Infof("HTTPS client initialized for server:%s with TLS VSock transport on port %d", servername, vsockPort)

	return &http.Client{
		Transport: transport,
	}
}
