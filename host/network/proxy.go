package network

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	networking "github.com/getaxal/verified-signer/common/network"
	vsockproxy "github.com/getaxal/verified-signer/common/vsock/proxy"

	log "github.com/sirupsen/logrus"
)

// This function listens to the Vsock port provided and forwards the traffic to the TCP port provided. it will forward all traffic from this vsock port to
// the URL provided.
func InitVsockToTcpProxy(ctx context.Context, vsockPort uint32, tcpPort uint32, forwardUrl string) {
	log.Infof("Listening to vsock at port: %v", vsockPort)
	log.Infof("Forwarding tcp to %s:%v", forwardUrl, tcpPort)
	vsockproxy.NewVsockProxy(ctx, forwardUrl, tcpPort, vsockPort)
}

// This function listens to the TCP port provided and forwards the network call into the Vsock port provided.
func InitTcpToVsockProxy(ctx context.Context, tcpPort uint32, vsockPort uint32) {
	log.Infof("Listening to tcp at port: %d", tcpPort)
	log.Infof("Forwarding to vsock at port: %d", vsockPort)

	vsockproxy.NewProxy(ctx, tcpPort, 5, vsockPort)
}

// SimpleHTTPToVsockProxy - minimal proxy that forwards HTTP requests to vsock
func InitSimpleHTTPToVsockProxy(ctx context.Context, tcpPort uint32, vsockPort uint32, enclaveCID uint32) {
	// Create the vsock HTTP client
	vsockClient := networking.InitHttpClientWithVsockTransportHost(vsockPort, enclaveCID)

	// Create handler that forwards all requests
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a new request for the vsock client
		proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy all headers
		proxyReq.Header = r.Header.Clone()

		// Forward the request through vsock
		resp, err := vsockClient.Do(proxyReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for k, v := range resp.Header {
			w.Header()[k] = v
		}

		// Write status code
		w.WriteHeader(resp.StatusCode)

		// Copy response body
		io.Copy(w, resp.Body)
	})

	// Create and start the server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", tcpPort),
		Handler: handler,
	}

	go func() {
		log.Infof("Starting HTTP to Vsock proxy on port %d -> vsock %d:%d", tcpPort, enclaveCID, vsockPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Server error: %v", err)
		}
	}()

	// Handle graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()
}
