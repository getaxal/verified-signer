//go:build !linux
// +build !linux

package vsock

import (
	"fmt"
	"net"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

// errUnimplemented is returned by all functions on platforms that
// cannot make use of VM sockets.
var errUnimplemented = fmt.Errorf("vsock: not implemented on %s", runtime.GOOS)

type Config struct{}

func Listen(port uint32, cfg *Config) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}

func Dial(contextID, port uint32, cfg *Config) (net.Conn, error) {
	d := net.Dialer{Timeout: time.Second * 10}
	conn, err := d.Dial("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("try connect localhost -> %d failed: %s\n", port, err.Error())
		return nil, err
	}
	log.Printf("connected: %s -> %d\n", conn.RemoteAddr(), port)
	return conn, nil
}
