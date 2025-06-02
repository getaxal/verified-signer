package vsockproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/getaxal/verified-signer/common/vsock"

	log "github.com/sirupsen/logrus"
)

func handle(context context.Context, conn net.Conn, remoteCid, remotePort uint32) {
	proxy, err := vsock.Dial(remoteCid, remotePort, nil)
	//log.Printf("proxy Dial remoteCid:%d , remotePort:%d, error:%v", remoteCid, remotePort, err)
	if err != nil {
		log.Error(errors.New("handle failed to connect" + err.Error()))
		return
	}

	go forward(context, conn, proxy, true)
	go forward(context, proxy, conn, false)
}

func forward(context context.Context, source, destination net.Conn, close bool) {
	// log.Infof("Source: %v -> Destination: %v", source.RemoteAddr(), destination.RemoteAddr())

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("forward RemoteAddr:%s,LocalAddr:%s,error:%v", source.RemoteAddr(), source.LocalAddr(), r)
		}
	}()
	if close {
		defer func() {
			log.Printf("close connection,source:%s,target:%s", source.LocalAddr(), destination.RemoteAddr())
			source.Close()
			destination.Close()
		}()
	}
	io.Copy(destination, source)
}

// This function listens to the TCP port and forwards traffic to the vsock port. The tcp port is the localport and the remote port is the vsock port.
func NewProxy(context context.Context, localPort, remoteCid, remotePort uint32) {
	local, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		log.Error(fmt.Sprintf("NewProxy fail to listen :%d,error:%v", localPort, err))
		return
	}
	for {
		conn, err := local.Accept()
		if err != nil {
			log.Errorf("NewProxy Accept failed,localPort %d error: %s", localPort, err.Error())
			return
		}
		//log.Printf("conn Accept,local:%s,remote :%s", local.Addr().String(), conn.RemoteAddr().String())
		go handle(context, conn, remoteCid, remotePort)
	}
}

// This listens to the vsock and forwards anything to the tcp endpoint. Local port is the vsock port, while the remote port
// is the port of the remote url
func NewVsockProxy(context context.Context, remoteHost string, remotePort uint32, localPort uint32) {
	local, err := vsock.Listen(localPort, nil)
	if err != nil {
		log.Error(fmt.Sprintf("NewVsockProxy fail to listen :%d,error:%v", localPort, err))
		return
	}
	for {
		conn, err := local.Accept()
		// log.Infof("Accepted connection from vsock")
		if err != nil {
			log.Errorf("NewVsockProxy Accept failed,localPort %d error: %s", localPort, err.Error())
			return
		}
		// log.Printf("conn Accept,local:%s,remote :%s", local.Addr().String(), conn.RemoteAddr().String())

		go handleVsock(context, conn, remoteHost, remotePort)

	}
}

func handleVsock(context context.Context, conn net.Conn, remoteHost string, remotePort uint32) {
	hostname := remoteHost
	if strings.HasPrefix(hostname, "https://") {
		hostname = strings.TrimPrefix(hostname, "https://")
	} else if strings.HasPrefix(hostname, "http://") {
		hostname = strings.TrimPrefix(hostname, "http://")
	}

	log.Infof("Connecting to %s:%d", hostname, remotePort)
	proxy, err := net.Dial("tcp", net.JoinHostPort(hostname, fmt.Sprintf("%d", remotePort)))
	if err != nil {
		log.Error(errors.New("handle failed to connect" + err.Error()))
		return
	}
	go forward(context, conn, proxy, true)
	go forward(context, proxy, conn, false)
}
