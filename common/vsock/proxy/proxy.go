package vsockproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/axal/verified-signer-common/vsock"

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
	log.Infof("Source: %v -> Destination: %v", source.RemoteAddr(), destination.RemoteAddr())

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

func NewProxy(context context.Context, localPort, remoteCid, remotePort uint32) {
	log.Info("new proxy", " localPort", localPort, " remoteCid", remoteCid, " remotePort", remotePort)
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

// This is for the host, it listens to the vsock and forwards anything to the tcp endpoint. Local port is the vsock port, while the remote port
// is the port of the remote url
func NewVsockProxy(context context.Context, remoteHost string, remotePort uint32, localPort uint32) {
	local, err := vsock.Listen(localPort, nil)
	if err != nil {
		log.Error(fmt.Sprintf("NewVsockProxy fail to listen :%d,error:%v", localPort, err))
		return
	}
	for {
		conn, err := local.Accept()
		log.Infof("Accepted connection from vsock")
		if err != nil {
			log.Errorf("NewVsockProxy Accept failed,localPort %d error: %s", localPort, err.Error())
			return
		}
		// log.Printf("conn Accept,local:%s,remote :%s", local.Addr().String(), conn.RemoteAddr().String())

		go handleVsock(context, conn, remoteHost, remotePort)

	}
}

// This listens to the all tcp connections at a specific port and forwards it to the vsock. In this function,
// the remotePort is the port of the vsock and the localPort is the port at which we want the enclave to listen to for tcp connections.
// For example, if the enclave is sending a tcp connection accross http to example.com, the local port is 80(http) and the remotePort is the port of the vsock.
// remoteCid should be 3.
func NewSocat(context context.Context, remoteCid uint32, remotePort uint32, localPort uint32) {
	local, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		log.Error(fmt.Sprintf("NewSocat fail to listen :%d,error:%v", localPort, err))
		return
	}
	for {
		conn, err := local.Accept()
		if err != nil {
			log.Errorf("NewSocat Accept failed,localPort %d error: %s", localPort, err.Error())
			return
		}
		// log.Printf("conn Accept,local:%s,remote :%s", local.Addr().String(), conn.RemoteAddr().String())
		go handle(context, conn, remoteCid, remotePort)
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
