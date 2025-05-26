//go:build linux
// +build linux

package vsock

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// contextID retrieves the local context ID for this system.
func contextID() (uint32, error) {
	f, err := os.Open(devVsock)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	//id, err := unix.IoctlGetInt(int(f.Fd()), unix.IOCTL_VM_SOCKETS_GET_LOCAL_CID)
	//return uint32(id), err
	return unix.IoctlGetUint32(int(f.Fd()), unix.IOCTL_VM_SOCKETS_GET_LOCAL_CID)
}

// isErrno determines if an error a matches UNIX error number.
func isErrno(err error, errno int) bool {
	switch errno {
	case ebadf:
		return err == unix.EBADF
	case enotconn:
		return err == unix.ENOTCONN
	default:
		panicf("vsock: isErrno called with unhandled error number parameter: %d", errno)
		return false
	}
}

func panicf(format string, a ...interface{}) {
	log.Panic(fmt.Sprintf(format, a...))
}
