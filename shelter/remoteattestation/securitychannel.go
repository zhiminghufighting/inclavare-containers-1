package remoteattestation

/*
#cgo CFLAGS:  -I/opt/intel/sgxsdk/include
#cgo CFLAGS:  -I../../ra-tls/build/include
#cgo LDFLAGS: -L../../ra-tls/build/lib
#cgo LDFLAGS: -l:libra-challenger.a -l:libwolfssl.a -lm
#ifdef RATLS_ECDSA
#cgo LDFLAGS:  -lsgx_dcap_quoteverify -lsgx_urts -lpthread -ldl -lsgx_dcap_ql
#endif

extern int ra_tls_echo(int sockfd, unsigned char* mrenclave, unsigned char* mrsigner);
extern int ra_tls_enc_protocol(int sockfd, unsigned char* sendmsg, unsigned int sendmsglen, unsigned char* retmsg, unsigned int* recemsglen);
*/
import "C"
import (
	"fmt"
	"net"
	"unsafe"
)

const (
	defaultsockAddress = "/run/rune/ra-tls.sock"
	defaulttcpAddress  = "0.0.0.0:3443"
)

//for local tcp connection
func RemoteTlsSetupTCP(address string, mrenclave unsafe.Pointer, mrsigner unsafe.Pointer) error {
	addr := address
	if addr == "" {
		addr = defaulttcpAddress
	}

	conn, err := net.Dial("tcp", addr)
	fmt.Printf("net dail tcp socket.\n")
	if err != nil {
		return fmt.Errorf("tcp connection failed with err %s.\n", err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("casting to UnixConn failed.\n")
	}

	sockfd, err := tcpConn.File()
	if err != nil {
		return err
	}
	C.ra_tls_echo(C.int(sockfd.Fd()), (*C.uchar)(mrenclave), (*C.uchar)(mrsigner))
	return nil
}

//for local unix socket connection
func RemoteTlsSetupSock(address string, mrenclave unsafe.Pointer, mrsigner unsafe.Pointer) error {
	addr := address
	if addr == "" {
		addr = defaultsockAddress
	}

	conn, err := net.Dial("unix", addr)
	if err != nil {
		return fmt.Errorf("unix connection failed with err %s.\n", err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("casting to UnixConn failed.\n")
	}

	sockfd, err := unixConn.File()
	if err != nil {
		return err
	}
	C.ra_tls_echo(C.int(sockfd.Fd()), (*C.uchar)(mrenclave), (*C.uchar)(mrsigner))
	return nil
}

//for manage porotol debug purpuse
func RemoteTlsSetupSockProtocol(address string, sendmsg unsafe.Pointer, sendmsglen uint, retmsg unsafe.Pointer, recemsglen unsafe.Pointer) error {
        addr := address
        if addr == "" {
                addr = defaultsockAddress
        }

        conn, err := net.Dial("unix", addr)
        if err != nil {
                return fmt.Errorf("unix connection failed with err %s.\n", err)
        }
        defer conn.Close()

        unixConn, ok := conn.(*net.UnixConn)
        if !ok {
                return fmt.Errorf("casting to UnixConn failed.\n")
        }

        sockfd, err := unixConn.File()
        if err != nil {
                return err
        }
        C.ra_tls_enc_protocol(C.int(sockfd.Fd()), (*C.uchar)(sendmsg), (C.uint)(sendmsglen), (*C.uchar)(retmsg), (*C.uint)(recemsglen))
        return nil
}

