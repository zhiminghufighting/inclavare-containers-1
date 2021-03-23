package main // import "github.com/inclavare-containers/inclavared"

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls
#cgo LDFLAGS: -L../build/lib -L/opt/intel/sgxsdk/lib64 -Llib -lra-tls-server -l:libcurl-wolfssl.a -l:libwolfssl.a -lsgx_uae_service -lsgx_urts -lz -lm
#ifdef RATLS_ECDSA
#cgo LDFLAGS: -lsgx_dcap_ql
#endif

#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"

extern int ra_tls_server_startup(sgx_enclave_id_t id, int sockfd);
extern int ra_tls_server_startup_protocol(sgx_enclave_id_t id, int connd, unsigned char* sendmsg, unsigned int sendmsglen);

static sgx_enclave_id_t load_enclave(void)
{
	sgx_launch_token_t t;
        memset(t, 0, sizeof(t));

        sgx_enclave_id_t id;
        int updated = 0;
        int ret = sgx_create_enclave("Wolfssl_Enclave.signed.so", 1, &t, &updated, &id, NULL);
        if (ret != SGX_SUCCESS) {
                fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
                return -1;
        }

	return id;
}
*/
import "C"
import (
	"fmt"
	"github.com/urfave/cli"
	"encoding/json"
	"net"
	"syscall"
	"unsafe"
)

const (
	defaultAddress = "/run/rune/ra-tls.sock"
)

type EnclaveInfo struct{
        Id string               `json:"string_id,omitempty"`
        Msgtype string          `json:"string_type,omitempty"`
        Version uint8           `json:"uint8_version,omitempty"`
        Mrenclave [32]byte      `json:"byte_mrenclave,omitempty"`
        Mrsigner  [32]byte      `json:"byte_mrsigner,omitempty"`
}

var runCommand = cli.Command{
	Name:  "run",
	Usage: "run the inclavared",
	ArgsUsage: `[command options]

EXAMPLE:

       # shelterd-shim-agent run &`,
	Flags: []cli.Flag{
		/*
			cli.IntFlag{
				Name:        "port",
				Value:       listeningPort,
				Usage:       "listening port for receiving external requests",
				Destination: &listeningPort,
			},
		*/
		cli.StringFlag{
			Name:  "addr",
			Usage: "the timeout in second for re-establishing the connection to inclavared",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		eid := C.load_enclave()

		addr := cliContext.String("addr")
		if addr == "" {
			addr = defaultAddress
		}

		syscall.Unlink(addr)

		ln, err := net.Listen("unix", addr)
		if err != nil {
			return err
		}
		defer ln.Close()

		unixListener, ok := ln.(*net.UnixListener)
		if !ok {
			return fmt.Errorf("casting to UnixListener failed")
		}

		unixListener.SetUnlinkOnClose(false)
		defer unixListener.SetUnlinkOnClose(true)

		c, err := unixListener.Accept()
		if err != nil {
			return err
		}
		defer c.Close()

		conn, ok := c.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		connFile, err := conn.File()
		if err != nil {
			return err
		}
		defer connFile.Close()
		sendCmd := EnclaveInfo{
                        Id: "00001",
                        Msgtype: "GETENCLAVEINFO",
                        Version: 1,
                        Mrenclave:[32]byte{0x01,0x02,0x03,0x04,0x05, 0x06,0x07, 0x08, 0x09,0x10, 0x11, 0x12, 0x13,0x14, 0x15,0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31},
                        Mrsigner: [32]byte{0x01,0x02,0x03,0x04,0x05, 0x06,0x07, 0x08, 0x09,0x10, 0x11, 0x12, 0x13,0x14, 0x15,0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32},
                }
                sendmsg , err := json.Marshal(sendCmd)
                if err != nil{
                        fmt.Printf("json marshal filed, err is %s.\n", err)
                }
                sendmsglen := (uint)(len(sendmsg))
		data := make([]byte, sendmsglen)
		data = sendmsg

		//C.ra_tls_server_startup(eid, C.int(connFile.Fd()))
		C.ra_tls_server_startup_protocol(eid, C.int(connFile.Fd()), (*C.uchar)((unsafe.Pointer)(&data[0])), (C.uint)(sendmsglen))
		return nil
	},
}
