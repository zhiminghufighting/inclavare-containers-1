package main

import (
	"fmt"
	"github.com/inclavare-containers/shelter/remoteattestation"
	"github.com/inclavare-containers/shelter/utils"
	"github.com/urfave/cli"
	"encoding/json"
	"unsafe"
)

var (
	remoteMrenclave [utils.MRENCLAVE_HASH_SIZE]byte
	remoteMrsigner  [utils.MRSINGER_HASH_SIZE]byte
)

var sgxraCommand = cli.Command{
	Name:  "remoteattestation",
	Usage: "attest IAS report obtained by inclavared and setup TLS security channel with inclavared",
	ArgsUsage: `[command options]

EXAMPLE:
       # shelter mrenclave`,
	/*	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "none",
			Usage: "none",
		},
		cli.StringFlag{
			Name:  "none",
			Usage: "none",
		},
	},*/

	SkipArgReorder: true,

	Action: func(cliContext *cli.Context) error {

		var socketAddr string
		socketAddr = cliContext.String("addr")
		//connect to inclavared by TCP socket
		//ret := remoteattestation.RemoteTlsSetupTCP(socketAddr, (unsafe.Pointer)(&remoteMrenclave[0]), (unsafe.Pointer)(&remoteMrsigner[0]))
		//connect to ra-tls-server by unix socket
		//ret := remoteattestation.RemoteTlsSetupSock(socketAddr, (unsafe.Pointer)(&remoteMrenclave[0]), (unsafe.Pointer)(&remoteMrsigner[0]))
		//for enclvae management protocol prototype
		cmdMsg := utils.GetEnclaveInfo{
			MsgType: "GETENCLAVEINFO",
		}
		sendMsg , err := json.Marshal(cmdMsg)
		if err != nil{
			return fmt.Errorf("json marshal failed, err: %s \n", err)
		}
		sendMsgLen := (uint)(len(sendMsg))
		var receiveMsg [utils.MANAGE_POOL_SIZE]byte
		var receiveMsgLen uint = 0
		sendData := make([]byte, sendMsgLen)
		sendData = sendMsg
		ret := remoteattestation.RemoteTlsSetupSockProtocol(socketAddr, (unsafe.Pointer)(&sendData[0]), sendMsgLen, (unsafe.Pointer)(&receiveMsg[0]), (unsafe.Pointer)(&receiveMsgLen))
		if ret != nil {
			return fmt.Errorf("RemotTlsSetup failed with err: %s \n", ret)
		}
		receiveBuffer := receiveMsg[:receiveMsgLen]
                var parseInfo utils.EnclaveInfo
                err = json.Unmarshal(receiveBuffer, &parseInfo)
		if err != nil{
                        return fmt.Errorf("json Unmarshal failed, err: %s \n", err)
                }
                remoteMrenclave = parseInfo.Mrenclave
		remoteMrsigner = parseInfo.Mrsigner
		fmt.Println("App Enclave mrenclave:",remoteMrenclave)
		fmt.Println("App Enclave mrsinger:",remoteMrsigner)

		fmt.Printf("remote attestation is successful.\n")
		return nil

	},
}
