package utils

import (
)

const (
	MRENCLAVE_HASH_SIZE = 32
	MRSINGER_HASH_SIZE = 32
	MANAGE_POOL_SIZE = 1024
	ManageCmd1 = "GETENCLAVEINFO"
)

type GetEnclaveInfo struct{
	MsgType string          `json:"string_type"`
}

type EnclaveInfo struct{
	Id string               `json:"string_id,omitempty"`
	MsgType string          `json:"string_type,omitempty"`
	Version uint8           `json:"uint8_version,omitempty"`
	Mrenclave [MRENCLAVE_HASH_SIZE]byte      `json:"byte_mrenclave,omitempty"`
	Mrsigner  [MRSINGER_HASH_SIZE]byte      `json:"byte_mrsigner,omitempty"`
}

