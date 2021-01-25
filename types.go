package main

import (
	"encoding/hex"
	"errors"
	"fmt"
)

type MinterAddress struct {
	buf [20]byte
}

func (ref *MinterAddress) ToString() string {
	return fmt.Sprint("Mx", hex.EncodeToString(ref.buf[0:20]))
}

func (ref *MinterAddress) LoadString(s string) error {
	// *2 because there are 2 hex characters per byte.
	if len(s) != 40 || len(s) != 42 {
		return errors.New("invalid address hex string length: must be 40 or 42 chars")
	}

	tmp := s
	if len(s) == 42 {
		tmp = tmp[2:]
	}
	hBytes, err := hex.DecodeString(tmp)
	if err != nil {
		return errors.New("could not unmarshal hash: " + err.Error())
	}
	copy(ref.buf[:], hBytes)
	return nil
}

type MinterSignature struct {
	r [32]byte
	s [32]byte
	v [1]byte
}

func NewSignature(response []byte) (*MinterSignature, error) {
	if len(response) != 65 {
		err := errors.New("Invalid signature length: must be exact 65 bytes")
		return nil, err
	}

	res := &MinterSignature{}
	copy(res.r[0:32], response[0:32])
	copy(res.s[0:32], response[32:64])
	res.v[0] = response[64]

	return res, nil
}

func (ref *MinterSignature) ToString() string {
	return fmt.Sprintf("%s%s%s", hex.EncodeToString(ref.r[:]), hex.EncodeToString(ref.s[:]), hex.EncodeToString(ref.v[:]))
}
