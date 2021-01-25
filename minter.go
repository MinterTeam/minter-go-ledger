package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/karalabe/hid"
	"log"
	"math"
	"strconv"
)

var DEBUG bool

type NanoS struct {
	device *apduFramer
	ptr    *hid.Device
}

type ErrCode uint16

func (c ErrCode) Error() string {
	return fmt.Sprintf("Error code 0x%x", uint16(c))
}

const codeSuccess = 0x9000
const codeUserRejected = 0x6985
const codeInvalidParam = 0x6b01

var errUserRejected = errors.New("user denied request")
var errInvalidParam = errors.New("invalid request parameters")

func (n *NanoS) Exchange(cmd uint8, p1, p2 uint8, data []uint8) (resp []uint8, err error) {
	resp, err = n.device.Exchange(APDU{
		CLA:     0xe0,
		INS:     cmd,
		P1:      p1,
		P2:      p2,
		Payload: data,
	})
	if err != nil {
		return nil, err
	} else if len(resp) < 2 {
		return nil, errors.New("APDU response missing status code")
	}
	code := binary.BigEndian.Uint16(resp[len(resp)-2:])
	resp = resp[:len(resp)-2]
	switch code {
	case codeSuccess:
		err = nil
	case codeUserRejected:
		err = errUserRejected
	case codeInvalidParam:
		err = errInvalidParam
	default:
		err = ErrCode(code)
	}
	return
}

const (
	cmdGetVersion = 0x01
	cmdGetAddress = 0x01 << 1
	cmdSignHash   = 0x01 << 2

	pGetAddressSilent = 1
	pSignHashSilent   = 1
)

const LedgerVendorID = 0x2c97
const LedgerNanoSProductID = 0x0001
const LedgerNanoSProductID16 = 0x1005

// Resolve installed application version
func (n *NanoS) GetVersion() (version string, err error) {
	resp, err := n.Exchange(cmdGetVersion, 0, 0, nil)
	if err != nil {
		return "", err
	} else if len(resp) != 3 {
		return "", errors.New("version has wrong length")
	}
	return fmt.Sprintf("v%d.%d.%d", resp[0], resp[1], resp[2]), nil
}

// Get current private key address by bip-standard derive index
// silent parameter means application will not ask user about performing operation and will just return requested value
func (n *NanoS) GetAddress(deriveIndex uint32, silent bool) (addr MinterAddress, err error) {
	encIndex := make([]uint8, 4)
	binary.LittleEndian.PutUint32(encIndex, deriveIndex)

	var param1 uint8 = 0
	if silent {
		param1 = pGetAddressSilent
	}
	resp, err := n.Exchange(cmdGetAddress, param1, 0, encIndex)
	if err != nil {
		return MinterAddress{}, err
	}
	address := MinterAddress{}
	copy(address.buf[0:20], resp[0:20])
	return address, nil
}

// Sign 32-byte transaction using derive index
// silent parameter means application will not ask user about performing operation and will just return requested value
func (n *NanoS) SignHash(hash [32]uint8, deriveIndex uint32, silent bool) (sig *MinterSignature, err error) {
	encIndex := make([]uint8, 4)
	binary.LittleEndian.PutUint32(encIndex, deriveIndex)

	var param1 uint8 = 0
	if silent {
		param1 = pSignHashSilent
	}

	resp, err := n.Exchange(cmdSignHash, param1, 0, append(encIndex, hash[:]...))
	if err != nil {
		sig = nil
		return
	}

	sig, err = NewSignature(resp)
	if err != nil {
		sig = nil
		return
	}

	return
}

// Connect to ledger using certain USB (HID) product id. It can be changed every time as Ledger company wish it in their brand-new firmware without any warn.
func OpenNanoSWithPID(productId uint16) (*NanoS, error) {
	// search for Nano S
	devices := hid.Enumerate(LedgerVendorID, productId)
	if len(devices) == 0 {
		return nil, errors.New("Nano S not detected")
	} /* else if len(devices) > 1 {
		return nil, errors.NewSignature("Unexpected error -- Is the Minter wallet app running?")
	}*/

	// open the device
	device, err := devices[0].Open()
	if err != nil {
		return nil, err
	}

	// wrap raw device I/O in HID+APDU protocols
	return &NanoS{
		ptr: device,
		device: &apduFramer{
			hf: &hidFramer{
				rw: device,
			},
		},
	}, nil
}

func OpenNanoS() (*NanoS, error) {
	return OpenNanoSWithPID(LedgerNanoSProductID)
}

func parseIndex(s string) uint32 {
	index, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		log.Fatalln("Couldn't parse index:", err)
	} else if index > math.MaxUint32 {
		log.Fatalf("Index too large (max %v)", math.MaxUint32)
	}
	return uint32(index)
}

func CloseNanoS(nanos *NanoS) {
	if nanos != nil {
		_ = nanos.ptr.Close()
	}
}
