package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	nanos, err := OpenNanoS()
	// due firmware 1.6.+ changed some configurations, nano s now have other product id for system menu and application
	// check all variants
	if err != nil {
		nanos, err = OpenNanoSWithPID(LedgerNanoSProductID16)
	}

	// close descriptors after operations complete
	defer CloseNanoS(nanos)

	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + " or Minter app isn't running\n")
		return
	}

	fmt.Printf("[using NanoS with product id: 0x%04x]\n", nanos.ptr.ProductID)

	var deriveIndex uint32 = 0

	// Get minter address
	address, err := nanos.GetAddress(deriveIndex, true)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to get address: %s", err.Error())
		return
	}
	fmt.Println("My Address: ", address.ToString())

	// Get app version
	appVersion, err := nanos.GetVersion()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to app version: %s", err.Error())
		return
	}
	fmt.Println("Ledger app version: ", appVersion)

	// Sign tx
	tx := "725efb68d8daaf30c1be0ee6727ccab60e5b08a57ef0d80fc9e0bd9e46e62944"
	txBytes, err := hex.DecodeString(tx)
	var tmp [32]byte
	copy(tmp[0:32], txBytes[:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to decode hex string: %s", err.Error())
		return
	}
	if len(txBytes) != 32 {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to sign tx: invalid length of transaction. Must be 32 bytes, given: %d", len(txBytes))
		return
	}

	signature, err := nanos.SignHash(tmp, deriveIndex, true)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable sign tx: %s", err.Error())
		return
	}
	fmt.Println("Test signature: ", signature.ToString())

}
