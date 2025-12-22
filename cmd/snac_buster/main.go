package main

import (
	"bytes"
	"fmt"

	"github.com/mk6i/open-oscar-server/wire"
)

func main() {

	b := []byte{}

	flap := wire.FLAPFrame{}
	err := wire.UnmarshalBE(&flap, bytes.NewReader(b))
	if err != nil {
		err = fmt.Errorf("unable to unmarshal FLAP frame: %w", err)
	}

	rd := bytes.NewBuffer(flap.Payload)
	snac := wire.SNACFrame{}
	wire.UnmarshalBE(&snac, rd)

	printByteSlice(rd.Bytes())
	//snacBody := wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{}
	//wire.UnmarshalBE(&snacBody, rd)
	////fmt.Println(snacBody)
	//
	//fmt.Println()
	//
	//for _, tlv := range snacBody.TLVList {
	//	fmt.Printf("0x%x\t", tlv.Tag)
	//	printByteSlice(tlv.Value)
	//	fmt.Println()
	//}
}

func printByteSlice(data []byte) {
	fmt.Print("[]byte{")
	for i, b := range data {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("0x%02X", b)
	}
	fmt.Println("}")
}
