package oscarclient

import (
	"bytes"
	"fmt"
	"io"

	"github.com/mk6i/open-oscar-server/wire"
)

// snacDecoders unmarshal the bodies of the SNACs that in-process clients
// handle, keyed by food group and subgroup.
var snacDecoders = map[[2]uint16]func(r io.Reader) (any, error){
	{wire.OService, wire.OServiceHostOnline}:       decodeBody[wire.SNAC_0x01_0x03_OServiceHostOnline],
	{wire.OService, wire.OServiceServiceResponse}:  decodeBody[wire.SNAC_0x01_0x05_OServiceServiceResponse],
	{wire.OService, wire.OServiceRateParamsReply}:  decodeBody[wire.SNAC_0x01_0x07_OServiceRateParamsReply],
	{wire.OService, wire.OServiceRateParamChange}:  decodeBody[wire.SNAC_0x01_0x0A_OServiceRateParamsChange],
	{wire.OService, wire.OServiceUserInfoUpdate}:   decodeBody[wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate],
	{wire.OService, wire.OServiceEvilNotification}: decodeBody[wire.SNAC_0x01_0x10_OServiceEvilNotification],
	{wire.Locate, wire.LocateUserInfoReply}:        decodeBody[wire.SNAC_0x02_0x06_LocateUserInfoReply],
	{wire.Locate, wire.LocateSetDirReply}:          decodeBody[wire.SNAC_0x02_0x0A_LocateSetDirReply],
	{wire.Locate, wire.LocateGetDirReply}:          decodeBody[wire.SNAC_0x02_0x0C_LocateGetDirReply],
	{wire.Buddy, wire.BuddyArrived}:                decodeBody[wire.SNAC_0x03_0x0B_BuddyArrived],
	{wire.Buddy, wire.BuddyDeparted}:               decodeBody[wire.SNAC_0x03_0x0C_BuddyDeparted],
	{wire.ICBM, wire.ICBMChannelMsgToClient}:       decodeBody[wire.SNAC_0x04_0x07_ICBMChannelMsgToClient],
	{wire.ICBM, wire.ICBMEvilReply}:                decodeBody[wire.SNAC_0x04_0x09_ICBMEvilReply],
	{wire.ICBM, wire.ICBMClientErr}:                decodeBody[wire.SNAC_0x04_0x0B_ICBMClientErr],
	{wire.ICBM, wire.ICBMHostAck}:                  decodeBody[wire.SNAC_0x04_0x0C_ICBMHostAck],
	{wire.ICBM, wire.ICBMClientEvent}:              decodeBody[wire.SNAC_0x04_0x14_ICBMClientEvent],
	{wire.ICBM, wire.ICBMOfflineRetrieveReply}:     decodeBody[wire.SNAC_0x04_0x17_ICBMOfflineRetrieveReply],
	{wire.Admin, wire.AdminInfoChangeReply}:        decodeBody[wire.SNAC_0x07_0x05_AdminChangeReply],
	{wire.ChatNav, wire.ChatNavNavInfo}:            decodeBody[wire.SNAC_0x0D_0x09_ChatNavNavInfo],
	{wire.Chat, wire.ChatUsersJoined}:              decodeBody[wire.SNAC_0x0E_0x03_ChatUsersJoined],
	{wire.Chat, wire.ChatUsersLeft}:                decodeBody[wire.SNAC_0x0E_0x04_ChatUsersLeft],
	{wire.Chat, wire.ChatChannelMsgToClient}:       decodeBody[wire.SNAC_0x0E_0x06_ChatChannelMsgToClient],
	{wire.ODir, wire.ODirInfoReply}:                decodeBody[wire.SNAC_0x0F_0x03_InfoReply],
	{wire.BART, wire.BARTUploadReply}:              decodeBody[wire.SNAC_0x10_0x03_BARTUploadReply],
	{wire.Feedbag, wire.FeedbagReply}:              decodeBody[wire.SNAC_0x13_0x06_FeedbagReply],
	{wire.Feedbag, wire.FeedbagInsertItem}:         decodeBody[wire.SNAC_0x13_0x08_FeedbagInsertItem],
	{wire.Feedbag, wire.FeedbagUpdateItem}:         decodeBody[wire.SNAC_0x13_0x09_FeedbagUpdateItem],
	{wire.Feedbag, wire.FeedbagDeleteItem}:         decodeBody[wire.SNAC_0x13_0x0A_FeedbagDeleteItem],
	{wire.Feedbag, wire.FeedbagStatus}:             decodeBody[wire.SNAC_0x13_0x0E_FeedbagStatus],
	{wire.BUCP, wire.BUCPLoginResponse}:            decodeBody[wire.SNAC_0x17_0x03_BUCPLoginResponse],
}

// snacErrorSubGroup is the subgroup of the error SNAC in every food group.
const snacErrorSubGroup = 0x0001

// DecodeSNAC unmarshals a SNAC received from the OSCAR server. A SNAC that no
// in-process client handles is returned with a nil body.
func DecodeSNAC(payload []byte) (wire.SNACMessage, error) {
	r := bytes.NewReader(payload)
	msg := wire.SNACMessage{}
	if err := wire.UnmarshalBE(&msg.Frame, r); err != nil {
		return msg, fmt.Errorf("unmarshal SNAC frame: %w", err)
	}

	decode := snacDecoders[[2]uint16{msg.Frame.FoodGroup, msg.Frame.SubGroup}]
	if msg.Frame.SubGroup == snacErrorSubGroup {
		decode = decodeBody[wire.SNACError]
	}
	if decode == nil {
		return msg, nil
	}

	body, err := decode(r)
	if err != nil {
		return msg, fmt.Errorf("unmarshal %s: %w",
			wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup), err)
	}
	msg.Body = body
	return msg, nil
}

func decodeBody[T any](r io.Reader) (any, error) {
	var body T
	err := wire.UnmarshalBE(&body, r)
	return body, err
}
