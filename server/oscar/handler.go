package oscar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/oscar/middleware"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// ErrRouteNotFound is an error that indicates a failure to find a matching
	// route for an OSCAR protocol request.
	ErrRouteNotFound            = errors.New("route not found")
	errUnknownICQMetaReqType    = errors.New("unknown ICQ request type")
	errUnknownICQMetaReqSubType = errors.New("unknown ICQ metadata request subtype")
)

// ResponseWriter is the interface for sending a SNAC response to the client
// from the server handlers.
type ResponseWriter interface {
	SendSNAC(frame wire.SNACFrame, body any) error
}

// Handler defines a structure for routing OSCAR protocol requests to
// appropriate handlers based on group:subGroup identifiers.
type Handler struct {
	AdminService
	BARTService
	BuddyService
	ChatNavService
	ChatService
	FeedbagService
	ICBMService
	ICQService
	LocateService
	ODirService
	OServiceService
	PermitDenyService
	StatsService
	UserLookupService
	middleware.RouteLogger
}

func (rt Handler) AdminConfirmRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC, err := rt.AdminService.ConfirmRequest(ctx, instance, inFrame)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) AdminInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x07_0x02_AdminInfoQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.AdminService.InfoQuery(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) AdminInfoChangeRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.AdminService.InfoChangeRequest(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) AlertNotifyCapabilities(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, _ ResponseWriter) error {
	rt.LogRequest(ctx, inFrame, nil)
	return nil
}

func (rt Handler) AlertNotifyDisplayCapabilities(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, _ ResponseWriter) error {
	rt.LogRequest(ctx, inFrame, nil)
	return nil
}

func (rt Handler) BARTUploadQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x10_0x02_BARTUploadQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.BARTService.UpsertItem(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, outSNAC, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BARTDownloadQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x10_0x04_BARTDownloadQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.BARTService.RetrieveItem(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, outSNAC, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BARTDownload2Query(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x10_0x06_BARTDownload2Query{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNACS, err := rt.BARTService.RetrieveItemV2(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	for _, snac := range outSNACS {
		rt.LogRequestAndResponse(ctx, inFrame, snac, snac.Frame, snac.Body)
		if err := rw.SendSNAC(snac.Frame, snac.Body); err != nil {
			return err
		}
	}
	return nil
}

func (rt Handler) BuddyRightsQuery(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inSNAC := wire.SNAC_0x03_0x02_BuddyRightsQuery{}
	if err := wire.UnmarshalBE(&inSNAC, r); err != nil {
		return err
	}
	outSNAC := rt.BuddyService.RightsQuery(ctx, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, inSNAC, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BuddyAddBuddies(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inSNAC := wire.SNAC_0x03_0x04_BuddyAddBuddies{}
	if err := wire.UnmarshalBE(&inSNAC, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inSNAC)
	return rt.BuddyService.AddBuddies(ctx, instance, inSNAC)
}

func (rt Handler) BuddyDelBuddies(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inSNAC := wire.SNAC_0x03_0x05_BuddyDelBuddies{}
	if err := wire.UnmarshalBE(&inSNAC, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inSNAC)
	return rt.BuddyService.DelBuddies(ctx, instance, inSNAC)
}

func (rt Handler) BuddyAddTempBuddies(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inSNAC := wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{}
	if err := wire.UnmarshalBE(&inSNAC, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inSNAC)
	return rt.BuddyService.AddTempBuddies(ctx, instance, inSNAC)
}

func (rt Handler) BuddyDelTempBuddies(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inSNAC := wire.SNAC_0x03_0x10_BuddyDelTempBuddies{}
	if err := wire.UnmarshalBE(&inSNAC, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inSNAC)
	return rt.BuddyService.DelTempBuddies(ctx, instance, inSNAC)
}

func (rt Handler) ChatChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ChatService.ChannelMsgToHost(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	if outSNAC == nil {
		return nil
	}
	rt.Logger.InfoContext(ctx, "user sent a chat message")
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ChatNavRequestChatRights(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC := rt.ChatNavService.RequestChatRights(ctx, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ChatNavRequestExchangeInfo(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ChatNavService.ExchangeInfo(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ChatNavRequestRoomInfo(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ChatNavService.RequestRoomInfo(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ChatNavCreateRoom(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ChatNavService.CreateRoom(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	roomName, _ := inBody.String(wire.ChatRoomTLVRoomName)
	rt.Logger.InfoContext(ctx, "user started a chat room", slog.String("roomName", roomName))
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagRightsQuery(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x02_FeedbagRightsQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC := rt.FeedbagService.RightsQuery(ctx, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC, err := rt.FeedbagService.Query(ctx, instance, inFrame)
	if err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, outSNAC)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagQueryIfModified(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x05_FeedbagQueryIfModified{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.FeedbagService.QueryIfModified(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagUse(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, _ ResponseWriter) error {
	rt.LogRequest(ctx, inFrame, nil)
	return rt.FeedbagService.Use(ctx, instance)
}

func (rt Handler) FeedbagInsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x08_FeedbagInsertItem{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.FeedbagService.UpsertItem(ctx, instance, inFrame, inBody.Items)
	if err != nil {
		return err
	}
	if outSNAC == nil {
		rt.LogRequest(ctx, inFrame, inBody)
		return nil
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagUpdateItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x09_FeedbagUpdateItem{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.FeedbagService.UpsertItem(ctx, instance, inFrame, inBody.Items)
	if err != nil {
		return err
	}
	if outSNAC == nil {
		rt.LogRequest(ctx, inFrame, inBody)
		return nil
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagDeleteItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.FeedbagService.DeleteItem(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	if outSNAC == nil {
		rt.LogRequest(ctx, inFrame, inBody)
		return nil
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) FeedbagStartCluster(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x11_FeedbagStartCluster{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.FeedbagService.StartCluster(ctx, inFrame, inBody)
	rt.LogRequest(ctx, inFrame, inBody)
	return nil
}

func (rt Handler) FeedbagEndCluster(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, _ ResponseWriter) error {
	rt.LogRequest(ctx, inFrame, nil)
	return nil
}

func (rt Handler) FeedbagRespondAuthorizeToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	if err := rt.FeedbagService.RespondAuthorizeToHost(ctx, instance, inFrame, inBody); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return nil
}

func (rt Handler) ICBMAddParameters(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x04_0x02_ICBMAddParameters{}
	rt.LogRequest(ctx, inFrame, inBody)
	return wire.UnmarshalBE(&inBody, r)
}

func (rt Handler) ICBMParameterQuery(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC := rt.ICBMService.ParameterQuery(ctx, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, outSNAC, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ICBMChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ICBMService.ChannelMsgToHost(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.Logger.InfoContext(ctx, "user sent an IM", slog.String("recipient", inBody.ScreenName))
	if outSNAC == nil {
		return nil
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ICBMEvilRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x04_0x08_ICBMEvilRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ICBMService.EvilRequest(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ICBMClientErr(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x04_0x0B_ICBMClientErr{}
	rt.LogRequest(ctx, inFrame, inBody)
	err := wire.UnmarshalBE(&inBody, r)
	if err != nil {
		return err
	}
	return rt.ICBMService.ClientErr(ctx, instance, inFrame, inBody)
}

func (rt Handler) ICBMClientEvent(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x04_0x14_ICBMClientEvent{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.ICBMService.ClientEvent(ctx, instance, inFrame, inBody)
}

func (rt Handler) ICBMOfflineRetrieve(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, rw ResponseWriter) error {
	outSNAC, err := rt.ICBMService.OfflineRetrieve(ctx, instance, inFrame)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ICQDBQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x15_0x02_BQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}

	md, ok := inBody.Bytes(wire.ICQTLVTagsMetadata)
	if !ok {
		return errors.New("invalid ICQ frame")
	}

	icqChunk := wire.ICQMessageRequestEnvelope{}
	if err := wire.UnmarshalLE(&icqChunk, bytes.NewBuffer(md)); err != nil {
		return err
	}
	buf := bytes.NewBuffer(icqChunk.Body)
	icqMD := wire.ICQMetadataWithSubType{}
	if err := wire.UnmarshalLE(&icqMD, buf); err != nil {
		return err
	}

	switch icqMD.ReqType {
	case wire.ICQDBQueryOfflineMsgReq:
		return rt.ICQService.OfflineMsgReq(ctx, instance, icqMD.Seq)
	case wire.ICQDBQueryDeleteMsgReq:
		return rt.ICQService.DeleteMsgReq(ctx, instance, icqMD.Seq)
	case wire.ICQDBQueryMetaReq:
		if icqMD.Optional == nil {
			return errors.New("got req without subtype")
		}
		rt.Logger.Debug("ICQ client request",
			"query_name", wire.ICQDBQueryName(icqMD.ReqType),
			"query_type", wire.ICQDBQueryMetaName(icqMD.Optional.ReqSubType),
			"uin", instance.UIN())

		switch icqMD.Optional.ReqSubType {
		case wire.ICQDBQueryMetaReqShortInfo:
			userInfo := wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo{}
			if err := binary.Read(buf, binary.LittleEndian, &userInfo); err != nil {
				return nil
			}
			return rt.ICQService.ShortUserInfo(ctx, instance, userInfo, icqMD.Seq)
		case wire.ICQDBQueryMetaReqFullInfo, wire.ICQDBQueryMetaReqFullInfo2:
			userInfo := wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{}
			if err := binary.Read(buf, binary.LittleEndian, &userInfo); err != nil {
				return nil
			}
			return rt.ICQService.FullUserInfo(ctx, instance, userInfo, icqMD.Seq)
		case wire.ICQDBQueryMetaReqXMLReq:
			req := wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.XMLReqData(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetPermissions:
			req := wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetPermissions(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchByUIN:
			req := wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.FindByUIN(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchByUIN2:
			rest := buf.Bytes()
			if bytes.HasPrefix(rest, []byte{0x36, 0x01, 0x06, 0x00}) && len(rest) == 8 {
				// fix incorrect TLV len set by QIP 2005. it specifies len=6
				// for a 4-byte value, causing the unmarshaler to return EOF.
				rest[2] = 4
			}
			req := wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2{}
			if err := wire.UnmarshalLE(&req, bytes.NewReader(rest)); err != nil {
				return err
			}
			if err := rt.ICQService.FindByUIN2(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchByEmail:
			req := wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.FindByICQEmail(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchByEmail3:
			req := wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.FindByEmail3(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchByDetails:
			req := wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.FindByICQName(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchWhitePages:
			req := wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.FindByICQInterests(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSearchWhitePages2:
			req := wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.FindByWhitePages2(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetBasicInfo:
			req := wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetBasicInfo(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetWorkInfo:
			req := wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetWorkInfo(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetMoreInfo:
			req := wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetMoreInfo(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetNotes:
			req := wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetUserNotes(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetEmails:
			req := wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetEmails(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetInterests:
			req := wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetInterests(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqSetAffiliations:
			req := wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.ICQService.SetAffiliations(ctx, instance, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqStat0a8c,
			wire.ICQDBQueryMetaReqStat0a96,
			wire.ICQDBQueryMetaReqStat0aaa,
			wire.ICQDBQueryMetaReqStat0ab4,
			wire.ICQDBQueryMetaReqStat0ab9,
			wire.ICQDBQueryMetaReqStat0abe,
			wire.ICQDBQueryMetaReqStat0ac8,
			wire.ICQDBQueryMetaReqStat0acd,
			wire.ICQDBQueryMetaReqStat0ad2,
			wire.ICQDBQueryMetaReqStat0ad7,
			wire.ICQDBQueryMetaReqStat0758:
			rt.Logger.Debug("got a request for stats, not doing anything right now")
		default:
			return fmt.Errorf("%w: %X", errUnknownICQMetaReqSubType, icqMD.Optional.ReqSubType)
		}
	default:
		return fmt.Errorf("%w: %X", errUnknownICQMetaReqType, icqMD.ReqType)
	}

	return nil
}

func (rt Handler) LocateRightsQuery(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC := rt.LocateService.RightsQuery(ctx, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) LocateSetInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x02_0x04_LocateSetInfo{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.LocateService.SetInfo(ctx, instance, inBody)
}

func (rt Handler) LocateSetDirInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x02_0x09_LocateSetDirInfo{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.LocateService.SetDirInfo(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) LocateGetDirInfo(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x02_0x0B_LocateGetDirInfo{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.LocateService.DirInfo(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) LocateSetKeywordInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x02_0x0F_LocateSetKeywordInfo{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.LocateService.SetKeywordInfo(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) LocateUserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x02_0x05_LocateUserInfoQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.LocateService.UserInfoQuery(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) LocateUserInfoQuery2(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x02_0x15_LocateUserInfoQuery2{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	// SNAC functionality for LocateUserInfoQuery and LocateUserInfoQuery2 is
	// identical except for the Type field data type (uint16 vs uint32).
	wrappedBody := wire.SNAC_0x02_0x05_LocateUserInfoQuery{
		Type:       uint16(inBody.Type2),
		ScreenName: inBody.ScreenName,
	}
	outSNAC, err := rt.LocateService.UserInfoQuery(ctx, instance, inFrame, wrappedBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ODirInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0F_0x02_InfoQuery{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.ODirService.InfoQuery(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, outSNAC, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) ODirKeywordListQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	outSNAC, err := rt.ODirService.KeywordListQuery(ctx, inFrame)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) OServiceRateParamsQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC := rt.OServiceService.RateParamsQuery(ctx, instance, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) OServiceRateParamsSubAdd(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.OServiceService.RateParamsSubAdd(ctx, instance, inBody)
	rt.LogRequest(ctx, inFrame, inBody)
	return nil
}

func (rt Handler) OServiceUserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC := rt.OServiceService.UserInfoQuery(ctx, instance, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) OServiceIdleNotification(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x01_0x11_OServiceIdleNotification{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.OServiceService.IdleNotification(ctx, instance, inBody)
}

func (rt Handler) OServiceClientVersions(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x01_0x17_OServiceClientVersions{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNACs := rt.OServiceService.ClientVersions(ctx, instance, inFrame, inBody)
	for _, snac := range outSNACs {
		rt.LogRequestAndResponse(ctx, inFrame, inBody, snac.Frame, snac.Body)
		if err := rw.SendSNAC(snac.Frame, snac.Body); err != nil {
			return err
		}
	}
	return nil
}

func (rt Handler) OServiceSetUserInfoFields(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.OServiceService.SetUserInfoFields(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) OServiceNoop(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	// no-op keep-alive
	rt.LogRequest(ctx, inFrame, nil)
	return nil
}

func (rt Handler) OServiceSetPrivacyFlags(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x01_0x14_OServiceSetPrivacyFlags{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.OServiceService.SetPrivacyFlags(ctx, inBody)
	rt.LogRequest(ctx, inFrame, inBody)
	return nil
}

func (rt Handler) OServiceServiceRequest(ctx context.Context, service uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error {
	inBody := wire.SNAC_0x01_0x04_OServiceServiceRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.OServiceService.ServiceRequest(ctx, service, instance, inFrame, inBody, listener)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) OServiceClientOnline(ctx context.Context, service uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, _ ResponseWriter) error {
	inBody := wire.SNAC_0x01_0x02_OServiceClientOnline{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.Logger.InfoContext(ctx, "user signed on")
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.OServiceService.ClientOnline(ctx, service, inBody, instance)
}

func (rt Handler) PermitDenyRightsQuery(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, rw ResponseWriter) error {
	outSNAC := rt.PermitDenyService.RightsQuery(ctx, inFrame)
	rt.LogRequestAndResponse(ctx, inFrame, nil, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) PermitDenyAddDenyListEntries(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.PermitDenyService.AddDenyListEntries(ctx, instance, inBody)
}

func (rt Handler) PermitDenyDelDenyListEntries(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.PermitDenyService.DelDenyListEntries(ctx, instance, inBody)
}

func (rt Handler) PermitDenyAddPermListEntries(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.PermitDenyService.AddPermListEntries(ctx, instance, inBody)
}

func (rt Handler) PermitDenyDelPermListEntries(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	rt.LogRequest(ctx, inFrame, inBody)
	return rt.PermitDenyService.DelPermListEntries(ctx, instance, inBody)
}

// PermitDenySetGroupPermitMask sets the classes of users I can interact with. We don't
// apply any of these settings to the privacy mechanism, so just log them for
// now.
func (rt Handler) PermitDenySetGroupPermitMask(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x09_0x04_PermitDenySetGroupPermitMask{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}

	var flags []string

	if inBody.IsFlagSet(wire.OServiceUserFlagUnconfirmed) {
		flags = append(flags, "wire.OServiceUserFlagUnconfirmed")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagAdministrator) {
		flags = append(flags, "wire.OServiceUserFlagAdministrator")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagAOL) {
		flags = append(flags, "wire.OServiceUserFlagAOL")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagOSCARPay) {
		flags = append(flags, "wire.OServiceUserFlagOSCARPay")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagOSCARFree) {
		flags = append(flags, "wire.OServiceUserFlagOSCARFree")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagUnavailable) {
		flags = append(flags, "wire.OServiceUserFlagUnavailable")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagICQ) {
		flags = append(flags, "wire.OServiceUserFlagICQ")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagWireless) {
		flags = append(flags, "wire.OServiceUserFlagWireless")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagInternal) {
		flags = append(flags, "wire.OServiceUserFlagInternal")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagFish) {
		flags = append(flags, "wire.OServiceUserFlagFish")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagBot) {
		flags = append(flags, "wire.OServiceUserFlagBot")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagBeast) {
		flags = append(flags, "wire.OServiceUserFlagBeast")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagOneWayWireless) {
		flags = append(flags, "wire.OServiceUserFlagOneWayWireless")
	}
	if inBody.IsFlagSet(wire.OServiceUserFlagOfficial) {
		flags = append(flags, "wire.OServiceUserFlagOfficial")
	}

	rt.Logger.Info("set pd group mask", "flags", flags)
	rt.LogRequest(ctx, inFrame, inBody)

	return nil
}

func (rt Handler) StatsReportEvents(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0B_0x03_StatsReportEvents{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}

	outSNAC := rt.StatsService.ReportEvents(ctx, inFrame, inBody)
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)

	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) UserLookupFindByEmail(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0x0A_0x02_UserLookupFindByEmail{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.UserLookupService.FindByEmail(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

// Handle directs an incoming OSCAR request to the appropriate handler based on
// its group and subGroup identifiers found in the SNAC frame. It returns an
// ErrRouteNotFound error if no matching handler is found for the group:subGroup
// pair in the request.
func (rt Handler) Handle(ctx context.Context, server uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error {
	switch inFrame.FoodGroup {
	case wire.Admin:
		switch inFrame.SubGroup {
		case wire.AdminAcctConfirmRequest:
			return rt.AdminConfirmRequest(ctx, instance, inFrame, r, rw)
		case wire.AdminInfoChangeRequest:
			return rt.AdminInfoChangeRequest(ctx, instance, inFrame, r, rw)
		case wire.AdminInfoQuery:
			return rt.AdminInfoQuery(ctx, instance, inFrame, r, rw)
		}
	case wire.Alert:
		switch inFrame.SubGroup {
		case wire.AlertNotifyCapabilities:
			return rt.AlertNotifyCapabilities(ctx, instance, inFrame, r, rw)
		case wire.AlertNotifyDisplayCapabilities:
			return rt.AlertNotifyDisplayCapabilities(ctx, instance, inFrame, r, rw)
		}
	case wire.BART:
		switch inFrame.SubGroup {
		case wire.BARTDownloadQuery:
			return rt.BARTDownloadQuery(ctx, instance, inFrame, r, rw)
		case wire.BARTDownload2Query:
			return rt.BARTDownload2Query(ctx, instance, inFrame, r, rw)
		case wire.BARTUploadQuery:
			return rt.BARTUploadQuery(ctx, instance, inFrame, r, rw)
		}
	case wire.Buddy:
		switch inFrame.SubGroup {
		case wire.BuddyAddBuddies:
			return rt.BuddyAddBuddies(ctx, instance, inFrame, r, rw)
		case wire.BuddyDelBuddies:
			return rt.BuddyDelBuddies(ctx, instance, inFrame, r, rw)
		case wire.BuddyRightsQuery:
			return rt.BuddyRightsQuery(ctx, instance, inFrame, r, rw)
		case wire.BuddyAddTempBuddies:
			return rt.BuddyAddTempBuddies(ctx, instance, inFrame, r, rw)
		case wire.BuddyDelTempBuddies:
			return rt.BuddyDelTempBuddies(ctx, instance, inFrame, r, rw)
		}
	case wire.Chat:
		switch inFrame.SubGroup {
		case wire.ChatChannelMsgToHost:
			return rt.ChatChannelMsgToHost(ctx, instance, inFrame, r, rw)
		}
	case wire.ChatNav:
		switch inFrame.SubGroup {
		case wire.ChatNavCreateRoom:
			return rt.ChatNavCreateRoom(ctx, instance, inFrame, r, rw)
		case wire.ChatNavRequestChatRights:
			return rt.ChatNavRequestChatRights(ctx, instance, inFrame, r, rw)
		case wire.ChatNavRequestExchangeInfo:
			return rt.ChatNavRequestExchangeInfo(ctx, instance, inFrame, r, rw)
		case wire.ChatNavRequestRoomInfo:
			return rt.ChatNavRequestRoomInfo(ctx, instance, inFrame, r, rw)
		}
	case wire.Feedbag:
		switch inFrame.SubGroup {
		case wire.FeedbagDeleteItem:
			return rt.FeedbagDeleteItem(ctx, instance, inFrame, r, rw)
		case wire.FeedbagEndCluster:
			return rt.FeedbagEndCluster(ctx, instance, inFrame, r, rw)
		case wire.FeedbagInsertItem:
			return rt.FeedbagInsertItem(ctx, instance, inFrame, r, rw)
		case wire.FeedbagQuery:
			return rt.FeedbagQuery(ctx, instance, inFrame, r, rw)
		case wire.FeedbagQueryIfModified:
			return rt.FeedbagQueryIfModified(ctx, instance, inFrame, r, rw)
		case wire.FeedbagRespondAuthorizeToHost:
			return rt.FeedbagRespondAuthorizeToHost(ctx, instance, inFrame, r, rw)
		case wire.FeedbagRightsQuery:
			return rt.FeedbagRightsQuery(ctx, instance, inFrame, r, rw)
		case wire.FeedbagStartCluster:
			return rt.FeedbagStartCluster(ctx, instance, inFrame, r, rw)
		case wire.FeedbagUpdateItem:
			return rt.FeedbagUpdateItem(ctx, instance, inFrame, r, rw)
		case wire.FeedbagUse:
			return rt.FeedbagUse(ctx, instance, inFrame, r, rw)
		}
	case wire.ICQ:
		switch inFrame.SubGroup {
		case wire.ICQDBQuery:
			return rt.ICQDBQuery(ctx, instance, inFrame, r, rw)
		}
	case wire.ICBM:
		switch inFrame.SubGroup {
		case wire.ICBMAddParameters:
			return rt.ICBMAddParameters(ctx, instance, inFrame, r, rw)
		case wire.ICBMChannelMsgToHost:
			return rt.ICBMChannelMsgToHost(ctx, instance, inFrame, r, rw)
		case wire.ICBMClientErr:
			return rt.ICBMClientErr(ctx, instance, inFrame, r, rw)
		case wire.ICBMClientEvent:
			return rt.ICBMClientEvent(ctx, instance, inFrame, r, rw)
		case wire.ICBMEvilRequest:
			return rt.ICBMEvilRequest(ctx, instance, inFrame, r, rw)
		case wire.ICBMParameterQuery:
			return rt.ICBMParameterQuery(ctx, instance, inFrame, r, rw)
		case wire.ICBMOfflineRetrieve:
			return rt.ICBMOfflineRetrieve(ctx, instance, inFrame, rw)
		}
	case wire.Locate:
		switch inFrame.SubGroup {
		case wire.LocateGetDirInfo:
			return rt.LocateGetDirInfo(ctx, instance, inFrame, r, rw)
		case wire.LocateRightsQuery:
			return rt.LocateRightsQuery(ctx, instance, inFrame, r, rw)
		case wire.LocateSetDirInfo:
			return rt.LocateSetDirInfo(ctx, instance, inFrame, r, rw)
		case wire.LocateSetInfo:
			return rt.LocateSetInfo(ctx, instance, inFrame, r, rw)
		case wire.LocateSetKeywordInfo:
			return rt.LocateSetKeywordInfo(ctx, instance, inFrame, r, rw)
		case wire.LocateUserInfoQuery:
			return rt.LocateUserInfoQuery(ctx, instance, inFrame, r, rw)
		case wire.LocateUserInfoQuery2:
			return rt.LocateUserInfoQuery2(ctx, instance, inFrame, r, rw)
		}
	case wire.ODir:
		switch inFrame.SubGroup {
		case wire.ODirInfoQuery:
			return rt.ODirInfoQuery(ctx, instance, inFrame, r, rw)
		case wire.ODirKeywordListQuery:
			return rt.ODirKeywordListQuery(ctx, instance, inFrame, r, rw)
		}
	case wire.OService:
		switch inFrame.SubGroup {
		case wire.OServiceClientOnline:
			return rt.OServiceClientOnline(ctx, server, instance, inFrame, r, rw)
		case wire.OServiceClientVersions:
			return rt.OServiceClientVersions(ctx, instance, inFrame, r, rw)
		case wire.OServiceIdleNotification:
			return rt.OServiceIdleNotification(ctx, instance, inFrame, r, rw)
		case wire.OServiceNoop:
			return rt.OServiceNoop(ctx, instance, inFrame, r, rw)
		case wire.OServiceRateParamsQuery:
			return rt.OServiceRateParamsQuery(ctx, instance, inFrame, r, rw)
		case wire.OServiceRateParamsSubAdd:
			return rt.OServiceRateParamsSubAdd(ctx, instance, inFrame, r, rw)
		case wire.OServiceServiceRequest:
			return rt.OServiceServiceRequest(ctx, server, instance, inFrame, r, rw, listener)
		case wire.OServiceSetPrivacyFlags:
			return rt.OServiceSetPrivacyFlags(ctx, instance, inFrame, r, rw)
		case wire.OServiceSetUserInfoFields:
			return rt.OServiceSetUserInfoFields(ctx, instance, inFrame, r, rw)
		case wire.OServiceUserInfoQuery:
			return rt.OServiceUserInfoQuery(ctx, instance, inFrame, r, rw)
		}
	case wire.PermitDeny:
		switch inFrame.SubGroup {
		case wire.PermitDenyAddDenyListEntries:
			return rt.PermitDenyAddDenyListEntries(ctx, instance, inFrame, r, rw)
		case wire.PermitDenyAddPermListEntries:
			return rt.PermitDenyAddPermListEntries(ctx, instance, inFrame, r, rw)
		case wire.PermitDenyDelDenyListEntries:
			return rt.PermitDenyDelDenyListEntries(ctx, instance, inFrame, r, rw)
		case wire.PermitDenyDelPermListEntries:
			return rt.PermitDenyDelPermListEntries(ctx, instance, inFrame, r, rw)
		case wire.PermitDenyRightsQuery:
			return rt.PermitDenyRightsQuery(ctx, instance, inFrame, r, rw)
		case wire.PermitDenySetGroupPermitMask:
			return rt.PermitDenySetGroupPermitMask(ctx, instance, inFrame, r, rw)
		}
	case wire.Stats:
		switch inFrame.SubGroup {
		case wire.StatsReportEvents:
			return rt.StatsReportEvents(ctx, instance, inFrame, r, rw)
		}
	case wire.UserLookup:
		switch inFrame.SubGroup {
		case wire.UserLookupFindByEmail:
			return rt.UserLookupFindByEmail(ctx, instance, inFrame, r, rw)

		}
	}

	return ErrRouteNotFound
}
