package oscarclient

import "github.com/mk6i/open-oscar-server/wire"

// statusQuery and warning are request contexts a client might cache with a
// SNAC.
type (
	statusQuery struct {
		screenName string
	}
	warning struct{}
)

// newSNAC returns a SNAC message with the given frame fields and body.
func newSNAC(foodGroup uint16, subGroup uint16, reqID uint32, body any) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: foodGroup,
			SubGroup:  subGroup,
			RequestID: reqID,
		},
		Body: body,
	}
}
