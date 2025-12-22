package foodgroup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestStatsService_ReportEvents(t *testing.T) {
	svc := NewStatsService()

	frame := wire.SNACFrame{
		RequestID: 1234,
	}
	body := wire.SNAC_0x0B_0x03_StatsReportEvents{}

	have := svc.ReportEvents(context.Background(), frame, body)

	want := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Stats,
			SubGroup:  wire.StatsReportAck,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x0B_0x04_StatsReportAck{},
	}

	assert.Equal(t, want, have)
}
