package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebAPISession_GetStoredIMs(t *testing.T) {
	sess := &WebAPISession{}
	sess.AddStoredIM("buddy1", "me", "hello", "msg-1", 100)
	sess.AddStoredIM("buddy1", "buddy1", "hi back", "msg-2", 200)
	sess.AddStoredIM("buddy2", "buddy2", "other chat", "msg-3", 150)

	msgs := sess.GetStoredIMs(StoredIMQuery{
		PartnerAimID: "buddy1",
		SortOrder:    "descendingDate",
		NToGet:       10,
	})
	assert.Len(t, msgs, 2)
	assert.Equal(t, "msg-2", msgs[0]["msgId"])
	assert.Equal(t, float64(200), msgs[0]["date"])
	assert.Equal(t, "hello", msgs[1]["message"])

	msgs = sess.GetStoredIMs(StoredIMQuery{
		PartnerAimID: "buddy1",
		SortOrder:    "ascendingDate",
		StartTime:    150,
		EndTime:      250,
	})
	assert.Len(t, msgs, 1)
	assert.Equal(t, "msg-2", msgs[0]["msgId"])
}
