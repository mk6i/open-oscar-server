package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestWebAPISession_GetStoredIMs_NormalizesPartner(t *testing.T) {
	sess := &WebAPISession{}
	sess.AddStoredIM("Mike Kelly", "mikekelly", "hello", "msg-1", 100)

	// The web client queries history by the normalized aimId, never by the
	// display screen name it was stored under.
	msgs := sess.GetStoredIMs(StoredIMQuery{
		PartnerAimID: "mikekelly",
		NToGet:       10,
	})
	require.Len(t, msgs, 1)
	assert.Equal(t, "msg-1", msgs[0]["msgId"])
}
