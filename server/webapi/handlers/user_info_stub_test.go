package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AIM Express asks for the service list at sign-on and reads every field of
// each entry, so the payload names them all rather than omitting the false ones.
func TestGetServicesAdvertisesAIMAlone(t *testing.T) {
	h := &UserInfoStubHandler{}

	rr := httptest.NewRecorder()
	h.GetServices(rr, httptest.NewRequest(http.MethodGet, "/getServices?f=json&r=1", nil))

	require.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				Services []map[string]any `json:"services"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "body: %s", rr.Body.String())

	assert.Equal(t, 200, body.Response.StatusCode)
	require.Len(t, body.Response.Data.Services, 1)

	svc := body.Response.Data.Services[0]
	assert.Equal(t, "aim", svc["name"])
	assert.Equal(t, "aim", svc["service"])
	assert.Equal(t, true, svc["associated"])
	assert.Equal(t, true, svc["online"])
	// A roster here means a third-party friend list to import, not the buddy list.
	assert.Equal(t, false, svc["roster"])
	assert.Equal(t, false, svc["haveRoster"])
	for _, field := range []string{"autoLogin", "signupURL"} {
		assert.Contains(t, svc, field, "client reads %s unconditionally", field)
	}
}
