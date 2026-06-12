package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttachRequestID(t *testing.T) {
	t.Run("sets requestId from r query param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/buddylist/addBuddy?r=abc123", nil)
		data := attachRequestID(req, BaseResponse{
			Response: ResponseBody{
				StatusCode: 200,
				StatusText: "OK",
			},
		})

		br, ok := data.(BaseResponse)
		assert.True(t, ok)
		assert.Equal(t, "abc123", br.Response.RequestID)
	})

	t.Run("preserves explicit requestId", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/buddylist/addBuddy?r=abc123", nil)
		data := attachRequestID(req, BaseResponse{
			Response: ResponseBody{
				StatusCode: 200,
				StatusText: "OK",
				RequestID:  "existing",
			},
		})

		br, ok := data.(BaseResponse)
		assert.True(t, ok)
		assert.Equal(t, "existing", br.Response.RequestID)
	})

	t.Run("no-op without r param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/buddylist/addBuddy", nil)
		data := attachRequestID(req, BaseResponse{
			Response: ResponseBody{
				StatusCode: 200,
				StatusText: "OK",
			},
		})

		br, ok := data.(BaseResponse)
		assert.True(t, ok)
		assert.Empty(t, br.Response.RequestID)
	})
}

func TestSendResponseIncludesRequestID(t *testing.T) {
	req := httptest.NewRequest("GET", "/buddylist/addBuddy?r=req-42&f=json", nil)
	rr := httptest.NewRecorder()

	resp := BaseResponse{
		Response: ResponseBody{
			StatusCode: 200,
			StatusText: "OK",
			Data:       map[string]string{"resultCode": "success"},
		},
	}
	SendResponse(rr, req, resp, slog.Default())

	assert.Equal(t, http.StatusOK, rr.Code)
	body := strings.TrimSpace(rr.Body.String())
	assert.Equal(t, `{"response":{"statusCode":200,"statusText":"OK","requestId":"req-42","data":{"resultCode":"success"}}}`, body)
}
