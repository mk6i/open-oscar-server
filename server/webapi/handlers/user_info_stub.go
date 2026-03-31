package handlers

import (
	"log/slog"
	"net/http"
)

type UserInfoStubHandler struct {
	Logger *slog.Logger
}

func (h *UserInfoStubHandler) GetLocationsFollowing(w http.ResponseWriter, r *http.Request) {
	h.emptyOK(w, r)
}

func (h *UserInfoStubHandler) GetUserDetails(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"userDetails": map[string]interface{}{
			"services": []map[string]interface{}{},
		},
	}
	SendResponse(w, r, resp, h.Logger)
}

func (h *UserInfoStubHandler) EmptyOK(w http.ResponseWriter, r *http.Request) {
	h.emptyOK(w, r)
}

func (h *UserInfoStubHandler) emptyOK(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{}
	SendResponse(w, r, resp, h.Logger)
}
