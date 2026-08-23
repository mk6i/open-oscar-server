package handlers

import (
	"log/slog"
	"net/http"
)

type UserInfoStubHandler struct {
	Logger *slog.Logger
}

// UserDetailsData reports which third-party services the account is linked to.
type UserDetailsData struct {
	UserDetails UserDetails `json:"userDetails" xml:"userDetails"`
}

// UserDetails lists the linked services.
type UserDetails struct {
	Services []UserService `json:"services" xml:"services>service"`
}

// UserService names one linked service.
type UserService struct {
	Service string `json:"service" xml:"service"`
}

// NotificationsData is the social-notification feed, which this server does not
// keep.
type NotificationsData struct {
	// Activities is always sent, empty included: the client maps over it
	// unconditionally on a 200.
	Activities []string `json:"activities" xml:"activities>activity"`
}

// ServicesData lists the IM services the account can sign on to.
type ServicesData struct {
	// Services is always sent, empty included: the client iterates it
	// unconditionally on a 200.
	Services []Service `json:"services" xml:"services>service"`
}

// Service describes one signed-on or linkable IM service. Every field is sent
// even when false or empty, because the client reads each one unconditionally
// rather than testing for its presence.
type Service struct {
	Name       string `json:"name" xml:"name"`
	Service    string `json:"service" xml:"service"`
	Associated bool   `json:"associated" xml:"associated"`
	Online     bool   `json:"online" xml:"online"`
	// Roster is a third-party friend list available to import, not the buddy
	// list; this server federates with nothing, so there is never one.
	Roster     bool   `json:"roster" xml:"roster"`
	HaveRoster bool   `json:"haveRoster" xml:"haveRoster"`
	AutoLogin  bool   `json:"autoLogin" xml:"autoLogin"`
	SignupURL  string `json:"signupURL" xml:"signupURL"`
}

// GetServices advertises AIM as the only service, already signed on. The client
// asks at sign-on to build its service list and to decide whether to offer a
// link-account prompt for the others.
func (h *UserInfoStubHandler) GetServices(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &ServicesData{
		Services: []Service{
			{
				Name:       "aim",
				Service:    "aim",
				Associated: true,
				Online:     true,
			},
		},
	}
	SendResponse(w, r, resp, h.Logger)
}

func (h *UserInfoStubHandler) GetUserDetails(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &UserDetailsData{
		UserDetails: UserDetails{Services: []UserService{{Service: "aim"}}},
	}
	SendResponse(w, r, resp, h.Logger)
}

// HeyGetNotifications returns an empty social-notification feed.
//
// The activities array must be present even when empty: the client maps over
// response.data.activities unconditionally on a 200, so omitting it raises
// "Array.prototype.map called on null or undefined" and aborts the rest of the
// notification setup.
func (h *UserInfoStubHandler) HeyGetNotifications(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &NotificationsData{Activities: []string{}}
	SendResponse(w, r, resp, h.Logger)
}

func (h *UserInfoStubHandler) EmptyOK(w http.ResponseWriter, r *http.Request) {
	h.emptyOK(w, r)
}

func (h *UserInfoStubHandler) emptyOK(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}
