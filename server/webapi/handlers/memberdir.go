package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// defaultMemberDirLimit caps how many directory search results are returned
// when the client does not specify nToGet.
const defaultMemberDirLimit = 100

// DirSearchService issues OSCAR ODir directory searches. A single InfoQuery
// dispatches to name/address, email, or interest-keyword search based on which
// TLVs the query carries.
type DirSearchService interface {
	InfoQuery(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0F_0x02_InfoQuery) (wire.SNACMessage, error)
}

// MemberDirLocateService retrieves a user's stored directory info by screen
// name. memberDir/get uses this to return the caller's own directory profile.
type MemberDirLocateService interface {
	DirInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x0B_LocateGetDirInfo) (wire.SNACMessage, error)
}

// MemberDirHandler handles Web AIM API member-directory endpoints
// (memberDir/search and memberDir/get).
type MemberDirHandler struct {
	DirSearchService DirSearchService
	LocateService    MemberDirLocateService
	Logger           *slog.Logger
}

// MemberDirProfile is the per-result directory profile the web client consumes.
// The client keys users by AimID and, for its own directory info, renders
// FirstName/LastName.
type MemberDirProfile struct {
	AimID     string `json:"aimId" xml:"aimId"`
	DisplayID string `json:"displayId,omitempty" xml:"displayId,omitempty"`
	FirstName string `json:"firstName,omitempty" xml:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty" xml:"lastName,omitempty"`
	State     string `json:"state,omitempty" xml:"state,omitempty"`
	City      string `json:"city,omitempty" xml:"city,omitempty"`
	Country   string `json:"country,omitempty" xml:"country,omitempty"`
}

// MemberDirInfo wraps a profile in the "info" envelope the client expects:
// results are read as data.results.infoArray[i].profile for search and
// data.infoArray[0].profile for get.
type MemberDirInfo struct {
	Profile MemberDirProfile `json:"profile" xml:"profile"`
}

// Search handles GET /memberDir/search. The web client sends the raw add-contact
// input as a "match" parameter shaped like "keyword=<x>" or
// "firstName=<x>,lastName=<y>". We translate that into an OSCAR ODir InfoQuery
// and let the ODir service pick the search mode.
func (h *MemberDirHandler) Search(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

	fields := parseMatch(r.URL.Query().Get("match"))
	inBody := buildDirInfoQuery(fields)

	reply, err := h.DirSearchService.InfoQuery(ctx, wire.SNACFrame{}, inBody)
	if err != nil {
		h.Logger.ErrorContext(ctx, "memberDir search failed", "err", err.Error())
		h.sendData(w, r, map[string]any{"results": map[string]any{"infoArray": []MemberDirInfo{}}})
		return
	}

	body, ok := reply.Body.(wire.SNAC_0x0F_0x03_InfoReply)
	if !ok || body.Status != wire.ODirSearchResponseOK {
		// Missing/insufficient params or an empty directory: return no results
		// rather than an error so the client simply shows an empty result set.
		h.sendData(w, r, map[string]any{"results": map[string]any{"infoArray": []MemberDirInfo{}}})
		return
	}

	limit := defaultMemberDirLimit
	if v := r.URL.Query().Get("nToGet"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	self := session.ScreenName.IdentScreenName()

	infoArray := make([]MemberDirInfo, 0, len(body.Results.List))
	for _, result := range body.Results.List {
		profile := MemberDirProfile{}
		if sn, ok := result.String(wire.ODirTLVScreenName); ok && sn != "" {
			profile.DisplayID = sn
			profile.AimID = state.NewIdentScreenName(sn).String()
		}
		profile.FirstName, _ = result.String(wire.ODirTLVFirstName)
		profile.LastName, _ = result.String(wire.ODirTLVLastName)
		profile.State, _ = result.String(wire.ODirTLVState)
		profile.City, _ = result.String(wire.ODirTLVCity)
		profile.Country, _ = result.String(wire.ODirTLVCountry)
		// Exclude the requesting user from their own search results.
		if state.NewIdentScreenName(profile.DisplayID).String() == self.String() {
			continue
		}
		infoArray = append(infoArray, MemberDirInfo{Profile: profile})
		if len(infoArray) >= limit {
			break
		}
	}

	h.Logger.DebugContext(ctx, "memberDir search",
		"aimsid", session.AimSID,
		"match", r.URL.Query().Get("match"),
		"results", len(infoArray),
	)

	h.sendData(w, r, map[string]any{"results": map[string]any{"infoArray": infoArray}})
}

// Get handles GET /memberDir/get.
func (h *MemberDirHandler) Get(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

	targets := parseTargets(r.URL.Query().Get("t"))
	if len(targets) == 0 {
		targets = []string{session.ScreenName.String()}
	}

	infoArray := make([]MemberDirInfo, 0, len(targets))
	for _, target := range targets {
		reply, err := h.LocateService.DirInfo(ctx, wire.SNACFrame{},
			wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: target})
		if err != nil {
			h.Logger.ErrorContext(ctx, "memberDir get failed", "screenName", target, "err", err.Error())
			continue
		}
		body, ok := reply.Body.(wire.SNAC_0x02_0x0C_LocateGetDirReply)
		if !ok {
			continue
		}
		profile := MemberDirProfile{}
		profile.FirstName, _ = body.String(wire.ODirTLVFirstName)
		profile.LastName, _ = body.String(wire.ODirTLVLastName)
		profile.State, _ = body.String(wire.ODirTLVState)
		profile.City, _ = body.String(wire.ODirTLVCity)
		profile.Country, _ = body.String(wire.ODirTLVCountry)
		profile.AimID = session.ScreenName.IdentScreenName().String()
		profile.DisplayID = session.ScreenName.String()
		infoArray = append(infoArray, MemberDirInfo{Profile: profile})
	}

	h.Logger.DebugContext(ctx, "memberDir get",
		"aimsid", session.AimSID,
		"targets", len(targets),
	)

	h.sendData(w, r, map[string]any{"infoArray": infoArray})
}

// sendData wraps data in the standard response envelope and sends it via
// SendResponse, which honors the JSONP callback the web client uses.
func (h *MemberDirHandler) sendData(w http.ResponseWriter, r *http.Request, data any) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = data
	SendResponse(w, r, resp, h.Logger)
}

// buildDirInfoQuery maps the web client's parsed "match" fields onto ODir search
// TLVs. The client only ever sends two shapes: "firstName=<x>,lastName=<y>"
// (input split on the first space) or "keyword=<x>" (everything else, including
// a typed email). Name search takes precedence over interest-keyword search.
func buildDirInfoQuery(fields map[string]string) wire.SNAC_0x0F_0x02_InfoQuery {
	inBody := wire.SNAC_0x0F_0x02_InfoQuery{}
	switch {
	case fields["firstName"] != "" || fields["lastName"] != "":
		if v := fields["firstName"]; v != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVFirstName, v))
		}
		if v := fields["lastName"]; v != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVLastName, v))
		}
	case fields["keyword"] != "":
		inBody.Append(wire.NewTLVBE(wire.ODirTLVInterest, fields["keyword"]))
	}
	return inBody
}

// parseMatch splits the web client's "match" value ("key=value,key=value")
// into a field map.
func parseMatch(match string) map[string]string {
	fields := make(map[string]string)
	for pair := range strings.SplitSeq(match, ",") {
		key, val, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if key = strings.TrimSpace(key); key != "" {
			fields[key] = strings.TrimSpace(val)
		}
	}
	return fields
}

// parseTargets splits a comma-separated "t" screen-name list, trimming blanks.
func parseTargets(t string) []string {
	var targets []string
	for name := range strings.SplitSeq(t, ",") {
		if name = strings.TrimSpace(name); name != "" {
			targets = append(targets, name)
		}
	}
	return targets
}
