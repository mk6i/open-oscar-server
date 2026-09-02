package webapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// defaultMemberDirLimit caps how many directory search results are returned
// when the client does not specify nToGet.
const defaultMemberDirLimit = 100

// maxMemberDirTargets caps how many screen names a single memberDir/get may
// resolve. Every target costs its own directory lookup, and the web client only
// ever asks for one, so this bounds the fan-out an arbitrary "t" list can force.
const maxMemberDirTargets = 20

// dirInfoTags are the directory fields carried in both the ODir get reply and
// the locate set request. SetDirectoryInfo replaces every column, so
// memberDir/update re-sends all of them to preserve fields the web form (which
// only edits first/last name) does not touch.
var dirInfoTags = []uint16{
	wire.ODirTLVFirstName,
	wire.ODirTLVLastName,
	wire.ODirTLVMiddleName,
	wire.ODirTLVMaidenName,
	wire.ODirTLVCountry,
	wire.ODirTLVState,
	wire.ODirTLVCity,
	wire.ODirTLVNickName,
	wire.ODirTLVZIP,
	wire.ODirTLVAddress,
}

// MemberDirHandler handles Web AIM API member-directory endpoints
// (memberDir/search, memberDir/get, and memberDir/update).
type MemberDirHandler struct {
	DirSearchService DirSearchService
	LocateService    LocateService
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

// MemberDirResults wraps a directory search result set.
type MemberDirResults struct {
	Results MemberDirSearchResults `json:"results" xml:"results"`
}

// MemberDirSearchResults is the matched profile list plus its counters. All three
// counters are required: clients read them strictly.
type MemberDirSearchResults struct {
	NTotal    int             `json:"nTotal" xml:"nTotal"`
	NSkipped  int             `json:"nSkipped" xml:"nSkipped"`
	NProfiles int             `json:"nProfiles" xml:"nProfiles"`
	InfoArray []MemberDirInfo `json:"infoArray" xml:"infoArray>info"`
}

// MemberDirInfoArray is the list of matched profiles.
type MemberDirInfoArray struct {
	InfoArray []MemberDirInfo `json:"infoArray" xml:"infoArray>info"`
}

// Search handles GET /memberDir/search. The web client sends the raw add-contact
// input as a "match" parameter shaped like "keyword=<x>" or
// "firstName=<x>,lastName=<y>". We translate that into an OSCAR ODir InfoQuery
// and let the ODir service pick the search mode.
func (h *MemberDirHandler) Search(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	fields := parseMatch(r.URL.Query().Get("match"))
	self := session.ScreenName.IdentScreenName()

	// ODir matches interests, names and email but never the screen name, so an
	// identity lookup runs alongside the directory search.
	profiles := make([]MemberDirProfile, 0, 8)
	seen := make(map[string]bool)
	addProfile := func(profile MemberDirProfile) {
		// Exclude the requesting user from their own search results.
		if profile.AimID == "" || profile.AimID == self.String() || seen[profile.AimID] {
			return
		}
		seen[profile.AimID] = true
		profiles = append(profiles, profile)
	}

	if profile, found := h.exactScreenNameMatch(ctx, fields["keyword"]); found {
		addProfile(profile)
	}

	// A failed directory search is not fatal: the screen-name match may still stand.
	if reply, err := h.DirSearchService.InfoQuery(ctx, wire.SNACFrame{}, buildDirInfoQuery(fields)); err != nil {
		h.Logger.ErrorContext(ctx, "memberDir search failed", "err", err.Error())
	} else if body, ok := reply.Body.(wire.SNAC_0x0F_0x03_InfoReply); ok && body.Status == wire.ODirSearchResponseOK {
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
			addProfile(profile)
		}
	}

	limit := defaultMemberDirLimit
	if v := r.URL.Query().Get("nToGet"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	skip := 0
	if v := r.URL.Query().Get("nToSkip"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			skip = n
		}
	}
	// matched counts every profile the query matched; infoArray holds the page of
	// them this response carries, after nToSkip and nToGet are applied.
	matched := 0
	infoArray := make([]MemberDirInfo, 0, len(profiles))
	for _, profile := range profiles {
		matched++
		if matched <= skip {
			continue
		}
		if len(infoArray) >= limit {
			continue
		}
		infoArray = append(infoArray, MemberDirInfo{Profile: profile})
	}

	h.Logger.DebugContext(ctx, "memberDir search",
		"aimsid", session.AimSID,
		"match", r.URL.Query().Get("match"),
		"results", len(infoArray),
	)

	SendOK(w, r, &MemberDirResults{Results: MemberDirSearchResults{
		NTotal:    matched,
		NSkipped:  skip,
		NProfiles: len(infoArray),
		InfoArray: infoArray,
	}}, h.Logger)
}

// exactScreenNameMatch resolves query as a screen name, reporting whether a user
// by that name exists along with their directory profile.
func (h *MemberDirHandler) exactScreenNameMatch(ctx context.Context, query string) (MemberDirProfile, bool) {
	query = strings.TrimSpace(query)
	if query == "" {
		return MemberDirProfile{}, false
	}

	reply, err := h.LocateService.DirInfo(ctx, wire.SNACFrame{}, wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: query})
	if err != nil {
		h.Logger.ErrorContext(ctx, "memberDir search: screen name lookup failed",
			"screenName", query, "err", err.Error())
		return MemberDirProfile{}, false
	}
	body, ok := reply.Body.(wire.SNAC_0x02_0x0C_LocateGetDirReply)
	if !ok {
		return MemberDirProfile{}, false
	}
	// DirInfo answers for any name, appending directory TLVs only for a user that
	// exists, so their presence — not their values — is the existence test.
	if !body.HasTag(wire.ODirTLVFirstName) {
		return MemberDirProfile{}, false
	}

	profile := MemberDirProfile{
		AimID:     state.NewIdentScreenName(query).String(),
		DisplayID: query,
	}
	profile.FirstName, _ = body.String(wire.ODirTLVFirstName)
	profile.LastName, _ = body.String(wire.ODirTLVLastName)
	profile.State, _ = body.String(wire.ODirTLVState)
	profile.City, _ = body.String(wire.ODirTLVCity)
	profile.Country, _ = body.String(wire.ODirTLVCountry)
	return profile, true
}

// Get handles GET /memberDir/get. The "t" param names the screen names to look
// up, defaulting to the caller when absent. Each returned profile carries the
// identity of the target it describes.
func (h *MemberDirHandler) Get(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	targets := parseTargets(r.URL.Query().Get("t"))
	if len(targets) == 0 {
		targets = []string{session.ScreenName.String()}
	}
	if len(targets) > maxMemberDirTargets {
		h.Logger.WarnContext(ctx, "memberDir get: truncating oversized target list",
			"aimsid", session.AimSID,
			"requested", len(targets),
			"cap", maxMemberDirTargets,
		)
		targets = targets[:maxMemberDirTargets]
	}

	infoArray := make([]MemberDirInfo, 0, len(targets))
	for _, target := range targets {
		reply, err := h.LocateService.DirInfo(ctx, wire.SNACFrame{}, wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: target})
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
		profile.AimID = state.NewIdentScreenName(target).String()
		profile.DisplayID = target
		infoArray = append(infoArray, MemberDirInfo{Profile: profile})
	}

	h.Logger.DebugContext(ctx, "memberDir get",
		"aimsid", session.AimSID,
		"targets", len(targets),
	)

	SendOK(w, r, &MemberDirInfoArray{InfoArray: infoArray}, h.Logger)
}

// Update handles /memberDir/update over GET and POST. Clients send repeated
// "set=key=value" params; first and last name are persisted to the directory
// record and every other field is ignored, having nowhere to be stored.
//
// SetDirectoryInfo replaces the whole directory record, so we read the current
// info first and re-send every field, overlaying only what the form changed.
func (h *MemberDirHandler) Update(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	sets := memberDirSets(r)

	// Seed from the current record so untouched fields survive the replace. A
	// failed read must abort: writing a record we couldn't seed would blank
	// every field the form doesn't edit.
	reply, err := h.LocateService.DirInfo(ctx, wire.SNACFrame{}, wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: session.ScreenName.String()})
	if err != nil {
		h.Logger.ErrorContext(ctx, "memberDir update: failed to read current dir info", "err", err.Error())
		SendEnvelopeStatus(w, r, http.StatusInternalServerError, "failed to update directory info", h.Logger)
		return
	}
	body, ok := reply.Body.(wire.SNAC_0x02_0x0C_LocateGetDirReply)
	if !ok {
		h.Logger.ErrorContext(ctx, "memberDir update: unexpected dir info reply", "body", fmt.Sprintf("%T", reply.Body))
		SendEnvelopeStatus(w, r, http.StatusInternalServerError, "failed to update directory info", h.Logger)
		return
	}

	values := make(map[uint16]string, len(dirInfoTags))
	for _, tag := range dirInfoTags {
		if v, ok := body.String(tag); ok {
			values[tag] = v
		}
	}

	// Overlay the form's edits. Assign unconditionally so clearing a name field
	// (the client sends "firstName=" with an empty value) is honored.
	if v, ok := sets["firstName"]; ok {
		values[wire.ODirTLVFirstName] = v
	}
	if v, ok := sets["lastName"]; ok {
		values[wire.ODirTLVLastName] = v
	}

	inBody := wire.SNAC_0x02_0x09_LocateSetDirInfo{}
	for _, tag := range dirInfoTags {
		inBody.Append(wire.NewTLVBE(tag, values[tag]))
	}

	if _, err := h.LocateService.SetDirInfo(ctx, session.OSCARSession, wire.SNACFrame{}, inBody); err != nil {
		h.Logger.ErrorContext(ctx, "memberDir update failed", "err", err.Error())
		SendEnvelopeStatus(w, r, http.StatusInternalServerError, "failed to update directory info", h.Logger)
		return
	}

	h.Logger.InfoContext(ctx, "memberDir update",
		"aimsid", session.AimSID,
		"firstName", values[wire.ODirTLVFirstName],
		"lastName", values[wire.ODirTLVLastName],
	)

	SendOK(w, r, struct{}{}, h.Logger)
}

// buildDirInfoQuery maps the web client's parsed "match" fields onto ODir search
// TLVs. The client only ever sends two shapes: "firstName=<x>,lastName=<y>"
// (input split on the last space) or "keyword=<x>" (everything else). Name
// search takes precedence over interest-keyword search.
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
		// "keyword" carries either an interest or an identifier. An address can
		// only be the latter, and ODir searches email directly.
		if kw := fields["keyword"]; strings.Contains(kw, "@") {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVEmailAddress, kw))
		} else {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVInterest, kw))
		}
	}
	return inBody
}

// parseMatch splits a client's "match" value ("key=value,key=value") into a field
// map. Values may carry a second layer of escaping, so they are unescaped
// after the split, the separators never being escaped themselves.
func parseMatch(match string) map[string]string {
	fields := make(map[string]string)
	for pair := range strings.SplitSeq(match, ",") {
		key, val, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if key = strings.TrimSpace(key); key == "" {
			continue
		}
		if unescaped, err := url.PathUnescape(val); err == nil {
			val = unescaped
		}
		fields[key] = strings.TrimSpace(val)
	}
	return fields
}

// memberDirSets reads the repeated "set" params into a field map. Body values arrive
// doubly encoded and need a second unescape; query values are already decoded, and
// unescaping those again would corrupt a literal '%'.
func memberDirSets(r *http.Request) map[string]string {
	fields := parseSet(r.URL.Query()["set"])
	for key, val := range parseSet(bodyValues(r, "set")) {
		if decoded, err := url.QueryUnescape(val); err == nil {
			val = decoded
		}
		fields[key] = val
	}
	return fields
}

// parseSet parses the repeated "set=key=value" params the update form sends
// into a field map.
func parseSet(sets []string) map[string]string {
	fields := make(map[string]string)
	for _, s := range sets {
		key, val, ok := strings.Cut(s, "=")
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
