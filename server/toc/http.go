package toc

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/html"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// profileTpl is the profile lookup response go template.
const profileTpl = `
<HTML><HEAD><TITLE>Profile Lookup</TITLE></HEAD><BODY>
Username : <B>{{- .ScreenName -}}</B><BR><BR>
{{ .Profile }}
</BODY></HTML>`

// directoryTpl is the directory search response go template.
const directoryTpl = `
<HTML><HEAD><TITLE>Open OSCAR Server</TITLE></HEAD><BODY><H3>Dir Results</H3>
{{- if .Results -}}
<TABLE>
{{- range .Results -}}
<TR><TD>
{{- if .FirstName}}<B>First Name:</B> {{.FirstName}}<BR>{{- end -}}
{{- if .MiddleName}}<B>Middle Name:</B> {{.MiddleName}}<BR>{{- end -}}
{{- if .LastName}}<B>Last Name:</B> {{.LastName}}<BR>{{- end -}}
{{- if .MaidenName}}<B>Maiden Name:</B> {{.MaidenName}}<BR>{{- end -}}
{{- if .Country}}<B>Country:</B> {{.Country}}<BR>{{- end -}}
{{- if .State}}<B>State:</B> {{.State}}<BR>{{- end -}}
{{- if .City}}<B>City:</B> {{.City}}<BR>{{- end -}}
{{- if .NickName}}<B>Nick Name:</B> {{.NickName}}<BR>{{- end -}}
{{- if .ZIP}}<B>ZIP Code:</B> {{.ZIP}}<BR>{{- end -}}
{{- if .Address}}<B>Address :</B> {{.Address}}<BR>{{- end -}}
</TD></TR>
{{- end -}}
</TABLE>
{{- else -}}
<BR>No results found.
{{- end -}}
</BODY></HTML>`

var (
	profileTemplate   *template.Template
	directoryTemplate *template.Template
)

func init() {
	var err error
	profileTemplate, err = template.New("profile").Parse(profileTpl)
	if err != nil {
		panic(fmt.Errorf("failed to compile profile template: %w", err))
	}

	directoryTemplate, err = template.New("directory").Parse(directoryTpl)
	if err != nil {
		panic(fmt.Errorf("failed to compile directory template: %w", err))
	}
}

// NewServeMux creates and returns an HTTP mux that serves all TOC routes.
func (s OSCARProxy) NewServeMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /info", s.RateLimiterMiddleware(s.AuthMiddleware(http.HandlerFunc(s.ProfileHandler))))
	mux.Handle("GET /dir_info", s.RateLimiterMiddleware(s.AuthMiddleware(http.HandlerFunc(s.DirInfoHandler))))
	mux.Handle("GET /dir_search", s.RateLimiterMiddleware(s.AuthMiddleware(http.HandlerFunc(s.DirSearchHandler))))
	return mux
}

func (s OSCARProxy) RateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			s.Logger.Error("failed to parse remote address", "err", err.Error())
			return
		}

		if !s.HTTPIPRateLimiter.Allow(ip) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware is an HTTP middleware that enforces authentication using an
// authorization cookie provided as a query parameter. It validates and decrypts
// the cookie before allowing the request to proceed.
//
// If the `cookie` query parameter is missing or invalid, the middleware
// responds with an appropriate HTTP error:
//   - 400 Bad Request if the `cookie` parameter is missing.
//   - 403 Forbidden if the cookie is invalid or cannot be decrypted.
//
// Requests with a valid cookie are passed to the next handler.
func (s OSCARProxy) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie := r.URL.Query().Get("cookie")
		if cookie == "" {
			http.Error(w, "required `cookie` param is missing", http.StatusBadRequest)
			return
		}

		data, err := hex.DecodeString(cookie)
		if err != nil {
			s.Logger.DebugContext(ctx, "error decoding string", "err", err.Error())
			http.Error(w, "invalid auth cookie", http.StatusForbidden)
			return
		}

		if _, err = s.CookieBaker.Crack(data); err != nil {
			s.Logger.DebugContext(ctx, "error cracking auth cookie", "err", err.Error())
			http.Error(w, "invalid auth cookie", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ProfileHandler handles requests to retrieve a user's profile information.
// It queries the LocateService to fetch profile data for the specified user.
//
// The request must include the following query parameters:
//   - `from`: The screen name of the user making the request.
//   - `user`: The screen name of the user whose profile is being requested.
//
// If any required parameter is missing, it responds with a 400 Bad Request.
// If the requested user is unavailable, it responds with a 404 Not Found.
func (s OSCARProxy) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	if from == "" {
		http.Error(w, "required `from` param is missing", http.StatusBadRequest)
		return
	}
	user := r.URL.Query().Get("user")
	if user == "" {
		http.Error(w, "required `user` param is missing", http.StatusBadRequest)
		return
	}

	sess := state.NewSession()
	sess.SetIdentScreenName(state.NewIdentScreenName(from))
	inBody := wire.SNAC_0x02_0x05_LocateUserInfoQuery{
		Type:       uint16(wire.LocateTypeSig),
		ScreenName: user,
	}

	ctx := r.Context()
	info, err := s.LocateService.UserInfoQuery(ctx, sess, wire.SNACFrame{}, inBody)
	if err != nil {
		s.logAndReturn500(ctx, w, fmt.Errorf("LocateService.UserInfoQuery: %w", err))
		return
	}

	switch v := info.Body.(type) {
	case wire.SNACError:
		if v.Code == wire.ErrorCodeNotLoggedOn {
			http.Error(w, "user is unavailable", http.StatusNotFound)
		} else {
			s.logAndReturn500(ctx, w, fmt.Errorf("LocateService.UserInfoQuery error code: %d", v.Code))
		}
	case wire.SNAC_0x02_0x06_LocateUserInfoReply:
		profile, hasProf := v.LocateInfo.Bytes(wire.LocateTLVTagsInfoSigData)
		if !hasProf {
			s.logAndReturn500(ctx, w, errors.New("LocateInfo.Bytes: missing wire.LocateTLVTagsInfoSigData"))
			return
		}

		pd := struct {
			ScreenName string
			Profile    template.HTML
		}{
			ScreenName: user,
			Profile:    template.HTML(extractProfile(profile)),
		}

		if err := profileTemplate.Execute(w, pd); err != nil {
			s.logAndReturn500(ctx, w, fmt.Errorf("t.Execute: %w", err))
		}
	default:
		s.logAndReturn500(ctx, w, fmt.Errorf("unknown response type: %T", v))
	}
}

// DirInfoHandler handles requests to retrieve directory information for a user.
// It queries the LocateService to fetch directory details associated with the
// given screen name.
//
// The request must include the following query parameter:
//   - `user`: The screen name of the user whose directory info is being requested.
//
// If the `user` parameter is missing, it responds with a 400 Bad Request.
// If no directory information is found, it responds with a 404 Not Found.
func (s OSCARProxy) DirInfoHandler(w http.ResponseWriter, request *http.Request) {
	user := request.URL.Query().Get("user")
	if user == "" {
		http.Error(w, "required `user` param is missing", http.StatusBadRequest)
		return
	}

	inBody := wire.SNAC_0x02_0x0B_LocateGetDirInfo{
		ScreenName: user,
	}

	ctx := request.Context()
	info, err := s.LocateService.DirInfo(ctx, wire.SNACFrame{}, inBody)
	if err != nil {
		s.logAndReturn500(ctx, w, fmt.Errorf("LocateService.DirInfo: %w", err))
		return
	}

	switch v := info.Body.(type) {
	case wire.SNAC_0x02_0x0C_LocateGetDirReply:
		if len(v.TLVList) > 0 {
			s.outputSearchResults(ctx, w, v.TLVBlock)
		} else {
			http.Error(w, "no user directory info found", http.StatusNotFound)
		}
	default:
		s.logAndReturn500(ctx, w, fmt.Errorf("LocateService.DirInfo: unknown response type: %T", v))
	}
}

// DirSearchHandler handles requests to perform a directory search based on
// various criteria. It queries the DirSearchService to find users matching the
// specified parameters. There are 3 search modes: name, email, keyword.
//
//	-Named-based search is toggled by the presence of either `first_name`
//	and/or `last_name` params. The following search params can be passed:
//		-`first_name`
//	  	-`middle_name`
//		-`last_name`
//		-`maiden_name`
//		-`city`
//		-`state`
//		-`country`
//	-Email-based search is triggered by the`email` param.
//	-Keyword-based search is triggered by the `keyword` param.
//
// If the search is missing required name parameters, it responds with a 400
// Bad Request.
func (s OSCARProxy) DirSearchHandler(w http.ResponseWriter, r *http.Request) {
	inBody := wire.SNAC_0x0F_0x02_InfoQuery{}

	q := r.URL.Query()
	switch {
	case q.Has("first_name") || q.Has("last_name"):
		if val := q.Get("first_name"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVFirstName, val))
		}
		if val := q.Get("middle_name"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVMiddleName, val))
		}
		if val := q.Get("last_name"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVLastName, val))
		}
		if val := q.Get("maiden_name"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVMaidenName, val))
		}
		if val := q.Get("city"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVCity, val))
		}
		if val := q.Get("state"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVState, val))
		}
		if val := q.Get("country"); val != "" {
			inBody.Append(wire.NewTLVBE(wire.ODirTLVCountry, val))
		}
	case q.Has("email"):
		inBody.Append(wire.NewTLVBE(wire.ODirTLVEmailAddress, q.Get("email")))
	case q.Has("keyword"):
		inBody.Append(wire.NewTLVBE(wire.ODirTLVInterest, q.Get("keyword")))
	}

	ctx := r.Context()
	info, err := s.DirSearchService.InfoQuery(ctx, wire.SNACFrame{}, inBody)
	if err != nil {
		s.logAndReturn500(ctx, w, fmt.Errorf("DirSearchService.InfoQuery: %w", err))
		return
	}

	switch v := info.Body.(type) {
	case wire.SNAC_0x0F_0x03_InfoReply:
		switch v.Status {
		case wire.ODirSearchResponseNameMissing:
			http.Error(w, "missing search parameters", http.StatusBadRequest)
		case wire.ODirSearchResponseOK:
			s.outputSearchResults(ctx, w, v.Results.List...)
		default:
			s.logAndReturn500(ctx, w, fmt.Errorf("DirSearchService.InfoQuery unknown status: %d", v.Status))
		}
	default:
		s.logAndReturn500(ctx, w, fmt.Errorf("DirSearchService.InfoQuery: unknown response type: %T", v))
	}
}

func (s OSCARProxy) outputSearchResults(ctx context.Context, w http.ResponseWriter, users ...wire.TLVBlock) {
	type DirSearchResult struct {
		FirstName  string
		MiddleName string
		LastName   string
		MaidenName string
		Country    string
		State      string
		City       string
		NickName   string
		ZIP        string
		Address    string
	}
	type PageData struct {
		Results []DirSearchResult
	}

	results := make([]DirSearchResult, 0, len(users))
	for _, result := range users {
		rec := DirSearchResult{}
		rec.FirstName, _ = result.String(wire.ODirTLVFirstName)
		rec.MiddleName, _ = result.String(wire.ODirTLVMiddleName)
		rec.LastName, _ = result.String(wire.ODirTLVLastName)
		rec.MaidenName, _ = result.String(wire.ODirTLVMaidenName)
		rec.Country, _ = result.String(wire.ODirTLVCountry)
		rec.State, _ = result.String(wire.ODirTLVState)
		rec.City, _ = result.String(wire.ODirTLVCity)
		rec.NickName, _ = result.String(wire.ODirTLVNickName)
		rec.ZIP, _ = result.String(wire.ODirTLVZIP)
		rec.Address, _ = result.String(wire.ODirTLVAddress)
		results = append(results, rec)
	}

	if err := directoryTemplate.Execute(w, PageData{Results: results}); err != nil {
		s.logAndReturn500(ctx, w, fmt.Errorf("t.Execute: %w", err))
	}
}

func (s OSCARProxy) logAndReturn500(ctx context.Context, w http.ResponseWriter, err error) {
	s.Logger.ErrorContext(ctx, "internal service error", "err", err.Error())
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// extractProfile extracts the contents of an HTML <BODY>. If there's no HTML
// body, just return the text.
//
// It only returns the following HTML tags: <b> <i> <font> <a> <u> <br> <hr> <s> <sub> <sup>
func extractProfile(htmlContent []byte) string {
	tokenizer := html.NewTokenizer(bytes.NewReader(htmlContent))
	var bodyContent bytes.Buffer

	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && err != io.EOF {
				return "unable to read profile"
			}
			return bodyContent.String()
		case html.StartTagToken, html.EndTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "b", "i", "font", "a", "u", "br", "hr", "s", "sub", "sup":
				bodyContent.WriteString(token.String())
			}
		case html.TextToken:
			bodyContent.Write(tokenizer.Text())
		}
	}
}
