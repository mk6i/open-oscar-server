package webapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// formPost builds a POST carrying body as its payload, with contentType set only
// when non-empty.
func formPost(body, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestParam(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		key  string
		want string
	}{
		{
			name: "from the query string",
			req:  httptest.NewRequest(http.MethodGet, "/x?aimsid=sid", nil),
			key:  "aimsid",
			want: "sid",
		},
		{
			name: "from a declared form body",
			req:  formPost("s=mikekelly&pwd=hunter2", "application/x-www-form-urlencoded"),
			key:  "s",
			want: "mikekelly",
		},
		{
			// A body may arrive unannounced, and ParseForm ignores one it cannot
			// type.
			name: "from an untyped form body",
			req:  formPost("s=mikekelly&pwd=hunter2", ""),
			key:  "pwd",
			want: "hunter2",
		},
		{
			name: "query wins over body",
			req: func() *http.Request {
				r := formPost("f=xml", "")
				r.URL.RawQuery = "f=json"
				return r
			}(),
			key:  "f",
			want: "json",
		},
		{
			name: "absent from both",
			req:  formPost("s=mikekelly", ""),
			key:  "nope",
			want: "",
		},
		{
			name: "body is not read on a GET",
			req:  httptest.NewRequest(http.MethodGet, "/x", strings.NewReader("s=mikekelly")),
			key:  "s",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, param(tt.req, tt.key))
		})
	}
}

func TestParamLeavesBinaryBodyIntact(t *testing.T) {
	// expressions/upload POSTs a raw image with its parameters on the query string,
	// arriving untyped. A parameter lookup that misses must not hand that body to
	// ParseForm, which would read it to EOF.
	image := "\xff\xd8\xff\xe0 not form data"

	var body string
	var missing string
	handler := WithBinaryBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		missing = param(r, "absent")
		read := make([]byte, len(image))
		n, _ := r.Body.Read(read)
		body = string(read[:n])
	}))

	req := formPost(image, "")
	req.URL.RawQuery = "type=buddyIcon"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, missing)
	assert.Equal(t, image, body, "the image body was consumed by form parsing")
}

func TestParamValues(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want []string
	}{
		{
			name: "repeated in the query string",
			req:  httptest.NewRequest(http.MethodGet, "/x?t=alice&t=bob", nil),
			want: []string{"alice", "bob"},
		},
		{
			name: "repeated in an untyped body",
			req:  formPost("t=alice&t=bob", ""),
			want: []string{"alice", "bob"},
		},
		{
			name: "absent",
			req:  httptest.NewRequest(http.MethodGet, "/x", nil),
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, paramValues(tt.req, "t"))
		})
	}
}

func TestPresenceTargets(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want []string
	}{
		{
			// One repetition per value.
			name: "repeated parameter",
			url:  "/presence/get?t=alice&t=bob&t=carol",
			want: []string{"alice", "bob", "carol"},
		},
		{
			// Comma-separated in a single parameter.
			name: "comma separated",
			url:  "/presence/get?t=alice,bob,carol",
			want: []string{"alice", "bob", "carol"},
		},
		{
			name: "both, with padding and empties discarded",
			url:  "/presence/get?t=alice,+bob&t=&t=carol",
			want: []string{"alice", "bob", "carol"},
		},
		{
			name: "no targets",
			url:  "/presence/get?bl=1",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := presenceTargets(httptest.NewRequest(http.MethodGet, tt.url, nil))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRequestIDFromFormBody(t *testing.T) {
	// A client may POST its correlation id in the body and read response.requestId
	// strictly off the reply, so a query-only read would leave the field empty.
	req := formPost("t=bob&message=hi&r=cookie-42", "")
	assert.Equal(t, "cookie-42", requestIDFromRequest(req))

	rr := httptest.NewRecorder()
	SendOK(rr, req, &SendIMData{MsgID: "msg-1", State: "delivered"}, nil)
	assert.Contains(t, rr.Body.String(), `"requestId":"cookie-42"`)
}
