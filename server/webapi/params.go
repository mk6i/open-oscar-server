package webapi

import (
	"context"
	"mime"
	"net/http"
	"strings"
)

// The Web API is method-agnostic: parameters may arrive on the query string or in a
// form-encoded body, varying by client and by endpoint. The helpers here read either
// location so a handler never has to care.

const formContentType = "application/x-www-form-urlencoded"

// binaryBodyKey marks a request whose body is a payload rather than form fields.
type binaryBodyKey struct{}

// WithBinaryBody marks a request body as a payload the parameter helpers must not
// consume. expressions/upload POSTs a raw untyped image, and without the marker a
// lookup that missed on the query string would hand it to ParseForm, which reads it
// to EOF.
func WithBinaryBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), binaryBodyKey{}, true)))
	})
}

func hasBinaryBody(r *http.Request) bool {
	marked, _ := r.Context().Value(binaryBodyKey{}).(bool)
	return marked
}

// parseBodyForm parses the request body as form fields, reporting whether the form
// is available to read afterwards. It is safe to call repeatedly: ParseForm caches
// its result on the request.
func parseBodyForm(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		return false
	}
	if hasBinaryBody(r) {
		return false
	}

	if ct := r.Header.Get("Content-Type"); ct == "" {
		// ParseForm ignores a body it cannot type, and form bodies often arrive
		// unannounced. A genuinely non-form body is marked by WithBinaryBody.
		r.Header.Set("Content-Type", formContentType)
	} else if mediaType, _, err := mime.ParseMediaType(ct); err != nil || mediaType != formContentType {
		return false
	}

	return r.ParseForm() == nil
}

// param returns a request parameter from the query string, falling back to the
// form-encoded body.
func param(r *http.Request, key string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	if !parseBodyForm(r) {
		return ""
	}
	return r.PostFormValue(key)
}

// paramValues returns every value sent for a repeated parameter, from the query
// string and the form-encoded body both.
func paramValues(r *http.Request, key string) []string {
	return append(r.URL.Query()[key], bodyValues(r, key)...)
}

// bodyValues returns every value sent for a repeated parameter in the form-encoded
// body, ignoring the query string. Most callers want paramValues instead.
func bodyValues(r *http.Request, key string) []string {
	if !parseBodyForm(r) {
		return nil
	}
	return r.PostForm[key]
}

// isTrueParam reports whether a boolean-ish parameter is set. Clients spell these
// inconsistently, so both "1" and "true" are accepted.
func isTrueParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}
