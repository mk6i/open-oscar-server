package webapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/mk6i/open-oscar-server/wire"
)

// Web API status codes. These are the client's own vocabulary, not HTTP codes,
// and it reads them from the envelope rather than from the HTTP status — which
// is why several of them ship on an HTTP 200 (see SendEnvelopeStatus).
const (
	// statusMoreAuthRequired is what makes a failed sign-in a demand for better
	// credentials rather than an error: paired with the detail code naming what
	// was wrong, it is what tells a client to say "incorrect password".
	statusMoreAuthRequired = 330
	// statusRateLimited is swallowed by the client on the IM path, so that the
	// rateLimit event owns the user-facing message instead of a generic send
	// failure alert.
	statusRateLimited      = 430
	statusMissingParameter = 460
	// statusParameterError is for a parameter that is present but unusable.
	statusParameterError = 462
	// statusNoSuchService is what the client accepts as "this account has no such
	// linked service". Its getAttributes callback treats 601 as an expected
	// outcome and returns early; any other status sends it into the success
	// branch, where it dereferences response.data.serviceName and marks the
	// service associated. A 404 therefore both crashes the callback and, if it
	// did not, would advertise a linked account that does not exist.
	statusNoSuchService = 601
	// statusSendFailed is one of the two codes (602/603) the client recognizes as
	// "recipient offline or blocked". Any other code, and an empty body most of
	// all, falls through to its generic "Bummer. Your message failed." alert.
	statusSendFailed = 602

	// detailBadPassword is the statusDetailCode under statusMoreAuthRequired that
	// names a wrong password specifically.
	detailBadPassword = 3011
)

// BaseResponse is the standard response envelope for all Web API responses.
// It supports both JSON and XML marshaling.
type BaseResponse struct {
	Response ResponseBody `json:"response"`
}

// MarshalXML renders the envelope as the Web API's flat <response> root, where
// JSON nests the same body under a "response" key. Reconciling the two shapes
// here is what lets one struct describe a response in both formats.
func (b BaseResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return e.EncodeElement(b.Response, xml.StartElement{Name: xml.Name{Local: "response"}})
}

// ResponseBody contains the status and data for API responses.
type ResponseBody struct {
	StatusCode int    `json:"statusCode" xml:"statusCode"`
	StatusText string `json:"statusText" xml:"statusText"`
	RequestID  string `json:"requestId,omitempty" xml:"requestId,omitempty"`
	// Data is never omitted. Every Web API method sends a data element even when
	// it carries no payload, and the client dereferences response.data on any
	// success; SendResponse substitutes an empty object when a handler sets none.
	Data interface{} `json:"data" xml:"data"`
}

// ErrorResponse represents an error response with proper XML/JSON support.
type ErrorResponse struct {
	Response struct {
		StatusCode int `json:"statusCode" xml:"statusCode"`
		// StatusDetailCode names which failure of a status code this is, e.g. 3011
		// (bad password) under 330. Omitted when unset, which a client would
		// otherwise read as a detail code of its own.
		StatusDetailCode int    `json:"statusDetailCode,omitempty" xml:"statusDetailCode,omitempty"`
		StatusText       string `json:"statusText" xml:"statusText"`
		// RequestID echoes the client's correlation id, the same way BaseResponse
		// carries it. A client that indexes replies by it cannot match a failure
		// that omits it, so an error needs it as much as a success does.
		RequestID string `json:"requestId,omitempty" xml:"requestId,omitempty"`
		// Data carries an empty object for the same reason the JSONP error path
		// sends one: a client callback that reaches response.data on a failure
		// throws a TypeError when it is absent.
		Data interface{} `json:"data" xml:"data"`
	} `json:"response"`
}

// MarshalXML renders the error envelope with the same flat root as BaseResponse.
func (e ErrorResponse) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	return enc.EncodeElement(e.Response, xml.StartElement{Name: xml.Name{Local: "response"}})
}

// newErrorResponse builds the error envelope every format shares.
func newErrorResponse(statusCode int, message string) ErrorResponse {
	return newErrorResponseDetail(statusCode, 0, message)
}

// newErrorResponseDetail builds the error envelope with a statusDetailCode.
func newErrorResponseDetail(statusCode, detailCode int, message string) ErrorResponse {
	resp := ErrorResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusDetailCode = detailCode
	resp.Response.StatusText = message
	resp.Response.Data = struct{}{}
	return resp
}

// requestFormat returns the format the client asked for. A POST sends "f" in
// its body, as clientLogin does.
func requestFormat(r *http.Request) string {
	return strings.ToLower(param(r, "f"))
}

// requestIDFromRequest returns the client's correlation id from the "r" parameter,
// echoed in response.requestId on every path. It may arrive in the POST body, so it
// is read from either location.
func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return param(r, "r")
}

// normalizeEnvelope fills in the envelope fields a handler does not set itself:
// the request correlation id, and an empty data object for a response that
// carries no payload. Both are things every encoder needs and none can infer —
// and encoding/xml has no way to render a nil data at all.
func normalizeEnvelope(r *http.Request, data interface{}) interface{} {
	br, ok := data.(BaseResponse)
	if !ok {
		return data
	}
	if br.Response.RequestID == "" {
		br.Response.RequestID = requestIDFromRequest(r)
	}
	if br.Response.Data == nil {
		br.Response.Data = struct{}{}
	}
	return br
}

// SendResponse sends a response in the requested format (JSON, JSONP, XML, or AMF).
// This is the centralized function that all handlers should use for responses.
func SendResponse(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	data = normalizeEnvelope(r, data)

	format := requestFormat(r)
	callback := jsonpCallback(r)

	// Check for AMF format first
	if format == "amf" || format == "amf3" {
		sendAMF(w, r, data, logger)
		return
	}

	// Check Accept header for AMF
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/x-amf") ||
		strings.Contains(accept, "application/amf") {
		sendAMF(w, r, data, logger)
		return
	}

	// If callback is provided, it's JSONP
	if callback != "" {
		sendJSONP(w, r, callback, data, logger)
		return
	}

	// Check for XML format
	if format == "xml" {
		sendXML(w, data, logger)
		return
	}

	// Default to JSON
	sendJSON(w, data, logger)
}

// SendError sends an error response in the format the client asked for.
//
// When the client requested JSONP, the error must be delivered as an executable
// callback: a bare JSON body inside a <script> tag is a syntax error, which the
// Web AIM client reports as the generic "Failed to load script tag, probably
// malformed JS at that url" instead of the real statusText.
func SendError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	sendErrorEnvelope(w, r, statusCode, newErrorResponse(statusCode, message))
}

// SendErrorDetail sends an error carrying a statusDetailCode, which is how a
// client tells one failure of a status code from another. The HTTP status is
// separate because the API codes are not HTTP codes: a bad clientLogin password
// is 330/3011 on an HTTP 401.
func SendErrorDetail(w http.ResponseWriter, r *http.Request, httpStatus, statusCode, detailCode int, message string) {
	sendErrorEnvelope(w, r, httpStatus, newErrorResponseDetail(statusCode, detailCode, message))
}

// SendOK sends the success envelope every Web API method answers with, carrying
// data as its payload.
//
// Pass nil for a bare acknowledgement: SendResponse substitutes the empty data
// object the client dereferences unconditionally on success.
func SendOK(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	resp.Response.Data = data
	SendResponse(w, r, resp, logger)
}

// SendEnvelopeStatus reports a non-success outcome that the client must read
// from the envelope, leaving the HTTP status at 200.
//
// This is the counterpart to SendError, which puts the code on the HTTP response
// too. Use it where a 4xx would keep the client from ever reading statusCode: the
// AIM client's request layer routes any non-2xx to its error handlers, which
// synthesize a generic failure and never look at the body. That makes the
// difference between "recipient is offline" (602) or "no such linked service"
// (601) and a generic "your message failed" alert.
//
// It carries no data element; SendResponse substitutes an empty one. A caller
// that needs to send data alongside a non-200 status builds the envelope itself.
func SendEnvelopeStatus(w http.ResponseWriter, r *http.Request, statusCode int, statusText string, logger *slog.Logger) {
	resp := BaseResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusText = statusText
	SendResponse(w, r, resp, logger)
}

// sendErrorEnvelope writes an error envelope in the format the client asked for.
func sendErrorEnvelope(w http.ResponseWriter, r *http.Request, httpStatus int, resp ErrorResponse) {
	resp.Response.RequestID = requestIDFromRequest(r)

	if callback := jsonpCallback(r); callback != "" && isValidCallback(callback) {
		sendJSONPError(w, r, callback, resp)
		return
	}

	// A client that gets a format it cannot parse reports the failure as an
	// unreadable response rather than as this statusText. The Content-Type is the
	// fallback signal, naming the format a handler already began writing.
	format := requestFormat(r)
	contentType := w.Header().Get("Content-Type")

	switch {
	case format == "xml" || strings.Contains(contentType, "xml"):
		sendXMLError(w, httpStatus, resp)
	case format == "amf" || format == "amf3" || strings.Contains(contentType, "amf"):
		sendAMFError(w, httpStatus, resp)
	default:
		sendJSONError(w, httpStatus, resp)
	}
}

// sendJSONPError writes an error envelope wrapped in the client's JSONP callback.
//
// The HTTP status is deliberately left at 200: browsers do not execute the body
// of a <script> tag that came back with a 4xx or 5xx, so a status-carrying JSONP
// error never reaches the callback at all. The real status travels in the
// envelope, which is where the Web AIM client reads it from regardless.
func sendJSONPError(w http.ResponseWriter, r *http.Request, callback string, resp ErrorResponse) {
	envelope := map[string]any{
		"statusCode": resp.Response.StatusCode,
		"statusText": resp.Response.StatusText,
		// Callbacks that reach response.data on a failure throw a TypeError when
		// it is absent, which aborts whatever the client was doing mid-startup.
		// Its XHR path fabricates an empty data for transport failures; JSONP
		// delivers the envelope verbatim, so the empty data has to come from here.
		"data": map[string]any{},
	}
	if resp.Response.StatusDetailCode != 0 {
		envelope["statusDetailCode"] = resp.Response.StatusDetailCode
	}
	// The client indexes JSONP replies by response.requestId and discards any
	// reply that lacks one ("Request id is missing from the server response"),
	// leaving the request pending until it times out.
	if id := requestIDFromRequest(r); id != "" {
		envelope["requestId"] = id
	}

	body, err := json.Marshal(map[string]any{"response": envelope})
	if err != nil {
		sendJSONError(w, http.StatusInternalServerError, newErrorResponse(http.StatusInternalServerError, "internal server error"))
		return
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write([]byte(callback))
	_, _ = w.Write([]byte("("))
	_, _ = w.Write(body)
	_, _ = w.Write([]byte(");"))
}

// sendJSONError sends a JSON error response.
func sendJSONError(w http.ResponseWriter, httpStatus int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(resp)
}

// sendXMLError sends an XML error response.
func sendXMLError(w http.ResponseWriter, httpStatus int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(httpStatus)

	// Write XML declaration and marshal the response
	xmlData, err := xml.Marshal(resp)
	if err != nil {
		// Fall back to simple text response
		http.Error(w, resp.Response.StatusText, httpStatus)
		return
	}

	xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)
	_, _ = w.Write([]byte(xmlOutput))
}

// sendJSON sends a JSON response.
func sendJSON(w http.ResponseWriter, data interface{}, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to encode JSON response", "err", err.Error())
		}
		return
	}
	if logger != nil {
		logger.Debug("JSON response", "body", string(body))
	}
	if _, err := w.Write(body); err != nil && logger != nil {
		logger.Error("failed to write JSON response", "err", err.Error())
	}
}

// sendXML sends an XML response.
func sendXML(w http.ResponseWriter, data interface{}, logger *slog.Logger) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	// Every payload is a struct whose xml tags name its elements, and the
	// envelope's MarshalXML renders the flat <response> root the Web API uses.
	xmlData, err := xml.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal XML response", "err", err.Error())
		}
		sendXMLError(w, http.StatusInternalServerError, newErrorResponse(http.StatusInternalServerError, "internal server error"))
		return
	}

	// Write XML declaration and data
	xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)

	// Set content length for proper response handling
	w.Header().Set("Content-Length", strconv.Itoa(len(xmlOutput)))
	_, _ = w.Write([]byte(xmlOutput))
}

// jsonpCallback returns the JSONP callback name from the request.
// Web AIM clients use the "c" query parameter; other callers may use "callback".
func jsonpCallback(r *http.Request) string {
	if r == nil {
		return ""
	}
	if callback := r.URL.Query().Get("c"); callback != "" {
		return callback
	}
	return r.URL.Query().Get("callback")
}

// sendJSONP sends a JSONP response with the specified callback.
func sendJSONP(w http.ResponseWriter, r *http.Request, callback string, data interface{}, logger *slog.Logger) {
	// Validate callback to prevent XSS. This is the one error here that cannot be
	// delivered as JSONP: there is no callback name safe to write.
	if !isValidCallback(callback) {
		sendJSONError(w, http.StatusBadRequest, newErrorResponse(http.StatusBadRequest, "invalid callback parameter"))
		return
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal response", "err", err.Error())
		}
		// The client is on the <script> transport, so the error has to be
		// executable JS for it to see anything but a load failure.
		sendJSONPError(w, r, callback, newErrorResponse(http.StatusInternalServerError, "internal server error"))
		return
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write([]byte(callback))
	_, _ = w.Write([]byte("("))
	_, _ = w.Write(jsonData)
	_, _ = w.Write([]byte(");"))
}

// isValidCallback validates a JSONP callback name to prevent XSS.
func isValidCallback(callback string) bool {
	if len(callback) == 0 || len(callback) > 100 {
		return false
	}

	// Allow alphanumeric, underscore, dollar sign, and dot (for namespace)
	for _, r := range callback {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '_' && r != '$' && r != '.' {
			return false
		}
	}

	return true
}

// sendAMF sends an AMF response
func sendAMF(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	amfData, err := wire.MarshalAMF3(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to encode AMF response",
				"err", err.Error(),
				"dataType", fmt.Sprintf("%T", data))
		}
		// Fall back to JSON error
		sendJSONError(w, http.StatusInternalServerError, newErrorResponse(http.StatusInternalServerError, "AMF encoding failed"))
		return
	}

	w.Header().Set("Content-Type", "application/x-amf")
	w.Header().Set("Content-Length", strconv.Itoa(len(amfData)))

	// Debug logging if enabled
	if logger != nil && logger.Enabled(context.TODO(), slog.LevelDebug) {
		hexPreview := ""
		if len(amfData) > 0 {
			previewLen := len(amfData)
			if previewLen > 64 {
				previewLen = 64
			}
			hexPreview = hex.EncodeToString(amfData[:previewLen])
		}

		logger.Debug("sending AMF response",
			"size", len(amfData),
			"path", r.URL.Path,
			"hexPreview", hexPreview)
	}

	if _, err := w.Write(amfData); err != nil {
		if logger != nil {
			logger.Error("failed to write AMF response",
				"err", err.Error())
		}
	}
}

// sendAMFError sends an AMF error response, falling back to JSON for a payload
// AMF3 cannot represent.
func sendAMFError(w http.ResponseWriter, httpStatus int, resp ErrorResponse) {
	amfData, err := wire.MarshalAMF3(resp)
	if err != nil {
		sendJSONError(w, httpStatus, resp)
		return
	}

	w.Header().Set("Content-Type", "application/x-amf")
	w.Header().Set("Content-Length", strconv.Itoa(len(amfData)))
	w.WriteHeader(httpStatus)
	_, _ = w.Write(amfData)
}
