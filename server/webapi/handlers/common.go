package handlers

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
)

// BaseResponse is the standard response envelope for all Web API responses.
// It supports both JSON and XML marshaling.
type BaseResponse struct {
	XMLName  xml.Name     `xml:"response" json:"-"`
	Response ResponseBody `json:"response"`
}

// ResponseBody contains the status and data for API responses.
type ResponseBody struct {
	StatusCode int         `json:"statusCode" xml:"statusCode"`
	StatusText string      `json:"statusText" xml:"statusText"`
	RequestID  string      `json:"requestId,omitempty" xml:"requestId,omitempty"`
	Data       interface{} `json:"data,omitempty" xml:"data,omitempty"`
}

// ErrorResponse represents an error response with proper XML/JSON support.
type ErrorResponse struct {
	XMLName  xml.Name `xml:"response" json:"-"`
	Response struct {
		StatusCode int    `json:"statusCode" xml:"statusCode"`
		StatusText string `json:"statusText" xml:"statusText"`
	} `json:"response" xml:"-"`
	// For XML responses, flatten the structure
	StatusCode int    `json:"-" xml:"statusCode"`
	StatusText string `json:"-" xml:"statusText"`
}

// XMLMapResponse is a helper struct for converting map-based responses to XML
type XMLMapResponse struct {
	XMLName    xml.Name `xml:"response"`
	StatusCode int      `xml:"statusCode"`
	StatusText string   `xml:"statusText"`
	Data       XMLData  `xml:"data,omitempty"`
}

// XMLData wraps the data for XML responses
type XMLData struct {
	// Auth response fields
	Token          *XMLToken `xml:"token,omitempty"`
	LoginID        string    `xml:"loginId,omitempty"`
	ScreenName     string    `xml:"screenName,omitempty"`
	SessionSecret  string    `xml:"sessionSecret,omitempty"`
	HostTime       int64     `xml:"hostTime,omitempty"`
	TokenExpiresIn int       `xml:"tokenExpiresIn,omitempty"`

	// Generic fields for other responses
	AimSID   string `xml:"aimsid,omitempty"`
	FetchURL string `xml:"fetchUrl,omitempty"`
	MsgID    string `xml:"msgId,omitempty"`
	State    string `xml:"state,omitempty"`

	// For any other data, we'll encode as string
	Raw string `xml:",chardata"`
}

// XMLToken represents the token structure in XML
type XMLToken struct {
	A         string `xml:"a"`
	ExpiresIn int    `xml:"expiresIn"`
}

// requestIDFromRequest returns the Web AIM client request correlation id from the
// "r" query parameter. JSONP callbacks require this echoed in response.requestId.
func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.URL.Query().Get("r")
}

// attachRequestID copies the request's "r" parameter into BaseResponse.requestId
// when the handler did not set one explicitly.
func attachRequestID(r *http.Request, data interface{}) interface{} {
	id := requestIDFromRequest(r)
	if id == "" {
		return data
	}
	br, ok := data.(BaseResponse)
	if !ok || br.Response.RequestID != "" {
		return data
	}
	br.Response.RequestID = id
	return br
}

// SendResponse sends a response in the requested format (JSON, JSONP, XML, or AMF).
// This is the centralized function that all handlers should use for responses.
func SendResponse(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	data = attachRequestID(r, data)

	// Check for format parameter (f for format or callback for JSONP)
	// First check URL query parameters
	format := strings.ToLower(r.URL.Query().Get("f"))
	callback := jsonpCallback(r)

	// If format not in URL query, check form values (for POST requests)
	if format == "" && r.Method == "POST" {
		_ = r.ParseForm()
		format = strings.ToLower(r.FormValue("f"))
		if callback == "" {
			callback = jsonpCallback(r)
		}
	}

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
		sendJSONP(w, callback, data, logger)
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

// SendError sends an error response in the appropriate format.
func SendError(w http.ResponseWriter, statusCode int, message string) {
	// Try to detect format from Content-Type header if already set
	contentType := w.Header().Get("Content-Type")

	if strings.Contains(contentType, "amf") {
		sendAMFError(w, nil, statusCode, message, nil)
	} else if strings.Contains(contentType, "xml") {
		sendXMLError(w, statusCode, message)
	} else {
		sendJSONError(w, statusCode, message)
	}
}

// sendJSONError sends a JSON error response.
func sendJSONError(w http.ResponseWriter, statusCode int, message string) {
	resp := ErrorResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusText = message

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

// sendXMLError sends an XML error response.
func sendXMLError(w http.ResponseWriter, statusCode int, message string) {
	resp := ErrorResponse{}
	resp.StatusCode = statusCode
	resp.StatusText = message

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(statusCode)

	// Write XML declaration and marshal the response
	xmlData, err := xml.Marshal(resp)
	if err != nil {
		// Fall back to simple text response
		http.Error(w, message, statusCode)
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

	// Convert BaseResponse with map data to a format XML can handle
	if baseResp, ok := data.(BaseResponse); ok {
		data = convertBaseResponseForXML(baseResp)
	}

	// Marshal the data
	xmlData, err := xml.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal XML response", "err", err.Error())
		}
		sendXMLError(w, http.StatusInternalServerError, "internal server error")
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
	if callback := r.URL.Query().Get("c"); callback != "" {
		return callback
	}
	return r.URL.Query().Get("callback")
}

// sendJSONP sends a JSONP response with the specified callback.
func sendJSONP(w http.ResponseWriter, callback string, data interface{}, logger *slog.Logger) {
	// Validate callback to prevent XSS
	if !isValidCallback(callback) {
		sendJSONError(w, http.StatusBadRequest, "invalid callback parameter")
		return
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal response", "err", err.Error())
		}
		sendJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/javascript")
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
	encoder := NewAMFEncoder(logger)
	version := DetectAMFVersion(r)

	amfData, err := encoder.EncodeAMF(data, version)
	if err != nil {
		if logger != nil {
			logger.Error("failed to encode AMF response",
				"err", err.Error(),
				"version", version,
				"dataType", fmt.Sprintf("%T", data))
		}
		// Fall back to JSON error
		sendJSONError(w, http.StatusInternalServerError, "AMF encoding failed")
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
			"version", version,
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

// convertBaseResponseForXML converts a BaseResponse with map data to XMLMapResponse
func convertBaseResponseForXML(resp BaseResponse) XMLMapResponse {
	xmlResp := XMLMapResponse{
		StatusCode: resp.Response.StatusCode,
		StatusText: resp.Response.StatusText,
	}

	// Convert map data to XMLData struct
	if dataMap, ok := resp.Response.Data.(map[string]interface{}); ok {
		xmlData := XMLData{}

		// Handle auth response fields
		if tokenData, ok := dataMap["token"].(map[string]interface{}); ok {
			xmlData.Token = &XMLToken{}
			if a, ok := tokenData["a"].(string); ok {
				xmlData.Token.A = a
			}
			if expiresIn, ok := tokenData["expiresIn"].(int); ok {
				xmlData.Token.ExpiresIn = expiresIn
			}
		}

		if loginId, ok := dataMap["loginId"].(string); ok {
			xmlData.LoginID = loginId
		}
		if screenName, ok := dataMap["screenName"].(string); ok {
			xmlData.ScreenName = screenName
		}
		if sessionSecret, ok := dataMap["sessionSecret"].(string); ok {
			xmlData.SessionSecret = sessionSecret
		}
		if hostTime, ok := dataMap["hostTime"].(int64); ok {
			xmlData.HostTime = hostTime
		}
		if tokenExpiresIn, ok := dataMap["tokenExpiresIn"].(int); ok {
			xmlData.TokenExpiresIn = tokenExpiresIn
		}

		// Handle session response fields
		if aimsid, ok := dataMap["aimsid"].(string); ok {
			xmlData.AimSID = aimsid
		}
		if fetchUrl, ok := dataMap["fetchUrl"].(string); ok {
			xmlData.FetchURL = fetchUrl
		}

		// Handle message response fields
		if msgId, ok := dataMap["msgId"].(string); ok {
			xmlData.MsgID = msgId
		}
		if state, ok := dataMap["state"].(string); ok {
			xmlData.State = state
		}

		xmlResp.Data = xmlData
	}

	return xmlResp
}

// sendAMFError sends an AMF error response
func sendAMFError(w http.ResponseWriter, r *http.Request, statusCode int, message string, logger *slog.Logger) {
	errorResp := ErrorResponse{}
	errorResp.Response.StatusCode = statusCode
	errorResp.Response.StatusText = message

	encoder := NewAMFEncoder(logger)
	version := DetectAMFVersion(r)

	amfData, err := encoder.EncodeAMF(errorResp, version)
	if err != nil {
		// If AMF encoding fails, fall back to JSON error
		sendJSONError(w, statusCode, message)
		return
	}

	w.Header().Set("Content-Type", "application/x-amf")
	w.Header().Set("Content-Length", strconv.Itoa(len(amfData)))
	w.WriteHeader(statusCode)
	_, _ = w.Write(amfData)
}
