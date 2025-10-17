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

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// SessionRetriever provides methods to retrieve OSCAR sessions.
type SessionRetriever interface {
	AllSessions() []*state.Session
	RetrieveSession(screenName state.IdentScreenName, sessionNum uint8) *state.Session
}

// FeedbagRetriever provides methods to retrieve feedbag data.
type FeedbagRetriever interface {
	RetrieveFeedbag(ctx context.Context, screenName state.IdentScreenName) ([]wire.FeedbagItem, error)
	RelationshipsByUser(ctx context.Context, screenName state.IdentScreenName) ([]state.IdentScreenName, error)
}

// CommonHandler provides shared utilities for all Web API handlers.
type CommonHandler struct {
	Logger *slog.Logger
}

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

// SendResponse sends a response in the requested format (JSON, JSONP, XML, or AMF).
// This is the centralized function that all handlers should use for responses.
func SendResponse(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	// Check for format parameter (f for format or callback for JSONP)
	// First check URL query parameters
	format := strings.ToLower(r.URL.Query().Get("f"))
	callback := r.URL.Query().Get("callback")

	// If format not in URL query, check form values (for POST requests)
	if format == "" && r.Method == "POST" {
		r.ParseForm()
		format = strings.ToLower(r.FormValue("f"))
		if callback == "" {
			callback = r.FormValue("callback")
		}
	}

	// Check for AMF format first
	if format == "amf" || format == "amf3" {
		SendAMF(w, r, data, logger)
		return
	}

	// Check Accept header for AMF
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/x-amf") ||
		strings.Contains(accept, "application/amf") {
		SendAMF(w, r, data, logger)
		return
	}

	// If callback is provided, it's JSONP
	if callback != "" {
		SendJSONP(w, callback, data, logger)
		return
	}

	// Check for XML format
	if format == "xml" {
		SendXML(w, data, logger)
		return
	}

	// Default to JSON
	SendJSON(w, data, logger)
}

// SendError sends an error response in the appropriate format.
func SendError(w http.ResponseWriter, statusCode int, message string) {
	// Try to detect format from Content-Type header if already set
	contentType := w.Header().Get("Content-Type")

	if strings.Contains(contentType, "amf") {
		SendAMFError(w, nil, statusCode, message, nil)
	} else if strings.Contains(contentType, "xml") {
		SendXMLError(w, statusCode, message)
	} else {
		SendJSONError(w, statusCode, message)
	}
}

// SendJSONError sends a JSON error response.
func SendJSONError(w http.ResponseWriter, statusCode int, message string) {
	resp := ErrorResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusText = message

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// SendXMLError sends an XML error response.
func SendXMLError(w http.ResponseWriter, statusCode int, message string) {
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
	w.Write([]byte(xmlOutput))
}

// SendJSON sends a JSON response.
func SendJSON(w http.ResponseWriter, data interface{}, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		if logger != nil {
			logger.Error("failed to encode JSON response", "err", err.Error())
		}
	}
}

// SendXML sends an XML response.
func SendXML(w http.ResponseWriter, data interface{}, logger *slog.Logger) {
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
		SendXMLError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Write XML declaration and data
	xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)

	// Set content length for proper response handling
	w.Header().Set("Content-Length", strconv.Itoa(len(xmlOutput)))
	w.Write([]byte(xmlOutput))
}

// SendJSONP sends a JSONP response with the specified callback.
func SendJSONP(w http.ResponseWriter, callback string, data interface{}, logger *slog.Logger) {
	// Validate callback to prevent XSS
	if !IsValidCallback(callback) {
		SendJSONError(w, http.StatusBadRequest, "invalid callback parameter")
		return
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal response", "err", err.Error())
		}
		SendJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(callback))
	w.Write([]byte("("))
	w.Write(jsonData)
	w.Write([]byte(");"))
}

// IsValidCallback validates a JSONP callback name to prevent XSS.
func IsValidCallback(callback string) bool {
	if len(callback) == 0 || len(callback) > 100 {
		return false
	}

	// Allow alphanumeric, underscore, dollar sign, and dot (for namespace)
	for _, r := range callback {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '$' || r == '.') {
			return false
		}
	}

	return true
}

// SendAMF sends an AMF response
func SendAMF(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
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
		SendJSONError(w, http.StatusInternalServerError, "AMF encoding failed")
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

// SendAMFError sends an AMF error response
func SendAMFError(w http.ResponseWriter, r *http.Request, statusCode int, message string, logger *slog.Logger) {
	errorResp := ErrorResponse{}
	errorResp.Response.StatusCode = statusCode
	errorResp.Response.StatusText = message

	encoder := NewAMFEncoder(logger)
	version := DetectAMFVersion(r)

	amfData, err := encoder.EncodeAMF(errorResp, version)
	if err != nil {
		// If AMF encoding fails, fall back to JSON error
		SendJSONError(w, statusCode, message)
		return
	}

	w.Header().Set("Content-Type", "application/x-amf")
	w.Header().Set("Content-Length", strconv.Itoa(len(amfData)))
	w.WriteHeader(statusCode)
	w.Write(amfData)
}
