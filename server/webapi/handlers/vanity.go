package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
)

// VanityHandler handles Web AIM API vanity URL endpoints.
type VanityHandler struct {
	SessionManager *state.WebAPISessionManager
	VanityManager  *state.VanityURLManager
	Logger         *slog.Logger
}

// GetVanityInfo handles GET /aim/getVanityInfo requests to retrieve vanity URL information.
func (h *VanityHandler) GetVanityInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// According to spec, this endpoint requires signed request parameters
	// but we'll make them optional for compatibility
	ts := r.URL.Query().Get("ts")
	sig := r.URL.Query().Get("sig_sha256")

	// Validate timestamp if provided
	if ts != "" && sig == "" {
		SendError(w, http.StatusBadRequest, "signature required when timestamp provided")
		return
	}

	// Get authentication from either aimsid or token
	aimsid := r.URL.Query().Get("aimsid")
	_ = r.URL.Query().Get("a") // Token auth not fully implemented

	var screenName string
	if aimsid != "" {
		session, err := h.SessionManager.GetSession(r.Context(), aimsid)
		if err == nil {
			screenName = session.ScreenName.String()
		}
	}

	// If no explicit target, use authenticated user
	targetUser := r.URL.Query().Get("t")
	if targetUser == "" && screenName != "" {
		targetUser = screenName
	}

	if targetUser == "" {
		SendError(w, http.StatusBadRequest, "missing target user")
		return
	}

	h.Logger.DebugContext(ctx, "retrieving vanity info",
		"targetUser", targetUser,
		"authenticated", screenName,
	)

	// Lookup vanity info by screen name
	info, err := h.VanityManager.GetVanityInfoByScreenName(ctx, targetUser)

	// Handle error or no vanity URL found
	if err != nil || info == nil {
		if err != nil && !strings.Contains(err.Error(), "not found") {
			h.Logger.ErrorContext(ctx, "failed to get vanity info",
				"error", err,
			)
			SendError(w, http.StatusInternalServerError, "failed to retrieve vanity info")
			return
		}

		// No vanity URL configured - return not found
		response := BaseResponse{}
		response.Response.StatusCode = 200
		response.Response.StatusText = "OK"
		response.Response.Data = map[string]interface{}{
			"found":      false,
			"screenName": targetUser,
		}
		SendResponse(w, r, response, h.Logger)
		return
	}

	// Build response
	responseData := map[string]interface{}{
		"found":      true,
		"screenName": info.ScreenName,
		"vanityUrl":  info.VanityURL,
		"profileUrl": info.ProfileURL,
		"isActive":   info.IsActive,
	}

	// Add optional fields if present
	if info.DisplayName != "" {
		responseData["displayName"] = info.DisplayName
	}
	if info.Bio != "" {
		responseData["bio"] = info.Bio
	}
	if info.Location != "" {
		responseData["location"] = info.Location
	}
	if info.Website != "" {
		responseData["website"] = info.Website
	}

	// Add extra data if present
	if info.Extra != nil {
		for k, v := range info.Extra {
			responseData[k] = v
		}
	}

	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = responseData

	SendResponse(w, r, response, h.Logger)
}

// SetVanityURL handles requests to set or update a vanity URL (requires authentication).
func (h *VanityHandler) SetVanityURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authentication required
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		SendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		SendError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Get vanity URL from parameters
	vanityURL := r.URL.Query().Get("vanityUrl")
	if vanityURL == "" {
		SendError(w, http.StatusBadRequest, "missing vanityUrl parameter")
		return
	}

	// Collect optional profile information
	info := make(map[string]interface{})
	if displayName := r.URL.Query().Get("displayName"); displayName != "" {
		info["displayName"] = displayName
	}
	if bio := r.URL.Query().Get("bio"); bio != "" {
		info["bio"] = bio
	}
	if location := r.URL.Query().Get("location"); location != "" {
		info["location"] = location
	}
	if website := r.URL.Query().Get("website"); website != "" {
		info["website"] = website
	}

	h.Logger.InfoContext(ctx, "setting vanity URL",
		"screenName", session.ScreenName.String(),
		"vanityUrl", vanityURL,
	)

	// Create or update the vanity URL
	if err := h.VanityManager.CreateOrUpdateVanityURL(ctx, session.ScreenName.String(), vanityURL, info); err != nil {
		h.Logger.ErrorContext(ctx, "failed to set vanity URL",
			"screenName", session.ScreenName.String(),
			"vanityUrl", vanityURL,
			"error", err,
		)

		// Check if it's a validation or duplicate error
		if strings.Contains(err.Error(), "reserved") ||
			strings.Contains(err.Error(), "already taken") ||
			strings.Contains(err.Error(), "must be") ||
			strings.Contains(err.Error(), "cannot") {
			SendError(w, http.StatusBadRequest, err.Error())
			return
		}

		SendError(w, http.StatusInternalServerError, "failed to set vanity URL")
		return
	}

	// Return success response with the new vanity info
	vanityInfo, _ := h.VanityManager.GetVanityInfoByScreenName(ctx, session.ScreenName.String())

	responseData := map[string]interface{}{
		"success":    true,
		"screenName": session.ScreenName.String(),
		"vanityUrl":  vanityURL,
	}

	if vanityInfo != nil {
		responseData["profileUrl"] = vanityInfo.ProfileURL
	}

	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = responseData

	SendResponse(w, r, response, h.Logger)
}

// CheckAvailability handles requests to check if a vanity URL is available.
func (h *VanityHandler) CheckAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get vanity URL from parameters
	vanityURL := r.URL.Query().Get("vanityUrl")
	if vanityURL == "" {
		SendError(w, http.StatusBadRequest, "missing vanityUrl parameter")
		return
	}

	h.Logger.DebugContext(ctx, "checking vanity URL availability",
		"vanityUrl", vanityURL,
	)

	// Check availability
	available, err := h.VanityManager.CheckAvailability(ctx, vanityURL)
	if err != nil {
		// If it's a validation error, return it as a bad request
		if strings.Contains(err.Error(), "must be") ||
			strings.Contains(err.Error(), "cannot") ||
			strings.Contains(err.Error(), "can only") {
			response := BaseResponse{}
			response.Response.StatusCode = 200
			response.Response.StatusText = "OK"
			response.Response.Data = map[string]interface{}{
				"available": false,
				"reason":    err.Error(),
			}
			SendResponse(w, r, response, h.Logger)
			return
		}

		h.Logger.ErrorContext(ctx, "failed to check availability",
			"vanityUrl", vanityURL,
			"error", err,
		)
		SendError(w, http.StatusInternalServerError, "failed to check availability")
		return
	}

	// Build response
	responseData := map[string]interface{}{
		"available": available,
		"vanityUrl": vanityURL,
	}

	if !available {
		responseData["reason"] = "This vanity URL is already taken or reserved"
	}

	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = responseData

	SendResponse(w, r, response, h.Logger)
}

// DeleteVanityURL handles requests to delete a vanity URL (requires authentication).
func (h *VanityHandler) DeleteVanityURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authentication required
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		SendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		SendError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	h.Logger.InfoContext(ctx, "deleting vanity URL",
		"screenName", session.ScreenName.String(),
	)

	// Delete the vanity URL
	if err := h.VanityManager.DeleteVanityURL(ctx, session.ScreenName.String()); err != nil {
		h.Logger.ErrorContext(ctx, "failed to delete vanity URL",
			"screenName", session.ScreenName.String(),
			"error", err,
		)
		SendError(w, http.StatusInternalServerError, "failed to delete vanity URL")
		return
	}

	// Return success response
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = map[string]interface{}{
		"success":    true,
		"screenName": session.ScreenName.String(),
		"message":    "Vanity URL deleted successfully",
	}

	SendResponse(w, r, response, h.Logger)
}
