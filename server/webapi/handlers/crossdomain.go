package handlers

import (
	"log/slog"
	"net/http"
)

// crossDomainPolicy grants any SWF access to this API.
//
// The permission is as broad as the CORS headers the same endpoints already
// send, and every method still needs an aimsid the policy does not hand out.
//
// secure="false" is required because the client reaches these hosts over both
// HTTP and HTTPS; a policy served over HTTPS otherwise permits HTTPS callers
// only, which breaks the plaintext listener.
const crossDomainPolicy = `<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="master-only"/>
  <allow-access-from domain="*" secure="false"/>
  <allow-http-request-headers-from domain="*" headers="*" secure="false"/>
</cross-domain-policy>
`

// CrossDomainPolicyHandler serves the Flash cross-domain policy.
type CrossDomainPolicyHandler struct {
	Logger *slog.Logger
}

// ServeHTTP answers GET /crossdomain.xml.
//
// Flash Player fetches this from the root of every host a SWF loads from before
// it will issue the request, and refuses the request outright when it is
// missing. The Web API is reached cross-origin from the host serving the client,
// so without this the whole API is unreachable to a real Flash Player. Ruffle
// does not enforce the policy, which is why this only surfaces on the plugin.
func (h *CrossDomainPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Flash rejects a master policy file that is not served as text or XML.
	w.Header().Set("Content-Type", "text/x-cross-domain-policy")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(crossDomainPolicy))
}
