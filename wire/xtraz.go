package wire

import (
	"encoding/xml"
	"errors"
	"html"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var (
	// CapXtrazScript is the UUID for the ICQ Xtraz/Tzer.
	// Xtraz enables extended status (XStatus), greeting cards, and chat invitations.
	CapXtrazScript = uuid.MustParse("3B60B3EF-D82A-6C45-A4E0-9C5A5E67E865")
)

const (
	XtrazFuncInvitation uint16 = 0x0001 // chat invitation
	XtrazFuncData       uint16 = 0x0002 // greeting cards, custom data
	XtrazFuncUserRemove uint16 = 0x0004 // user removal notification
	XtrazFuncNotify     uint16 = 0x0008 // XStatus notifications
)

const (
	XStatusAngry       uint8 = 1
	XStatusDuck        uint8 = 2
	XStatusTired       uint8 = 3
	XStatusParty       uint8 = 4
	XStatusBeer        uint8 = 5
	XStatusThinking    uint8 = 6
	XStatusEating      uint8 = 7
	XStatusTV          uint8 = 8
	XStatusFriends     uint8 = 9
	XStatusCoffee      uint8 = 10
	XStatusMusic       uint8 = 11
	XStatusBusiness    uint8 = 12
	XStatusCamera      uint8 = 13
	XStatusFunny       uint8 = 14
	XStatusPhone       uint8 = 15
	XStatusGames       uint8 = 16
	XStatusCollege     uint8 = 17
	XStatusShopping    uint8 = 18
	XStatusSick        uint8 = 19
	XStatusSleeping    uint8 = 20
	XStatusSurfing     uint8 = 21
	XStatusInternet    uint8 = 22
	XStatusEngineering uint8 = 23
	XStatusTyping      uint8 = 24
	XStatusPPC         uint8 = 25
	XStatusMobile      uint8 = 26
	XStatusLove        uint8 = 27
	XStatusSearching   uint8 = 28
	XStatusEvil        uint8 = 29
	XStatusDepression  uint8 = 30
	XStatusParty2      uint8 = 31
	XStatusCoffee2     uint8 = 32
)

// UnmangleXtrazXML decodes the HTML entity encoded XML used in Xtraz messages.
// Xtraz uses HTML entity encoding for transport: &lt; &gt; &amp; &quot;
func UnmangleXtrazXML(mangled string) string {
	return html.UnescapeString(mangled)
}

// MangleXtrazXML encodes XML for Xtraz transport using HTML entities.
func MangleXtrazXML(plain string) string {
	return html.EscapeString(plain)
}

// XtrazNotifyRequest represents a parsed Xtraz notification request (<N> type).
type XtrazNotifyRequest struct {
	PluginID  string
	ServiceID string
	RequestID string
	TransID   string // transaction ID
	SenderID  string // sender's UIN
}

// XtrazNotifyResponse represents a parsed Xtraz notification response (<NR> type).
type XtrazNotifyResponse struct {
	UIN     string
	Index   uint8
	Title   string
	Message string
}

// xmlNotifyRequest is the internal XML structure for parsing <N> requests.
type xmlNotifyRequest struct {
	XMLName xml.Name `xml:"N"`
	Query   struct {
		PluginID string `xml:"PluginID"`
	} `xml:"QUERY"`
	Notify struct {
		Srv struct {
			ID  string `xml:"id"`
			Req struct {
				ID       string `xml:"id"`
				Trans    string `xml:"trans"`
				SenderID string `xml:"senderId"`
			} `xml:"req"`
		} `xml:"srv"`
	} `xml:"NOTIFY"`
}

// xmlNotifyResponseRoot is the internal XML structure for the <Root> element in responses.
type xmlNotifyResponseRoot struct {
	UIN   string `xml:"uin"`
	Index uint8  `xml:"index"`
	Title string `xml:"title"`
	Desc  string `xml:"desc"`
}

// ParseXtrazNotifyRequest parses an Xtraz notification request from XML.
// The input is expected to be unmangled.
func ParseXtrazNotifyRequest(xmlData []byte) (*XtrazNotifyRequest, error) {
	var req xmlNotifyRequest
	if err := xml.Unmarshal(xmlData, &req); err != nil {
		return nil, err
	}
	return &XtrazNotifyRequest{
		PluginID:  req.Query.PluginID,
		ServiceID: req.Notify.Srv.ID,
		RequestID: req.Notify.Srv.Req.ID,
		TransID:   req.Notify.Srv.Req.Trans,
		SenderID:  req.Notify.Srv.Req.SenderID,
	}, nil
}

// ErrXtrazRootNotFound is returned when the Root element is not found in an Xtraz response.
var ErrXtrazRootNotFound = errors.New("xtraz: Root element not found in response")

// ParseXtrazNotifyResponse parses an Xtraz notification response from XML.
// The input should be unmangled.
func ParseXtrazNotifyResponse(xmlData []byte) (*XtrazNotifyResponse, error) {
	// The response XML has a nested structure, we need to extract the Root element
	xmlStr := string(xmlData)

	rootStart := strings.Index(xmlStr, "<Root>")
	rootEnd := strings.Index(xmlStr, "</Root>")
	if rootStart == -1 || rootEnd == -1 {
		return nil, ErrXtrazRootNotFound
	}

	rootXML := xmlStr[rootStart : rootEnd+len("</Root>")]

	var root xmlNotifyResponseRoot
	if err := xml.Unmarshal([]byte(rootXML), &root); err != nil {
		return nil, err
	}

	return &XtrazNotifyResponse{
		UIN:     root.UIN,
		Index:   root.Index,
		Title:   root.Title,
		Message: root.Desc,
	}, nil
}

// BuildXtrazNotifyResponse builds an Xtraz notification response XML string.
func BuildXtrazNotifyResponse(uin string, index uint8, title, message string) string {
	xmlStr := `<NR><RES><ret event="OnRemoteNotification"><srv><id></id>` +
		`<val srv_id="cAwaySrv"><Root><CASXtraSetAwayMessage></CASXtraSetAwayMessage>` +
		`<uin>` + uin + `</uin>` +
		`<index>` + strconv.Itoa(int(index)) + `</index>` +
		`<title>` + MangleXtrazXML(title) + `</title>` +
		`<desc>` + MangleXtrazXML(message) + `</desc>` +
		`</Root></val></srv></ret></RES></NR>`
	return MangleXtrazXML(xmlStr)
}

// BuildXtrazNotifyRequest builds an Xtraz notification request XML string.
func BuildXtrazNotifyRequest(senderUIN string) string {
	xml := `<N><QUERY><PluginID>srvMng</PluginID></QUERY>` +
		`<NOTIFY><srv><id>cAwaySrv</id>` +
		`<req><id>AwayStat</id><trans>1</trans>` +
		`<senderId>` + senderUIN + `</senderId></req></srv></NOTIFY></N>`
	return MangleXtrazXML(xml)
}
