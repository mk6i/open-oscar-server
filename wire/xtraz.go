package wire

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"
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

// XStatus mood capability IDs, advertised alongside the regular capabilities to
// indicate which mood icon a client is displaying.

var (
	// CapXStatusThinking is the UUID for the "thinking" mood
	CapXStatusThinking = uuid.MustParse("3FB0BD36-AF3B-4A60-9EEF-CF190F6A5A7F")
	// CapXStatusBusy is the UUID for the "busy" mood
	CapXStatusBusy = uuid.MustParse("488E1489-8ACA-4A08-82AA-77CE7A165208")
	// CapXStatusShopping is the UUID for the "shopping" mood
	CapXStatusShopping = uuid.MustParse("63627337-A03F-49FF-80E5-F709CDE0A4EE")
	// CapXStatusTypingAlt is an alternate UUID for the "typing" mood that ICQ 6
	// does not set for its typewriter icon
	CapXStatusTypingAlt = uuid.MustParse("634F6BD8-ADD2-4AA1-AAB9-115BC26D05A1")
	// CapXStatusQuestion is the UUID for the "question" mood
	CapXStatusQuestion = uuid.MustParse("631436FF-3F8A-40D0-A5CB-7B66E051B364")
	// CapXStatusAngry is the UUID for the "angry" mood
	CapXStatusAngry = uuid.MustParse("01D8D7EE-AC3B-492A-A58D-D3D877E66B92")
	// CapXStatusPlate is the UUID for the "plate" (eating) mood
	CapXStatusPlate = uuid.MustParse("F8E8D7B2-82C4-4142-90F8-10C6CE0A89A6")
	// CapXStatusCinema is the UUID for the "cinema" mood
	CapXStatusCinema = uuid.MustParse("107A9A18-1232-4DA4-B6CD-0879DB780F09")
	// CapXStatusSick is the UUID for the "sick" mood
	CapXStatusSick = uuid.MustParse("1F7A4071-BF3B-4E60-BC32-4C5787B04CF1")
	// CapXStatusTyping is the UUID for the "typing" mood
	CapXStatusTyping = uuid.MustParse("2CE0E4E5-7C64-4370-9C3A-7A1CE878A7DC")
	// CapXStatusSuit is the UUID for the "suit" mood
	CapXStatusSuit = uuid.MustParse("B70867F5-3825-4327-A1FF-CF4CC1939797")
	// CapXStatusBathing is the UUID for the "bathing" mood
	CapXStatusBathing = uuid.MustParse("5A581EA1-E580-430C-A06F-612298B7E4C7")
	// CapXStatusTV is the UUID for the "tv" mood
	CapXStatusTV = uuid.MustParse("80537DE2-A467-4A76-B354-6DFD075F5EC6")
	// CapXStatusExcited is the UUID for the "excited" mood
	CapXStatusExcited = uuid.MustParse("6F493098-4F7C-4AFF-A276-34A03BCEAEA7")
	// CapXStatusSleeping is the UUID for the "sleeping" mood
	CapXStatusSleeping = uuid.MustParse("785E8C48-40D3-4C65-886F-04CF3F3F43DF")
	// CapXStatusHiptop is the UUID for the "hiptop" mood
	CapXStatusHiptop = uuid.MustParse("101117C9-A3B0-40F9-81AC-49E159FBD5D4")
	// CapXStatusInLove is the UUID for the "in love" mood
	CapXStatusInLove = uuid.MustParse("DDCF0EA9-7195-4048-A9C6-413206D6F280")
	// CapXStatusSleepy is the UUID for the "sleepy" mood
	CapXStatusSleepy = uuid.MustParse("83C9B78E-77E7-4378-B2C5-FB6CFCC35BEC")
	// CapXStatusMeeting is the UUID for the "meeting" mood
	CapXStatusMeeting = uuid.MustParse("F18AB52E-DC57-491D-99DC-6444502457AF")
	// CapXStatusPhone is the UUID for the "phone" mood
	CapXStatusPhone = uuid.MustParse("1292E550-1B64-4F66-B206-B29AF378E48D")
	// CapXStatusSurfing is the UUID for the "surfing" mood
	CapXStatusSurfing = uuid.MustParse("A6ED557E-6BF7-44D4-A5D4-D2E7D95CE81F")
	// CapXStatusMobile is the UUID for the "mobile" mood
	CapXStatusMobile = uuid.MustParse("160C60BB-DD44-43F3-9140-050F00E6C009")
	// CapXStatusSearch is the UUID for the "search" mood
	CapXStatusSearch = uuid.MustParse("D4E2B0BA-334E-4FA5-98D0-117DBF4D3CC8")
	// CapXStatusParty is the UUID for the "party" mood
	CapXStatusParty = uuid.MustParse("E601E41C-3373-4BD1-BC06-811D6C323D81")
	// CapXStatusCoffee is the UUID for the "coffee" mood
	CapXStatusCoffee = uuid.MustParse("1B78AE31-FA0B-4D38-93D1-997EEEAFB218")
	// CapXStatusConsole is the UUID for the "console" (gaming) mood
	CapXStatusConsole = uuid.MustParse("D4A611D0-8F01-4EC0-9223-C5B6BEC6CCF0")
	// CapXStatusInternet is the UUID for the "internet" mood
	CapXStatusInternet = uuid.MustParse("12D07E3E-F885-489E-8E97-A72A6551E58D")
	// CapXStatusCigarette is the UUID for the "cigarette" mood
	CapXStatusCigarette = uuid.MustParse("6443C6AF-2260-4517-B58C-D7DF8E290352")
	// CapXStatusWriting is the UUID for the "writing" mood
	CapXStatusWriting = uuid.MustParse("0072D908-4AD1-43DD-9199-6F026966026F")
	// CapXStatusBeer is the UUID for the "beer" mood
	CapXStatusBeer = uuid.MustParse("8C50DBAE-81ED-4786-ACCA-16CC3213C7B7")
	// CapXStatusMusic is the UUID for the "music" mood
	CapXStatusMusic = uuid.MustParse("61BEE0DD-8BDD-475D-8DEE-5F4BAACF19A7")
	// CapXStatusStudying is the UUID for the "studying" mood
	CapXStatusStudying = uuid.MustParse("609D52F8-A29A-49A6-B2A0-2524C5E9D260")
	// CapXStatusWorking is the UUID for the "working" mood
	CapXStatusWorking = uuid.MustParse("BA74DB3E-9E24-434B-87B6-2F6B8DFEE50F")
	// CapXStatusRestroom is the UUID for the "restroom" mood
	CapXStatusRestroom = uuid.MustParse("16F5B76F-A9D2-4035-8CC5-C084703C98FA")
)

// A mood is a capability UUID ICQ clients advertise; Web API clients name the
// same moods with a token string.

// Invented capabilities for the four moods ICQ never assigned a UUID to, so at
// least clients of this server resolve them. Namespaced under "MOOD" in ASCII
// and ending in the mood number, they cannot collide with a genuine capability.
var (
	CapMoodHavingFun = uuid.MustParse("4D4F4F44-0000-0000-0000-00000000000D")
	CapMoodLove      = uuid.MustParse("4D4F4F44-0000-0000-0000-00000000003D")
	CapMoodWeekend   = uuid.MustParse("4D4F4F44-0000-0000-0000-000000000042")
	CapMoodOnTheWay  = uuid.MustParse("4D4F4F44-0000-0000-0000-000000000053")
)

// Mood is one ICQ XStatus mood, in both of the forms it travels in.
type Mood struct {
	ID  string    // the token Web API clients exchange, e.g. "0icqmood6"
	Cap uuid.UUID // the capability OSCAR clients advertise
}

// Moods lists every mood in the order ICQ web clients enumerate them. Where two
// moods share a capability, the one listed first is its canonical name.
var Moods = []Mood{
	{ID: "0icqmood0", Cap: CapXStatusShopping},  // shopping
	{ID: "0icqmood1", Cap: CapXStatusBathing},   // bathing
	{ID: "0icqmood2", Cap: CapXStatusSleepy},    // tired
	{ID: "0icqmood3", Cap: CapXStatusParty},     // party
	{ID: "0icqmood4", Cap: CapXStatusBeer},      // beer
	{ID: "0icqmood5", Cap: CapXStatusThinking},  // thinking
	{ID: "0icqmood6", Cap: CapXStatusPlate},     // eating
	{ID: "0icqmood7", Cap: CapXStatusTV},        // tv
	{ID: "0icqmood8", Cap: CapXStatusMeeting},   // friends
	{ID: "0icqmood9", Cap: CapXStatusCoffee},    // coffee
	{ID: "0icqmood10", Cap: CapXStatusMusic},    // music
	{ID: "0icqmood11", Cap: CapXStatusSuit},     // business
	{ID: "0icqmood12", Cap: CapXStatusCinema},   // cinema
	{ID: "0icqmood13", Cap: CapMoodHavingFun},   // having fun
	{ID: "0icqmood14", Cap: CapXStatusPhone},    // phone
	{ID: "0icqmood81", Cap: CapXStatusConsole},  // gamepad
	{ID: "0icqmood16", Cap: CapXStatusStudying}, // studying
	{ID: "0icqmood17", Cap: CapXStatusSick},     // sick
	{ID: "0icqmood70", Cap: CapXStatusSleeping}, // sleeping
	{ID: "0icqmood19", Cap: CapXStatusSurfing},  // surfing
	{ID: "0icqmood20", Cap: CapXStatusInternet}, // internet
	{ID: "0icqmood21", Cap: CapXStatusWorking},  // working
	{ID: "0icqmood22", Cap: CapXStatusTyping},   // typing
	{ID: "0icqmood23", Cap: CapXStatusAngry},    // angry
	{ID: "0icqmood66", Cap: CapMoodWeekend},     // weekend
	{ID: "0icqmood15", Cap: CapXStatusConsole},  // PSP
	{ID: "0icqmood71", Cap: CapXStatusMobile},   // on mobile
	{ID: "0icqmood18", Cap: CapXStatusSleeping}, // fall asleep
	{ID: "0icqmood68", Cap: CapXStatusRestroom}, // WC
	{ID: "0icqmood77", Cap: CapXStatusQuestion}, // confused
	{ID: "0icqmood83", Cap: CapMoodOnTheWay},    // on the way
	{ID: "0icqmood61", Cap: CapMoodLove},        // love
	{ID: "0icqmood76", Cap: CapXStatusInLove},   // in love
	{ID: "0icqmood85", Cap: CapXStatusSearch},   // searching
	{ID: "0icqmood84", Cap: CapXStatusWriting},  // diary
}

var (
	moodsByID  = indexMoodsByID()
	moodsByCap = indexMoodsByCap()
)

func indexMoodsByID() map[string]Mood {
	index := make(map[string]Mood, len(Moods))
	for _, m := range Moods {
		index[m.ID] = m
	}
	return index
}

func indexMoodsByCap() map[uuid.UUID]Mood {
	index := make(map[uuid.UUID]Mood, len(Moods))
	for _, m := range Moods {
		if _, taken := index[m.Cap]; !taken {
			index[m.Cap] = m
		}
	}
	return index
}

// MoodByID returns the mood named by a Web API mood token.
func MoodByID(id string) (Mood, bool) {
	m, ok := moodsByID[id]
	return m, ok
}

// MoodByCap returns the mood advertised by a capability UUID.
func MoodByCap(c [16]byte) (Mood, bool) {
	m, ok := moodsByCap[uuid.UUID(c)]
	return m, ok
}

// IsMoodCap reports whether c is a known mood capability.
func IsMoodCap(c [16]byte) bool {
	_, ok := MoodByCap(c)
	return ok
}

// MoodIconID encodes a mood token for the id parameter of a mood icon URL: hex
// of a two-byte big-endian length followed by the token, which is how ICQ
// clients read it. An unencodable token yields "", which clients read as no mood.
func MoodIconID(id string) string {
	if id == "" || len(id) > math.MaxUint16 {
		return ""
	}
	return fmt.Sprintf("%04x%s", len(id), hex.EncodeToString([]byte(id)))
}
