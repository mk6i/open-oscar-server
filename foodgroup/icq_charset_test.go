package foodgroup

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/encoding/charmap"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestLegacyToUTF8(t *testing.T) {
	// "Кутаиси" as Windows-1251 bytes
	kutaisi1251 := "\xca\xf3\xf2\xe0\xe8\xf1\xe8"

	t.Run("fallback charset text becomes UTF-8", func(t *testing.T) {
		in := state.ICQBasicInfo{City: kutaisi1251, FirstName: "Vitaly"}

		out := legacyToUTF8(charmap.Windows1251, in)

		assert.Equal(t, "Кутаиси", out.City)
		assert.Equal(t, "Vitaly", out.FirstName)
		assert.Equal(t, kutaisi1251, in.City, "input must not change")
	})

	t.Run("UTF-8 text is kept", func(t *testing.T) {
		in := state.ICQBasicInfo{City: "Кутаиси", Nickname: "ქართული"}

		assert.Equal(t, in, legacyToUTF8(charmap.Windows1251, in))
	})

	t.Run("strings behind pointers and slices are converted without touching the input", func(t *testing.T) {
		city := kutaisi1251
		in := state.ICQUserSearchCriteria{City: &city, HomePageKeywords: []string{kutaisi1251, "ascii"}}

		out := legacyToUTF8(charmap.Windows1251, in)

		assert.Equal(t, "Кутаиси", *out.City)
		assert.Equal(t, []string{"Кутаиси", "ascii"}, out.HomePageKeywords)
		assert.Equal(t, kutaisi1251, city)
		assert.Equal(t, kutaisi1251, in.HomePageKeywords[0])
	})

	t.Run("without a fallback charset text is kept", func(t *testing.T) {
		in := state.ICQBasicInfo{City: kutaisi1251}

		assert.Equal(t, in, legacyToUTF8(nil, in))
	})
}

func TestUTF8ToLegacy(t *testing.T) {
	kutaisi1251 := "\xca\xf3\xf2\xe0\xe8\xf1\xe8"

	t.Run("representable text is encoded in the fallback charset", func(t *testing.T) {
		in := state.ICQInfo{Basic: state.ICQBasicInfo{City: "Кутаиси", FirstName: "Vitaly"}}

		out := utf8ToLegacy(charmap.Windows1251, in)

		assert.Equal(t, kutaisi1251, out.Basic.City)
		assert.Equal(t, "Vitaly", out.Basic.FirstName)
	})

	t.Run("text the charset cannot represent is kept as UTF-8", func(t *testing.T) {
		in := state.ICQInfo{Basic: state.ICQBasicInfo{City: "ქუთაისი"}, Notes: state.ICQUserNotes{Notes: "привет 👋"}}

		assert.Equal(t, in, utf8ToLegacy(charmap.Windows1251, in))
	})

	t.Run("text stored before the conversion existed is kept", func(t *testing.T) {
		in := state.ICQInfo{Basic: state.ICQBasicInfo{City: kutaisi1251}}

		assert.Equal(t, in, utf8ToLegacy(charmap.Windows1251, in))
	})

	t.Run("a round trip through the store returns what the client sent", func(t *testing.T) {
		sent := state.ICQBasicInfo{City: kutaisi1251}

		stored := legacyToUTF8(charmap.Windows1251, sent)

		assert.Equal(t, sent, utf8ToLegacy(charmap.Windows1251, stored))
	})
}

func TestCh4Text(t *testing.T) {
	// "Привет, люблю" as Windows-1251 bytes; "ю" is the separator byte 0xFE
	reason1251 := "\xcf\xf0\xe8\xe2\xe5\xf2, \xeb\xfe\xe1\xeb\xfe"
	request := func(nick, reason string) string {
		return nick + "\xFEfirst\xFElast\xFEa@b.c\xFE1\xFE" + reason
	}

	t.Run("a stored UTF-8 request is encoded for a vintage client", func(t *testing.T) {
		out := ch4TextToLegacy(charmap.Windows1251, request("Дима", "Привет, люблю"))

		assert.Equal(t, request("\xc4\xe8\xec\xe0", reason1251), out)
	})

	t.Run("a request a vintage client sent is left alone on its way to another one", func(t *testing.T) {
		in := request("\xc4\xe8\xec\xe0", reason1251)

		assert.Equal(t, in, ch4TextToLegacy(charmap.Windows1251, in))
	})

	t.Run("a vintage request becomes UTF-8 with the reason intact", func(t *testing.T) {
		out := ch4TextToUTF8(charmap.Windows1251, wire.ICBMMsgTypeAuthReq, request("\xc4\xe8\xec\xe0", reason1251))

		assert.Equal(t, request("Дима", "Привет, люблю"), out)
	})

	t.Run("a stored UTF-8 request stays UTF-8 for a feedbag client", func(t *testing.T) {
		in := request("Дима", "Привет, люблю")

		assert.Equal(t, in, ch4TextToUTF8(charmap.Windows1251, wire.ICBMMsgTypeAuthReq, in))
	})

	t.Run("a vintage denial is a reason on its own", func(t *testing.T) {
		assert.Equal(t, "Привет, люблю", ch4TextToUTF8(charmap.Windows1251, wire.ICBMMsgTypeAuthDeny, reason1251))
	})

	t.Run("a message TLV is re-encoded only when its text changes", func(t *testing.T) {
		utf8TLV := wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{UIN: 100, MessageType: wire.ICBMMsgTypeAuthDeny, Message: "Привет"})
		legacyTLV := wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{UIN: 100, MessageType: wire.ICBMMsgTypeAuthDeny, Message: "\xcf\xf0\xe8\xe2\xe5\xf2"})

		assert.Equal(t, legacyTLV, ch4TLVToLegacy(charmap.Windows1251, utf8TLV))
		assert.Equal(t, legacyTLV, ch4TLVToLegacy(charmap.Windows1251, legacyTLV))
	})
}
