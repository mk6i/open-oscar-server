package foodgroup

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/encoding/charmap"

	"github.com/mk6i/open-oscar-server/state"
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
