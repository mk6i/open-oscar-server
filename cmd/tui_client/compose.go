package main

import (
	"fmt"
	"html"
	"slices"
	"strings"

	xhtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/mk6i/open-oscar-server/client/htmlterm"
)

// fontStyle is the user's message style, wrapped around every message they
// send.
type fontStyle struct {
	Face string `json:"face,omitempty"`
	// Size is an HTML font size, 1-7.
	Size int `json:"size,omitempty"`
	// Color and Back are the text and background colors, as #RRGGBB.
	Color     string `json:"color,omitempty"`
	Back      string `json:"back,omitempty"`
	Bold      bool   `json:"bold,omitempty"`
	Italic    bool   `json:"italic,omitempty"`
	Underline bool   `json:"underline,omitempty"`
}

// wrap applies the style to an HTML message.
func (f fontStyle) wrap(msg string) string {
	var open, closing []string
	var attrs []string
	for _, a := range []struct{ name, val string }{
		{"face", f.Face},
		{"size", sizeAttr(f.Size)},
		{"color", f.Color},
		{"back", f.Back},
	} {
		if a.val != "" {
			attrs = append(attrs, fmt.Sprintf(`%s="%s"`, a.name, html.EscapeString(a.val)))
		}
	}
	if len(attrs) > 0 {
		open = append(open, "<font "+strings.Join(attrs, " ")+">")
		closing = append(closing, "</font>")
	}
	for _, t := range []struct {
		on  bool
		tag string
	}{{f.Bold, "b"}, {f.Italic, "i"}, {f.Underline, "u"}} {
		if t.on {
			open = append(open, "<"+t.tag+">")
			closing = append(closing, "</"+t.tag+">")
		}
	}
	slices.Reverse(closing)
	return strings.Join(open, "") + msg + strings.Join(closing, "")
}

func sizeAttr(size int) string {
	if size == 0 {
		return ""
	}
	return fmt.Sprint(size)
}

// describe summarizes the style for display.
func (f fontStyle) describe() string {
	var parts []string
	if f.Face != "" {
		parts = append(parts, "face "+f.Face)
	}
	if f.Size != 0 {
		parts = append(parts, fmt.Sprintf("size %d", f.Size))
	}
	if f.Color != "" {
		parts = append(parts, "color "+f.Color)
	}
	if f.Back != "" {
		parts = append(parts, "background "+f.Back)
	}
	for _, s := range []struct {
		on   bool
		name string
	}{{f.Bold, "bold"}, {f.Italic, "italic"}, {f.Underline, "underline"}} {
		if s.on {
			parts = append(parts, s.name)
		}
	}
	if len(parts) == 0 {
		return "default"
	}
	return strings.Join(parts, ", ")
}

// normalizeColor converts a color such as "red", "f00" or "#FF0000" to
// #RRGGBB.
func normalizeColor(s string) (string, bool) {
	c, ok := htmlterm.ParseColor(s)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("#%06X", c), true
}

// allowedTags are the formatting tags that may be typed into a message, with
// the attributes each may carry.
var allowedTags = map[atom.Atom][]string{
	atom.B: nil, atom.Strong: nil, atom.I: nil, atom.Em: nil, atom.U: nil,
	atom.S: nil, atom.Strike: nil, atom.Sub: nil, atom.Sup: nil,
	atom.Big: nil, atom.Small: nil, atom.Br: nil,
	atom.Font: {"color", "back", "face", "size"},
	atom.A:    {"href"},
}

// sanitizeHTML turns a typed message into HTML. Formatting tags in
// allowedTags are kept, while everything else, such as "<3" or an unknown
// tag, is escaped so that it shows up as typed. Tags left open are closed.
func sanitizeHTML(text string) string {
	var out strings.Builder
	var open []atom.Atom

	z := xhtml.NewTokenizer(strings.NewReader(text))
	for {
		tt := z.Next()
		if tt == xhtml.ErrorToken {
			break
		}
		raw := string(z.Raw())
		tok := z.Token()
		attrs, allowed := allowedTags[tok.DataAtom]

		switch {
		case tt == xhtml.TextToken:
			out.WriteString(html.EscapeString(tok.Data))
		case !allowed:
			out.WriteString(html.EscapeString(raw))
		case tt == xhtml.StartTagToken || tt == xhtml.SelfClosingTagToken:
			out.WriteString("<" + tok.Data)
			for _, a := range tok.Attr {
				if slices.Contains(attrs, strings.ToLower(a.Key)) {
					out.WriteString(fmt.Sprintf(` %s="%s"`, strings.ToLower(a.Key), html.EscapeString(a.Val)))
				}
			}
			out.WriteString(">")
			if tok.DataAtom != atom.Br && tt == xhtml.StartTagToken {
				open = append(open, tok.DataAtom)
			}
		case tt == xhtml.EndTagToken:
			// close the innermost matching tag; drop unmatched end tags
			if i := slices.Index(reversed(open), tok.DataAtom); i >= 0 {
				for range i + 1 {
					out.WriteString("</" + open[len(open)-1].String() + ">")
					open = open[:len(open)-1]
				}
			}
		}
	}
	for i := len(open) - 1; i >= 0; i-- {
		out.WriteString("</" + open[i].String() + ">")
	}
	return out.String()
}

func reversed[T any](s []T) []T {
	r := slices.Clone(s)
	slices.Reverse(r)
	return r
}
