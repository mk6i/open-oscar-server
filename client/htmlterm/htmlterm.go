// Package htmlterm converts the HTML used in AIM messages and profiles to text
// for display in a terminal, either with ANSI styling or as plain text.
package htmlterm

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// style is the text style in effect at a point in the document.
type style struct {
	bold, italic, underline, strike bool
	// color is a 24-bit RGB color, or -1 for the default color.
	color int
}

func (s style) sgr() string {
	codes := []string{"0"}
	if s.bold {
		codes = append(codes, "1")
	}
	if s.italic {
		codes = append(codes, "3")
	}
	if s.underline {
		codes = append(codes, "4")
	}
	if s.strike {
		codes = append(codes, "9")
	}
	if s.color >= 0 {
		codes = append(codes, fmt.Sprintf("38;2;%d;%d;%d", s.color>>16&0xFF, s.color>>8&0xFF, s.color&0xFF))
	}
	return "\x1b[" + strings.Join(codes, ";") + "m"
}

// frame is an open element and the style that applies inside it.
type frame struct {
	tag   atom.Atom
	style style
	href  string
	text  strings.Builder
}

// ToANSI converts HTML to text styled with ANSI escape codes. Bold, italic,
// underline, strikethrough and font colors are kept; other markup is dropped.
// Colors too dark to read on a dark background are lightened when
// darkBackground is set.
func ToANSI(s string, darkBackground bool) string {
	return convert(s, true, darkBackground)
}

// Strip converts HTML to plain text.
func Strip(s string) string {
	return convert(s, false, false)
}

func convert(s string, ansi, darkBackground bool) string {
	var out strings.Builder
	stack := []*frame{{style: style{color: -1}}}
	cur := func() *frame { return stack[len(stack)-1] }
	styled := false

	write := func(text string) {
		if text == "" {
			return
		}
		f := cur()
		if ansi {
			st := f.style
			if st != (style{color: -1}) {
				out.WriteString(st.sgr())
				styled = true
			} else if styled {
				out.WriteString("\x1b[0m")
				styled = false
			}
		}
		out.WriteString(text)
		for _, fr := range stack {
			if fr.href != "" {
				fr.text.WriteString(text)
			}
		}
	}
	newline := func() {
		if ansi && styled {
			out.WriteString("\x1b[0m")
			styled = false
		}
		out.WriteString("\n")
	}
	push := func(tag atom.Atom, edit func(*style)) *frame {
		f := &frame{tag: tag, style: cur().style}
		if edit != nil {
			edit(&f.style)
		}
		stack = append(stack, f)
		return f
	}
	pop := func(tag atom.Atom) {
		// close the innermost matching element and everything opened inside it
		for i := len(stack) - 1; i > 0; i-- {
			if stack[i].tag != tag {
				continue
			}
			f := stack[i]
			stack = stack[:i]
			if f.href != "" && !sameLink(f.text.String(), f.href) {
				write(" <" + f.href + ">")
			}
			return
		}
	}

	z := html.NewTokenizer(strings.NewReader(s))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if ansi && styled {
				out.WriteString("\x1b[0m")
			}
			return strings.TrimSpace(out.String())
		case html.TextToken:
			write(collapseSpace(string(z.Text())))
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			switch tok.DataAtom {
			case atom.Br:
				newline()
				continue
			case atom.Hr:
				newline()
				write("----------------------------------------")
				newline()
				continue
			case atom.P, atom.Div:
				if out.Len() > 0 {
					newline()
				}
			case atom.Li:
				newline()
				write("• ")
				continue
			case atom.Img:
				if alt := attr(tok, "alt"); alt != "" {
					write(alt)
				}
				continue
			}
			if tt == html.SelfClosingTagToken {
				continue
			}
			switch tok.DataAtom {
			case atom.B, atom.Strong:
				push(tok.DataAtom, func(s *style) { s.bold = true })
			case atom.I, atom.Em:
				push(tok.DataAtom, func(s *style) { s.italic = true })
			case atom.U:
				push(tok.DataAtom, func(s *style) { s.underline = true })
			case atom.S, atom.Strike, atom.Del:
				push(tok.DataAtom, func(s *style) { s.strike = true })
			case atom.Font:
				color, ok := parseColor(attr(tok, "color"))
				push(tok.DataAtom, func(s *style) {
					if ok {
						s.color = adjustColor(color, darkBackground)
					}
				})
			case atom.A:
				f := push(tok.DataAtom, func(s *style) { s.underline = true })
				f.href = attr(tok, "href")
			case atom.H1, atom.H2, atom.H3, atom.H4, atom.H5, atom.H6:
				if out.Len() > 0 {
					newline()
				}
				push(tok.DataAtom, func(s *style) { s.bold = true })
			case atom.Script, atom.Style, atom.Title:
				skipElement(z, tok.DataAtom)
			}
		case html.EndTagToken:
			tok := z.Token()
			switch tok.DataAtom {
			case atom.P, atom.Div, atom.H1, atom.H2, atom.H3, atom.H4, atom.H5, atom.H6:
				pop(tok.DataAtom)
				newline()
			default:
				pop(tok.DataAtom)
			}
		}
	}
}

// skipElement discards tokens until the end of the element tag.
func skipElement(z *html.Tokenizer, tag atom.Atom) {
	for {
		switch z.Next() {
		case html.ErrorToken:
			return
		case html.EndTagToken:
			if z.Token().DataAtom == tag {
				return
			}
		}
	}
}

// sameLink reports whether a link's text already shows its target.
func sameLink(text, href string) bool {
	trim := func(s string) string {
		s = strings.TrimSpace(strings.ToLower(s))
		for _, p := range []string{"http://", "https://", "mailto:", "aim:"} {
			s = strings.TrimPrefix(s, p)
		}
		return strings.TrimSuffix(s, "/")
	}
	return trim(text) == trim(href)
}

// collapseSpace replaces runs of whitespace, including newlines, with a
// single space, as a browser would.
func collapseSpace(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

func attr(tok html.Token, name string) string {
	for _, a := range tok.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

// namedColors are the HTML color names AIM clients commonly used.
var namedColors = map[string]int{
	"black": 0x000000, "white": 0xFFFFFF, "red": 0xFF0000, "green": 0x008000,
	"blue": 0x0000FF, "yellow": 0xFFFF00, "purple": 0x800080, "orange": 0xFFA500,
	"gray": 0x808080, "grey": 0x808080, "silver": 0xC0C0C0, "maroon": 0x800000,
	"navy": 0x000080, "teal": 0x008080, "olive": 0x808000, "lime": 0x00FF00,
	"aqua": 0x00FFFF, "cyan": 0x00FFFF, "fuchsia": 0xFF00FF, "magenta": 0xFF00FF,
	"pink": 0xFFC0CB, "brown": 0xA52A2A,
}

// parseColor parses an HTML color such as "#FF0000", "FF0000" or "red".
func parseColor(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if c, ok := namedColors[s]; ok {
		return c, true
	}
	s = strings.TrimPrefix(s, "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return 0, false
	}
	c, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, false
	}
	return int(c), true
}

// adjustColor lightens colors that would be unreadable on a dark background.
// AIM users typically picked colors for a white background, so black text is
// common.
func adjustColor(c int, darkBackground bool) int {
	if !darkBackground {
		return c
	}
	r, g, b := c>>16&0xFF, c>>8&0xFF, c&0xFF
	// perceived brightness, 0-255
	lum := (299*r + 587*g + 114*b) / 1000
	if lum >= 64 {
		return c
	}
	if max(r, g, b) < 48 {
		return -1 // near black: use the terminal's default color
	}
	// blend toward white until readable
	mix := func(v int) int { return v + (255-v)/2 }
	return mix(r)<<16 | mix(g)<<8 | mix(b)
}
