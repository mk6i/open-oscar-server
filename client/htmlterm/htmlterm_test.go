package htmlterm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain text",
			in:   "hello there",
			want: "hello there",
		},
		{
			name: "typical AIM message",
			in:   `<HTML><BODY BGCOLOR="#ffffff"><FONT FACE="Arial" SIZE=2 COLOR="#000000">hi <B>there</B></FONT></BODY></HTML>`,
			want: "hi there",
		},
		{
			name: "line breaks and entities",
			in:   "a &amp; b<br>c&lt;d<BR/>e",
			want: "a & b\nc<d\ne",
		},
		{
			name: "link shows its target",
			in:   `<a href="http://example.com">my site</a>`,
			want: "my site <http://example.com>",
		},
		{
			name: "link whose text is its target",
			in:   `<a href="http://example.com/">example.com</a>`,
			want: "example.com",
		},
		{
			name: "whitespace collapses",
			in:   "a\n   b",
			want: "a b",
		},
		{
			name: "paragraphs",
			in:   "<p>one</p><p>two</p>",
			want: "one\n\ntwo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Strip(tt.in))
		})
	}
}

func TestToANSI(t *testing.T) {
	tests := []struct {
		name string
		in   string
		dark bool
		want string
	}{
		{
			name: "plain text is unstyled",
			in:   "hello",
			want: "hello",
		},
		{
			name: "bold then plain",
			in:   "<b>hi</b> there",
			want: "\x1b[0;1mhi\x1b[0m there",
		},
		{
			name: "nested styles",
			in:   "<i><u>x</u></i>",
			want: "\x1b[0;3;4mx\x1b[0m",
		},
		{
			name: "font color",
			in:   `<font color="#FF0000">red</font>`,
			want: "\x1b[0;38;2;255;0;0mred\x1b[0m",
		},
		{
			name: "named color",
			in:   `<font color="blue">blue</font>`,
			want: "\x1b[0;38;2;0;0;255mblue\x1b[0m",
		},
		{
			name: "black uses default color on dark background",
			in:   `<font color="#000000">dark</font>`,
			dark: true,
			want: "dark",
		},
		{
			name: "dark color lightened on dark background",
			in:   `<font color="#000080">navy</font>`,
			dark: true,
			want: "\x1b[0;38;2;127;127;191mnavy\x1b[0m",
		},
		{
			name: "unclosed tags reset at end",
			in:   "<b>bold",
			want: "\x1b[0;1mbold\x1b[0m",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ToANSI(tt.in, tt.dark))
		})
	}
}
