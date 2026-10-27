package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeHTML(t *testing.T) {
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
			name: "text that only looks like markup is escaped",
			in:   "i <3 you & 1 < 2",
			want: "i &lt;3 you &amp; 1 &lt; 2",
		},
		{
			name: "formatting tags are kept",
			in:   "<b>bold</b> <i>it</i> <u>u</u> <s>s</s>",
			want: "<b>bold</b> <i>it</i> <u>u</u> <s>s</s>",
		},
		{
			name: "font keeps allowed attributes only",
			in:   `<font color="#FF0000" onclick="x()">red</font>`,
			want: `<font color="#FF0000">red</font>`,
		},
		{
			name: "link and line break",
			in:   `<a href="http://example.com">site</a><br>next`,
			want: `<a href="http://example.com">site</a><br>next`,
		},
		{
			name: "unknown tags are escaped",
			in:   "<script>alert(1)</script><blink>hi</blink>",
			want: "&lt;script&gt;alert(1)&lt;/script&gt;&lt;blink&gt;hi&lt;/blink&gt;",
		},
		{
			name: "unclosed tags are closed",
			in:   "<b><i>bold italic",
			want: "<b><i>bold italic</i></b>",
		},
		{
			name: "end tag closes tags opened inside it",
			in:   "<b><i>x</b> y",
			want: "<b><i>x</i></b> y",
		},
		{
			name: "unmatched end tag is dropped",
			in:   "x</b>y",
			want: "xy",
		},
		{
			name: "entities typed as HTML are kept",
			in:   "a &lt;b&gt; c",
			want: "a &lt;b&gt; c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeHTML(tt.in))
		})
	}
}

func TestFontStyle_wrap(t *testing.T) {
	tests := []struct {
		name  string
		style fontStyle
		want  string
	}{
		{
			name: "default style",
			want: "hi",
		},
		{
			name:  "font attributes",
			style: fontStyle{Face: "Comic Sans MS", Size: 3, Color: "#0000FF", Back: "#FFFF00"},
			want:  `<font face="Comic Sans MS" size="3" color="#0000FF" back="#FFFF00">hi</font>`,
		},
		{
			name:  "styles nest inside the font tag",
			style: fontStyle{Color: "#FF0000", Bold: true, Underline: true},
			want:  `<font color="#FF0000"><b><u>hi</u></b></font>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.style.wrap("hi"))
		})
	}
}

func TestNormalizeColor(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{in: "red", want: "#FF0000", wantOK: true},
		{in: "#00ff00", want: "#00FF00", wantOK: true},
		{in: "f0a", want: "#FF00AA", wantOK: true},
		{in: "notacolor"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := normalizeColor(tt.in)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
