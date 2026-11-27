package fastsax

import (
	"testing"
)

func TestName(t *testing.T) {
	var cases = []struct {
		raw, wantName, wantRest string
	}{
		{"", "", ""},
		{"<>", "", ""},
		{"</>", "", ""},
		{"<foo>", "foo", ""},
		{"</foo>", "foo", ""},
		{"<foo/>", "foo", ""},
		{"<foo bar>", "foo", "bar"},
		{"</foo bar>", "foo", "bar"},
		{"<foo bar/>", "foo", "bar"},
		{"<foo bar=baz>", "foo", "bar=baz"},
		{"</foo bar=baz>", "foo", "bar=baz"},
		{"<foo bar=baz/>", "foo", "bar=baz"},
	}

	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			gotName, gotRest := Name([]byte(c.raw))
			if string(gotName) != c.wantName || string(gotRest) != c.wantRest {
				t.Errorf("got %q:%q, want %q:%q", gotName, gotRest, c.wantName, c.wantRest)
			}
		})
	}
}
