// Portions of this file (Name, NextAttribute, Unescape, the whitespace table,
// and the CData/Comment helpers) are derived from gosax
// (https://github.com/orisano/gosax), Copyright (c) 2024 Nao Yonashiro,
// licensed under the BSD 2-Clause License. See THIRD_PARTY_NOTICES.md.

package fastsax

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"
)

var errUnknownBang = errors.New("unknown markup after \"<!\"")

var whitespace = [256]bool{
	' ':  true,
	'\r': true,
	'\n': true,
	'\t': true,
}

// Name extracts the element name from a tag event's bytes (KindStart, KindEnd
// or KindSelfClose) and returns it together with the remaining bytes of the
// tag (the raw attribute region for start tags).
func Name(b []byte) (name, rest []byte) {
	if len(b) > 1 && b[0] == '<' {
		b = b[1:]
	}
	if len(b) > 1 && b[0] == '/' {
		b = b[1:]
	}
	if len(b) > 0 && b[len(b)-1] == '>' {
		b = b[:len(b)-1]
	}
	if len(b) > 1 && b[len(b)-1] == '/' {
		b = b[:len(b)-1]
	}
	for i := 0; i < len(b); i++ {
		if whitespace[b[i]] {
			return b[:i], b[i+1:]
		}
	}
	return b, nil
}

// Attribute is a single key/value pair from a start tag. Value is the raw
// bytes between (not including) the quotes; entities are not decoded — pass
// Value through Unescape or UnescapeAppend if needed.
type Attribute struct {
	Key   []byte
	Value []byte
}

// NextAttribute extracts the next attribute from the attribute region of a
// start tag (the rest return of Name). It returns the attribute and the
// remaining bytes. A zero-length Key signals that no attributes remain.
func NextAttribute(b []byte) (Attribute, []byte, error) {
	i := 0
	for ; i < len(b) && whitespace[b[i]]; i++ {
	}
	if i == len(b) {
		return Attribute{}, nil, nil
	}
	keyStart := i
	for ; i < len(b) && !whitespace[b[i]] && b[i] != '='; i++ {
	}
	key := b[keyStart:i]
	if len(key) == 0 {
		return Attribute{}, nil, fmt.Errorf("fastsax: empty attribute name")
	}
	for ; i < len(b) && whitespace[b[i]]; i++ {
	}
	if i == len(b) || b[i] != '=' {
		// attribute without value (e.g. trailing garbage); mirror gosax
		return Attribute{Key: key}, b[i:], nil
	}
	i++
	for ; i < len(b) && whitespace[b[i]]; i++ {
	}
	if i == len(b) {
		return Attribute{Key: key}, nil, fmt.Errorf("fastsax: attribute value not found")
	}
	quote := b[i]
	if quote != '"' && quote != '\'' {
		return Attribute{}, nil, fmt.Errorf("fastsax: invalid attribute value delimiter %q", quote)
	}
	end := bytes.IndexByte(b[i+1:], quote)
	if end < 0 {
		return Attribute{}, nil, fmt.Errorf("fastsax: unterminated attribute value")
	}
	value := b[i+1 : i+1+end]
	return Attribute{Key: key, Value: value}, b[i+1+end+1:], nil
}

// CData returns the payload of a KindCData event's bytes, stripping the
// <![CDATA[ ... ]]> delimiters.
func CData(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte("<![CDATA["))
	b = bytes.TrimSuffix(b, []byte("]]>"))
	return b
}

// Comment returns the payload of a KindComment event's bytes.
func Comment(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte("<!--"))
	b = bytes.TrimSuffix(b, []byte("-->"))
	return b
}

// Unescape decodes XML entity references in place and normalizes "\r" and
// "\r\n" line endings to "\n", returning a subslice of b. The input is
// mutated. Safe on record/batch slices because they are disjoint views.
func Unescape(b []byte) ([]byte, error) {
	p := indexUnescape(b)
	if p < 0 {
		return b, nil
	}
	begin := 0
	cur := p
	for {
		if b[p] == '&' {
			var escaped []byte
			// Named entities are at most 4 bytes ("quot"); numeric character
			// references may carry arbitrarily many leading zeros
			// ("&#00000010000;"), which encoding/xml accepts — found by
			// FuzzDifferential (testdata/fuzz/.../89aafa2682ad6a09 and
			// .../080116c739ec036c), so their ';' scan is unbounded.
			// Still linear overall:
			// successful scans cover disjoint spans and a failed scan errors
			// out immediately.
			lim := len(b) - p
			if p+1 >= len(b) || b[p+1] != '#' {
				lim = min(13, lim)
			}
			for i := 2; i < lim; i++ {
				if b[p+i] == ';' {
					escaped = b[p+1 : p+i]
					break
				}
			}
			if len(escaped) <= 1 {
				return nil, errors.New("fastsax: invalid escape sequence")
			}
			if cur != p && begin != p {
				cur += copy(b[cur:], b[begin:p])
			}
			if escaped[0] == '#' {
				var x uint64
				var err error
				if escaped[1] == 'x' || escaped[1] == 'X' {
					x, err = strconv.ParseUint(string(escaped[2:]), 16, 32)
				} else {
					x, err = strconv.ParseUint(string(escaped[1:]), 10, 32)
				}
				if err != nil {
					return nil, fmt.Errorf("fastsax: invalid char reference: %w", err)
				}
				cur += utf8.EncodeRune(b[cur:], rune(x))
			} else {
				switch string(escaped) {
				case "lt":
					b[cur] = '<'
				case "gt":
					b[cur] = '>'
				case "amp":
					b[cur] = '&'
				case "apos":
					b[cur] = '\''
				case "quot":
					b[cur] = '"'
				default:
					return nil, fmt.Errorf("fastsax: unknown entity %q", string(escaped))
				}
				cur++
			}
			begin = p + len(escaped) + 2
		} else { // '\r'
			if cur != p && begin != p {
				cur += copy(b[cur:], b[begin:p])
			}
			b[cur] = '\n'
			cur++
			begin = p + 1
			if p+1 < len(b) && b[p+1] == '\n' {
				begin++
			}
		}
		if i := indexUnescape(b[begin:]); i >= 0 {
			p = begin + i
		} else {
			break
		}
	}
	if len(b) != begin {
		cur += copy(b[cur:], b[begin:])
	}
	return b[:cur], nil
}

// UnescapeAppend appends the unescaped form of src to dst without mutating
// src. Use it when the decoded text must outlive the batch/record.
func UnescapeAppend(dst, src []byte) ([]byte, error) {
	p := indexUnescape(src)
	if p < 0 {
		return append(dst, src...), nil
	}
	dst = append(dst, src...)
	out, err := Unescape(dst[len(dst)-len(src):])
	if err != nil {
		return nil, err
	}
	return dst[:len(dst)-len(src)+len(out)], nil
}

func indexUnescape(s []byte) int {
	a := bytes.IndexByte(s, '&')
	r := bytes.IndexByte(s, '\r')
	if a < 0 {
		return r
	}
	if r >= 0 && r < a {
		return r
	}
	return a
}
