package blob

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Storage's XML is read with patterns, as blob-js reads it, not with encoding/xml: a key may hold a
// character XML 1.0 cannot carry, which encoding/xml refuses along with the whole listing, or a
// "\r", which it reads back as "\n" and so names a different key.
var xmlPatterns sync.Map // element name -> *regexp.Regexp

func xmlPattern(name string) *regexp.Regexp {
	if re, ok := xmlPatterns.Load(name); ok {
		return re.(*regexp.Regexp)
	}
	q := regexp.QuoteMeta(name)
	re, _ := xmlPatterns.LoadOrStore(name, regexp.MustCompile(`<`+q+`>([\s\S]*?)</`+q+`>`))
	return re.(*regexp.Regexp)
}

// xmlTag is the text of the first <name> element, entities decoded, and whether there is one.
func xmlTag(doc, name string) (string, bool) {
	m := xmlPattern(name).FindStringSubmatch(doc)
	if m == nil {
		return "", false
	}
	return decodeEntities(m[1]), true
}

// xmlText is xmlTag without the presence flag.
func xmlText(doc, name string) string {
	s, _ := xmlTag(doc, name)
	return s
}

// xmlBlocks is every <name> element, tags included, for reading its children with xmlTag.
func xmlBlocks(doc, name string) []string {
	return xmlPattern(name).FindAllString(doc, -1)
}

var entity = regexp.MustCompile(`&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|amp|quot|apos);`)

func decodeEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	return entity.ReplaceAllStringFunc(s, func(e string) string {
		switch name := e[1 : len(e)-1]; name {
		case "lt":
			return "<"
		case "gt":
			return ">"
		case "amp":
			return "&"
		case "quot":
			return `"`
		case "apos":
			return "'"
		default:
			var n uint64
			var err error
			if name[1] == 'x' {
				n, err = strconv.ParseUint(name[2:], 16, 32)
			} else {
				n, err = strconv.ParseUint(name[1:], 10, 32)
			}
			if err != nil || !utf8.ValidRune(rune(n)) {
				return e
			}
			return string(rune(n))
		}
	})
}

// escapeXML escapes text for an element. "\r" goes as a character reference, since a parser reads
// a literal one as "\n".
func escapeXML(s string) string {
	return xmlEscaper.Replace(s)
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#13;")

// xmlCarries reports whether XML 1.0 can carry s at all; it cannot carry most control characters,
// even as references.
func xmlCarries(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
