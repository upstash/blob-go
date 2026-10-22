package blob

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

func magic(b []byte, offset int, sig ...byte) bool {
	return len(b) >= offset+len(sig) && bytes.Equal(b[offset:offset+len(sig)], sig)
}

func asciiAt(b []byte, offset int, s string) bool {
	return len(b) >= offset+len(s) && string(b[offset:offset+len(s)]) == s
}

// The DIB header sizes BMP actually uses. Without this, "BM" matches any text beginning "BM".
var dibSizes = map[uint32]bool{12: true, 40: true, 52: true, 56: true, 64: true, 108: true, 124: true}

// The types a signature proves outright, with no sibling format sharing it. Only a declaration in
// this set can be contradicted by the bytes; containers (ISO-BMFF, EBML, Ogg, TIFF, fonts, MPEG
// audio, tar) are left out on purpose, because their signature proves the container and not the type.
var closedTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/bmp": true,
	"audio/wav": true, "video/x-msvideo": true, "application/pdf": true, "application/zip": true,
	"application/gzip": true, "application/x-7z-compressed": true, "application/x-rar-compressed": true,
	"application/x-bzip2": true,
}

// sniff is the type the leading bytes prove, or "" when they prove nothing it is willing to name.
func sniff(b []byte) string {
	// PNG's signature is a common polyglot prefix, so the IHDR chunk type at 12 is required too.
	if magic(b, 0, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) {
		if asciiAt(b, 12, "IHDR") {
			return "image/png"
		}
		return ""
	}
	if magic(b, 0, 0xff, 0xd8, 0xff) {
		return "image/jpeg"
	}
	if asciiAt(b, 0, "GIF87a") || asciiAt(b, 0, "GIF89a") {
		return "image/gif"
	}
	// RIFF at 0 is webp, wav and avi alike; the form type at 8 separates them.
	if asciiAt(b, 0, "RIFF") {
		switch {
		case asciiAt(b, 8, "WEBP"):
			return "image/webp"
		case asciiAt(b, 8, "WAVE"):
			return "audio/wav"
		case asciiAt(b, 8, "AVI "):
			return "video/x-msvideo"
		}
		return ""
	}
	if asciiAt(b, 0, "BM") && len(b) >= 18 {
		dib := uint32(b[14]) | uint32(b[15])<<8 | uint32(b[16])<<16 | uint32(b[17])<<24
		if dibSizes[dib] {
			return "image/bmp"
		}
	}
	if asciiAt(b, 0, "%PDF") {
		return "application/pdf"
	}
	if magic(b, 0, 0x50, 0x4b, 0x03, 0x04) || magic(b, 0, 0x50, 0x4b, 0x05, 0x06) || magic(b, 0, 0x50, 0x4b, 0x07, 0x08) {
		return "application/zip"
	}
	if magic(b, 0, 0x1f, 0x8b) {
		return "application/gzip"
	}
	if magic(b, 0, 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c) {
		return "application/x-7z-compressed"
	}
	if magic(b, 0, 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07) {
		return "application/x-rar-compressed"
	}
	// "BZh" is three ASCII letters; the level digit and the block magic make it a signature.
	if asciiAt(b, 0, "BZh") && len(b) > 3 && b[3] >= '1' && b[3] <= '9' && magic(b, 4, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59) {
		return "application/x-bzip2"
	}
	return ""
}

// What a wildcard means: a media family, not the subset sniff recognises. image/* never yields
// image/svg+xml: an SVG is script, so consenting to it has to be explicit.
var wildcards = map[string][]string{
	"image": {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/tiff", "image/avif", "image/heic", "image/heif", "image/x-icon"},
	"video": {"video/mp4", "video/quicktime", "video/webm", "video/x-matroska", "video/x-msvideo", "video/mpeg", "video/ogg", "video/3gpp"},
	"audio": {"audio/mpeg", "audio/wav", "audio/ogg", "audio/opus", "audio/flac", "audio/aac", "audio/mp4", "audio/webm"},
}

// Spellings browsers and operating systems really send for a type that has one canonical name.
var typeAliases = map[string]string{
	"image/jpg":                    "image/jpeg",
	"image/pjpeg":                  "image/jpeg",
	"image/vnd.microsoft.icon":     "image/x-icon",
	"audio/x-wav":                  "audio/wav",
	"audio/wave":                   "audio/wav",
	"audio/vnd.wave":               "audio/wav",
	"audio/mp3":                    "audio/mpeg",
	"audio/x-flac":                 "audio/flac",
	"audio/x-aac":                  "audio/aac",
	"video/avi":                    "video/x-msvideo",
	"video/msvideo":                "video/x-msvideo",
	"application/x-gzip":           "application/gzip",
	"application/x-zip-compressed": "application/zip",
	"application/vnd.rar":          "application/x-rar-compressed",
}

func bareType(t string) string {
	bare, _, _ := strings.Cut(t, ";")
	return strings.ToLower(strings.TrimSpace(bare))
}

func canonicalType(t string) string {
	bare := bareType(t)
	if a, ok := typeAliases[bare]; ok {
		return a
	}
	return bare
}

var typeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)

// expandContentTypes resolves the accept grammar to concrete types. Only image/*, video/* and
// audio/* exist; any other wildcard and an empty list are refused, because a list that matches
// everything is a limit that reads enforced and is not.
func expandContentTypes(allowed []string) ([]string, error) {
	if len(allowed) == 0 {
		return nil, newErr(CodeInvalidContentTypePattern, "contentTypes: empty list; omit the option to accept anything")
	}
	var out []string
	seen := map[string]bool{}
	push := func(t string) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, raw := range allowed {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if strings.HasSuffix(pattern, "/*") {
			family, ok := wildcards[strings.TrimSuffix(pattern, "/*")]
			if !ok {
				return nil, newErr(CodeInvalidContentTypePattern, fmt.Sprintf("contentTypes: only image/*, video/* and audio/* are wildcards, got %q", raw))
			}
			for _, t := range family {
				push(canonicalType(t))
			}
			continue
		}
		if !typeRE.MatchString(pattern) {
			return nil, newErr(CodeInvalidContentTypePattern, fmt.Sprintf("contentTypes: expected a \"type/subtype\", got %q", raw))
		}
		push(canonicalType(pattern))
	}
	return out, nil
}

// checkContentType checks the declared type against the allow list, and then against the bytes
// when there are any. The byte half refuses on a proven conflict only: bytes that prove nothing
// pass, and so do bytes that prove something the declaration cannot be checked against (a .docx
// really is a zip).
func checkContentType(declared string, head []byte, allowed []string) error {
	declaredBare := bareType(declared)
	want := canonicalType(declared)
	ok := false
	for _, a := range allowed {
		if canonicalType(a) == want {
			ok = true
			break
		}
	}
	if !ok {
		return NewError(CodeContentTypeNotAllowed, ErrorOptions{
			Message: declaredBare + " is not allowed",
			Hint:    "allowed: " + strings.Join(allowed, ", "),
		})
	}
	if head == nil {
		return nil
	}
	seen := sniff(head)
	if seen == "" || seen == want || !closedTypes[want] {
		return nil
	}
	return NewError(CodeContentTypeNotAllowed, ErrorOptions{
		Message: fmt.Sprintf("the bytes are %s, which cannot be served as %s", seen, declaredBare),
		Hint:    "declare the type the bytes actually are, or add it to ContentTypes",
	})
}
