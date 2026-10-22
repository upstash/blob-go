package blob

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// encodeKey percent-encodes a path segment by segment. A temporary credential authorises the whole
// bucket and a URL parser resolves "..", so a traversing key would touch a different object than
// the one named: it is refused rather than normalised.
func encodeKey(path string) (string, error) {
	if path == "" {
		return "", newErr(CodeInvalidInput, "path must be a non-empty string")
	}
	if !utf8.ValidString(path) {
		return "", newErr(CodeInvalidInput, "path must be valid UTF-8")
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		if s == "." || s == ".." {
			return "", newErr(CodeInvalidInput, fmt.Sprintf("path may not contain \".\" or \"..\" segments: %s", path))
		}
		segments[i] = uriEncode(s, false)
	}
	return strings.Join(segments, "/"), nil
}

// presignableKey refuses what the signing service will not sign: an empty segment ("dir/", "a//b")
// or a control character. Checked here too, so an upload with such a path fails before its
// multipart is created.
func presignableKey(path string) error {
	if _, err := encodeKey(path); err != nil {
		return err
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return newErr(CodeInvalidInput, "a signed url cannot name a path with control characters")
		}
	}
	for _, s := range strings.Split(path, "/") {
		if s == "" {
			return NewError(CodeInvalidInput, ErrorOptions{
				Message: "a signed url cannot name a path with an empty segment",
				Hint:    `drop the leading, trailing or doubled "/"`,
			})
		}
	}
	return nil
}

var headerNameRE = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

// metaHeaders turns metadata into x-amz-meta-* headers. Keys must be lowercase, since storage hands
// them back lowercased, and values printable ASCII, since storage does not carry anything else back
// unchanged (measured: "café" comes back as "=?utf-8?Q?caf=C3=A9?=").
func metaHeaders(metadata map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(metadata))
	for k, v := range metadata {
		if !headerNameRE.MatchString(k) {
			return nil, newErr(CodeInvalidInput, fmt.Sprintf("metadata key %q is not a valid header name", k))
		}
		if k != strings.ToLower(k) {
			return nil, NewError(CodeInvalidInput, ErrorOptions{
				Message: fmt.Sprintf("metadata key %q must be lowercase", k),
				Hint:    fmt.Sprintf("storage returns keys lowercased; write %q", strings.ToLower(k)),
			})
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				return nil, NewError(CodeInvalidInput, ErrorOptions{
					Message: fmt.Sprintf("metadata.%s has characters storage does not carry back unchanged", k),
					Hint:    "metadata is printable ASCII; percent-encode anything else with url.QueryEscape",
				})
			}
		}
		out["x-amz-meta-"+k] = v
	}
	return out, nil
}
