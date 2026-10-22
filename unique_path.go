package blob

import (
	"crypto/rand"
	"encoding/binary"
	"regexp"
	"strings"
)

const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var extensionRE = regexp.MustCompile(`(?i)\.[a-z0-9]{1,8}$`)

func randomSuffix() string {
	// 2^32 % 58 != 0, so a plain modulo would over-pick the low symbols: reject the short tail.
	const limit = (1 << 32) / uint64(len(base58)) * uint64(len(base58))
	out := make([]byte, 0, 8)
	var buf [4]byte
	for len(out) < 8 {
		_, _ = rand.Read(buf[:])
		n := uint64(binary.LittleEndian.Uint32(buf[:]))
		if n >= limit {
			continue
		}
		out = append(out, base58[n%uint64(len(base58))])
	}
	return string(out)
}

// UniquePath adds an eight-character random suffix to the final filename, before its extension, so
// uploads never overwrite each other. Everything else is kept exactly as given: case, spaces,
// punctuation, Unicode, slashes and length.
//
//	blob.UniquePath("users/" + userID + "/" + file.Name) // "users/alice/Q3 Report-<random>.pdf"
//
// An empty final filename uses "file". Paths are not validated here: every request refuses "." and
// ".." segments. Store the returned path and use it unchanged for later reads and deletes.
func UniquePath(path string) string {
	at := strings.LastIndex(path, "/") + 1
	dir, name := path[:at], path[at:]
	stem, ext := name, ""
	if loc := extensionRE.FindStringIndex(name); loc != nil && loc[0] > 0 {
		stem, ext = name[:loc[0]], name[loc[0]:]
	}
	if stem == "" {
		stem = "file"
	}
	return dir + stem + "-" + randomSuffix() + ext
}
