package blob

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
)

func errorsAs(err error, target any) bool { return errors.As(err, target) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func regexpMatch(re, s string) bool { return regexp.MustCompile(re).MatchString(s) }

func encodeToken(bucketID, password, hashForDomain string, flags byte) string {
	out := []byte{tokenVersion, flags, byte(len(bucketID)), byte(len(password) >> 8), byte(len(password)), byte(len(hashForDomain))}
	out = append(out, bucketID...)
	out = append(out, password...)
	out = append(out, hashForDomain...)
	return base64.RawURLEncoding.EncodeToString(out)
}

func resetCredentialCaches() {
	cachesMu.Lock()
	defer cachesMu.Unlock()
	caches = map[cacheKey]*credentialCache{}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
