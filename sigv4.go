package blob

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, service s3, UNSIGNED-PAYLOAD throughout so bodies stream without a hash.

const unsignedPayload = "UNSIGNED-PAYLOAD"

type signingCredentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
}

// uriEncode percent-encodes every byte outside the unreserved set, which S3 requires and
// url.PathEscape does not do.
func uriEncode(s string, keepSlash bool) string {
	const hexUpper = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper[c>>4])
		b.WriteByte(hexUpper[c&15])
	}
	return b.String()
}

// encodeQuery is the canonical query string, which is also what the request sends, so the two
// cannot disagree about an encoding.
func encodeQuery(query map[string]string) string {
	if len(query) == 0 {
		return ""
	}
	pairs := make([][2]string, 0, len(query))
	for k, v := range query {
		pairs = append(pairs, [2]string{uriEncode(k, false), uriEncode(v, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p[0] + "=" + p[1]
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// signHeaders returns the full header set to send, lowercased, for a header-authenticated request.
// u must carry the encoded path in RawPath (or a path that needs no encoding) and the query from
// encodeQuery.
func signHeaders(creds signingCredentials, method string, u *url.URL, headers map[string]string, now time.Time) map[string]string {
	amz := now.UTC().Format("20060102T150405Z")
	day := amz[:8]
	out := make(map[string]string, len(headers)+4)
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	out["host"] = u.Host
	out["x-amz-date"] = amz
	out["x-amz-content-sha256"] = unsignedPayload
	if creds.sessionToken != "" {
		out["x-amz-security-token"] = creds.sessionToken
	}

	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, k := range names {
		canonical.WriteString(k + ":" + strings.Join(strings.Fields(out[k]), " ") + "\n")
	}
	signed := strings.Join(names, ";")

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{strings.ToUpper(method), path, u.RawQuery, canonical.String(), signed, unsignedPayload}, "\n")
	scope := day + "/" + creds.region + "/s3/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amz, scope, sha256Hex(canonicalRequest)}, "\n")
	key := hmacSHA256([]byte("AWS4"+creds.secretAccessKey), day)
	key = hmacSHA256(key, creds.region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	out["authorization"] = "AWS4-HMAC-SHA256 Credential=" + creds.accessKeyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + sig
	delete(out, "host")
	return out
}
