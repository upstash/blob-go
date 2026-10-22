package blob

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	agentURL     = "https://blob.upstash.io"
	domainSuffix = "blob.upstash.io"
	tokenVersion = 0x02
)

type decodedToken struct {
	bucketID string
	password string
	// The bucket's public DNS label: <hashForDomain>.blob.upstash.io serves its objects.
	hashForDomain string
}

// decodeToken reads a bucket token. Trailing bytes mean tampering, so the length check is exact.
func decodeToken(token string) (decodedToken, error) {
	s := strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(strings.TrimSpace(token), "="))
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return decodedToken{}, errors.New("blob: token is not base64url")
	}
	if len(raw) < 6 || raw[0] != tokenVersion {
		return decodedToken{}, errors.New("blob: token: unsupported format")
	}
	idLen := int(raw[2])
	pwLen := int(raw[3])<<8 | int(raw[4])
	hLen := int(raw[5])
	if idLen == 0 || pwLen == 0 || hLen == 0 || len(raw) != 6+idLen+pwLen+hLen {
		return decodedToken{}, errors.New("blob: token: malformed")
	}
	return decodedToken{
		bucketID:      string(raw[6 : 6+idLen]),
		password:      string(raw[6+idLen : 6+idLen+pwLen]),
		hashForDomain: string(raw[6+idLen+pwLen:]),
	}, nil
}
