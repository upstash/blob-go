package blob

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// tokenPayload is what a completion token carries between an upload's phases. Signed, not
// encrypted: it is readable in devtools, so State carries an id, never a secret.
type tokenPayload struct {
	V int `json:"v"`
	// Bucket id the grant is bound to.
	B string `json:"b"`
	// Route id the grant is bound to: one bucket's routes all sign with the same key.
	R string `json:"r"`
	// Upload id: what makes an at-least-once phase 'end' idempotent for the app.
	ID   string `json:"id"`
	Path string `json:"path"`
	// The file's name as the browser gave it.
	N    string `json:"n"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	// Headers pinned into the signature: content-type, cache-control, x-amz-meta-*.
	Headers map[string]string `json:"headers"`
	// What onBeforeUpload returned as State.
	Ctx json.RawMessage `json:"ctx,omitempty"`
	// Unix ms.
	Exp int64 `json:"exp"`
	// R2's own multipart id; absent for a single PUT, which has no upload to complete or abort.
	UploadID string `json:"uploadId,omitempty"`
	// The part size for a multipart, and the whole file for a single PUT.
	PartSize int64 `json:"partSize"`
}

func completionMAC(body, key string) string {
	return base64.RawURLEncoding.EncodeToString(hmacSHA256([]byte("upstash-blob-completion:"+key), body))
}

func signCompletionToken(p *tokenPayload, key string) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + completionMAC(body, key), nil
}

// verifyCompletionToken is nil for anything but a token this bucket's key signed.
func verifyCompletionToken(token, key string) *tokenPayload {
	body, sig, found := strings.Cut(token, ".")
	if !found {
		return nil
	}
	if !hmac.Equal([]byte(sig), []byte(completionMAC(body, key))) {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body, "="))
	if err != nil {
		return nil
	}
	var p tokenPayload
	if json.Unmarshal(raw, &p) != nil || p.V != 1 {
		return nil
	}
	return &p
}
