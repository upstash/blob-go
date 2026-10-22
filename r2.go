package blob

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxPresignSeconds is the longest url the signing service signs; it is also how long one outlives
// a suspension or a password rotation.
const maxPresignSeconds = 600

const (
	defaultRetries = 2
	presignTimeout = 10 * time.Second
	// Error documents and listings are small; anything past this is not one.
	maxXMLBody = 16 << 20
)

// R2 answers a temporary credential that has expired with a 403 naming it, which is
// indistinguishable from a signature error unless the body is read.
var credentialRejected = regexp.MustCompile(`ExpiredToken|InvalidAccessKeyId|TokenRefreshRequired`)

type r2 struct {
	bucketID string
	token    string
	hostname string
	// The bucket password: the HMAC key for completion tokens. Never leaves the server.
	signingSecret string
	defaultCache  string
	telemetry     bool
	retry         retryPolicy
	creds         *credentialCache
	client        *http.Client
	// The visibility the last credential this bucket fetched carried. Kept here rather than read off
	// the shared cache, which another request can empty between a fetch and the read.
	vis atomic.Value
}

type r2Request struct {
	method string
	// path is the object key; "" addresses the bucket itself.
	path    string
	query   map[string]string
	headers map[string]string
	// At most one of body, stream and open. A stream is sent once and never retried; open hands
	// every attempt its own reader, since the transport may still be reading the last one.
	body   []byte
	stream io.Reader
	open   func() io.Reader
	length int64
}

func (q *r2Request) streaming() bool { return q.stream != nil }

func (r *r2) credentials(ctx context.Context) (*tempCredentials, error) {
	c, err := r.creds.get(ctx, r.client, r.retry)
	if err == nil {
		r.vis.Store(c.Visibility)
	}
	return c, err
}

// visibility is what the credentials response said, else public. Read after credentials() has
// resolved, which every request does before it writes a header or builds a BlobObject.
func (r *r2) visibility() string {
	if v, _ := r.vis.Load().(string); v != "" {
		return v
	}
	return "public"
}

// publicURL is "" on a private bucket: nothing serves its objects over the public host.
func (r *r2) publicURL(path string) string {
	if r.visibility() == "private" {
		return ""
	}
	enc, err := encodeKey(path)
	if err != nil {
		return ""
	}
	return "https://" + r.hostname + "/" + enc
}

func (r *r2) blobObject(path string, size int64, etag string, uploadedAt time.Time) BlobObject {
	b := BlobObject{Path: path, Size: size, ETag: etag, UploadedAt: uploadedAt}
	if u := r.publicURL(path); u != "" {
		b.URL = u
		b.VersionedURL = u + "?v=" + url.QueryEscape(etag)
	}
	return b
}

func (r *r2) objectURL(c *tempCredentials, path string, query map[string]string) (*url.URL, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, err
	}
	raw := "/" + uriEncode(c.Bucket, false)
	if path != "" {
		enc, err := encodeKey(path)
		if err != nil {
			return nil, err
		}
		raw += "/" + enc
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawPath = decoded, raw
	u.RawQuery = encodeQuery(query)
	return u, nil
}

var retriableMethods = map[string]bool{"GET": true, "HEAD": true, "PUT": true, "DELETE": true}

func (r *r2) attempts() int { return r.retry.retriesOr(defaultRetries) + 1 }

func (r *r2) wait(attempt int, retryAfter string) time.Duration {
	if r.retry.backoff == nil {
		return backoff(attempt, retryAfter, 200*time.Millisecond)
	}
	if _, ok := retryAfterSeconds(retryAfter); ok {
		return backoff(attempt, retryAfter, 200*time.Millisecond)
	}
	return max(r.retry.backoff(attempt-1), 0)
}

// fetch sends one signed request. A 5xx, a 429 and a dropped connection are retried for the verbs
// that can be sent twice safely; multipart complete and the batch delete are POSTs and are not. A
// stream is never retried: it has already been read once.
func (r *r2) fetch(ctx context.Context, q r2Request) (*http.Response, error) {
	streaming := q.streaming()
	attempts := 1
	if !streaming && retriableMethods[q.method] {
		attempts = r.attempts()
	}
	refreshed := false
	for attempt := 1; ; attempt++ {
		res, signedWith, err := r.send(ctx, q)
		if err != nil {
			// An *Error here came from minting a credential, which has its own retry policy and its
			// own verdict; only a dropped connection is this loop's to retry.
			if _, ok := asBlobError(err); ok {
				return nil, err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt >= attempts {
				return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "could not reach storage", Status: 502, Cause: err})
			}
			if err := sleep(ctx, r.wait(attempt, "")); err != nil {
				return nil, err
			}
			continue
		}
		if res.StatusCode == 403 && !refreshed && !streaming {
			// A HEAD carries no body to name the reason, so a credential that has visibly run out
			// counts as the same finding: re-mint once and ask again.
			outlived := false
			if c := r.creds.peek(); c != nil && !time.Now().Before(c.expiry()) {
				outlived = true
			}
			text, _ := io.ReadAll(io.LimitReader(res.Body, maxXMLBody))
			_ = res.Body.Close()
			if outlived || credentialRejected.Match(text) {
				refreshed = true
				r.creds.invalidate(signedWith)
				continue
			}
			ct := res.Header.Get("Content-Type")
			if ct == "" {
				ct = "application/xml"
			}
			return &http.Response{StatusCode: 403, Status: res.Status, Header: http.Header{"Content-Type": {ct}}, Body: io.NopCloser(bytes.NewReader(text))}, nil
		}
		if attempt < attempts && (res.StatusCode == 429 || res.StatusCode >= 500) && ctx.Err() == nil {
			retryAfter := res.Header.Get("Retry-After")
			drain(res)
			if err := sleep(ctx, r.wait(attempt, retryAfter)); err != nil {
				return nil, err
			}
			continue
		}
		return res, nil
	}
}

func (r *r2) send(ctx context.Context, q r2Request) (*http.Response, *tempCredentials, error) {
	c, err := r.credentials(ctx)
	if err != nil {
		return nil, nil, err
	}
	u, err := r.objectURL(c, q.path, q.query)
	if err != nil {
		return nil, nil, err
	}
	signed := signHeaders(signingCredentials{c.AccessKeyID, c.SecretAccessKey, c.SessionToken, c.Region}, q.method, u, q.headers, time.Now())
	var body io.Reader
	length := int64(0)
	switch {
	case q.stream != nil:
		body, length = q.stream, q.length
	case q.open != nil:
		body, length = q.open(), q.length
	case q.body != nil:
		body, length = bytes.NewReader(q.body), int64(len(q.body))
	}
	req, err := http.NewRequestWithContext(ctx, q.method, u.String(), body)
	if err != nil {
		return nil, nil, err
	}
	// The URL is rebuilt from its string, which can re-encode the path; the signature is over RawPath.
	req.URL = u
	if q.stream != nil || q.open != nil {
		// NewRequest only sizes the readers it knows; a wrapped stream would go chunked.
		req.ContentLength = length
		if length == 0 {
			req.Body = http.NoBody
		}
	}
	for k, v := range signed {
		if k == "content-length" {
			continue
		}
		req.Header.Set(k, v)
	}
	// Otherwise the transport negotiates gzip, which drops Content-Length and weakens ETags; object
	// reads need the stored representation for size checks and conditional writes.
	if q.method == "GET" || q.method == "HEAD" {
		req.Header.Set("Accept-Encoding", "identity")
	}
	res, err := r.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	return res, c, nil
}

type presignInit struct {
	method    string
	path      string
	expiresIn int
	headers   map[string]string
	query     map[string]string
	// partNumber > 0 signs one part of a multipart upload rather than the object.
	partNumber int
	uploadID   string
}

type presigned struct {
	url       string
	expiresAt time.Time
}

// presign gets a url for one operation on one object, signed by the agent. Never signed here: R2
// derives a temporary credential's secret from its session token and a url has to carry that token,
// so a url signed with it would hand its holder every object in the bucket until it expires.
func (r *r2) presign(ctx context.Context, init presignInit) (presigned, error) {
	if err := presignableKey(init.path); err != nil {
		return presigned{}, err
	}
	payload := map[string]any{
		"method":    init.method,
		"key":       init.path,
		"expiresIn": min(maxPresignSeconds, max(1, init.expiresIn)),
	}
	if len(init.headers) > 0 {
		payload["headers"] = init.headers
	}
	if len(init.query) > 0 {
		payload["query"] = init.query
	}
	if init.partNumber > 0 {
		payload["partNumber"] = init.partNumber
		payload["uploadId"] = init.uploadID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return presigned{}, err
	}
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, presignTimeout)
		req, err := http.NewRequestWithContext(actx, http.MethodPost, agentURL+"/v1/presign", bytes.NewReader(body))
		if err != nil {
			cancel()
			return presigned{}, err
		}
		req.Header.Set("Authorization", "Bearer "+r.token)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range telemetryHeaders(r.telemetry) {
			req.Header.Set(k, v)
		}
		res, err := r.client.Do(req)
		if err != nil {
			timedOut := errors.Is(actx.Err(), context.DeadlineExceeded)
			cancel()
			if ctx.Err() != nil {
				return presigned{}, ctx.Err()
			}
			// A hung agent is not asked again: three timeouts would hold an upload's begin for 30 s.
			if timedOut || attempt >= r.attempts() {
				return presigned{}, NewError(CodeRequestFailed, ErrorOptions{Message: "could not reach the signing service", Status: 502, Cause: err})
			}
			if err := sleep(ctx, r.wait(attempt, "")); err != nil {
				return presigned{}, err
			}
			continue
		}
		// Signing has no side effect, so every 429 and 5xx is safe to ask again.
		if attempt < r.attempts() && (res.StatusCode == 429 || res.StatusCode >= 500) {
			retryAfter := res.Header.Get("Retry-After")
			drain(res)
			cancel()
			if err := sleep(ctx, r.wait(attempt, retryAfter)); err != nil {
				return presigned{}, err
			}
			continue
		}
		p, err := presignedFrom(res)
		cancel()
		return p, err
	}
}

func presignedFrom(res *http.Response) (presigned, error) {
	defer drain(res)
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body)
	reason, _ := body["error"].(string)
	status := res.StatusCode
	// 413 is a request body over the agent's cap, which only oversized metadata reaches.
	if status == 400 || status == 413 {
		if reason == "" {
			reason = "bad request"
			if status == 413 {
				reason = "body too large"
			}
		}
		return presigned{}, newErr(CodeInvalidInput, "the signing service refused the request: "+reason)
	}
	// A 401 or 403 reason is the bucket owner's billing notice (suspended, read-only), and an upload
	// route hands the message to its end users, so it rides on the cause, which is never sent.
	var cause error
	if reason != "" {
		cause = errors.New(reason)
	}
	switch {
	case status == 401:
		return presigned{}, NewError(CodeUnauthorized, ErrorOptions{Message: "the bucket token was rejected", Cause: cause})
	case status == 403:
		return presigned{}, NewError(CodeForbidden, ErrorOptions{Message: "Upstash refused to sign a url for this bucket", Cause: cause})
	case status == 429:
		return presigned{}, newErr(CodeRateLimited, "presign requests are rate limited")
	case status < 200 || status > 299:
		msg := fmt.Sprintf("presign request failed with %d", status)
		if reason != "" {
			msg += ": " + reason
		}
		return presigned{}, NewError(CodeRequestFailed, ErrorOptions{Message: msg, Status: 502})
	}
	// The url is handed to whoever the caller gives it to: refuse anything but R2 over https.
	raw, _ := body["url"].(string)
	exp, ok := body["expiresAt"].(float64)
	if !isR2URL(raw) || !ok || math.IsNaN(exp) || math.IsInf(exp, 0) {
		return presigned{}, NewError(CodeRequestFailed, ErrorOptions{Message: "the signing service answered with an unexpected url", Status: 502})
	}
	return presigned{url: raw, expiresAt: time.UnixMilli(int64(exp * 1000))}, nil
}

type blobHead struct {
	size        int64
	etag        string
	contentType string
	// Verbatim from storage; "" when the object was stored without one.
	cacheControl string
	metadata     map[string]string
	uploadedAt   time.Time
}

func (r *r2) head(ctx context.Context, path string) (*blobHead, error) {
	res, err := r.fetch(ctx, r2Request{method: "HEAD", path: path})
	if err != nil {
		return nil, err
	}
	if res.StatusCode == 404 {
		drain(res)
		return nil, nil
	}
	if !ok(res) {
		return nil, errorFromResponse(res)
	}
	drain(res)
	return headFromHeaders(res)
}

var digits = regexp.MustCompile(`^\d+$`)

func headFromHeaders(res *http.Response) (*blobHead, error) {
	h := res.Header
	length := h.Get("Content-Length")
	size := int64(-1)
	if digits.MatchString(length) {
		if n, err := strconv.ParseInt(length, 10, 64); err == nil {
			size = n
		}
	} else if length == "" && res.ContentLength >= 0 && res.Request != nil && res.Request.Method != "HEAD" {
		size = res.ContentLength
	}
	if size < 0 {
		return nil, newErr(CodeRequestFailed, "storage returned a missing or invalid Content-Length")
	}
	metadata := map[string]string{}
	for k, v := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			metadata[lk[len("x-amz-meta-"):]] = v[0]
		}
	}
	contentType := h.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	uploadedAt := time.Now()
	if lm := h.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			uploadedAt = t
		}
	}
	return &blobHead{
		size:         size,
		etag:         h.Get("ETag"),
		contentType:  contentType,
		cacheControl: h.Get("Cache-Control"),
		metadata:     metadata,
		uploadedAt:   uploadedAt,
	}, nil
}

func ok(res *http.Response) bool { return res.StatusCode >= 200 && res.StatusCode <= 299 }

// readXML reads a whole (small) response body.
func readXML(res *http.Response) (string, error) {
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxXMLBody))
	if err != nil {
		return "", NewError(CodeRequestFailed, ErrorOptions{Message: "could not read the storage response", Status: 502, Cause: err})
	}
	return string(b), nil
}

func (r *r2) createMultipart(ctx context.Context, path string, headers map[string]string) (string, error) {
	res, err := r.fetch(ctx, r2Request{method: "POST", path: path, query: map[string]string{"uploads": ""}, headers: headers})
	if err != nil {
		return "", err
	}
	text, err := readXML(res)
	if err != nil {
		return "", err
	}
	if !ok(res) {
		return "", errorFromBody(res.StatusCode, text)
	}
	var doc struct {
		UploadID string `xml:"UploadId"`
	}
	if xml.Unmarshal([]byte(text), &doc) != nil || doc.UploadID == "" {
		return "", NewError(CodeRequestFailed, ErrorOptions{Message: "CreateMultipartUpload returned no upload id", Status: 502})
	}
	return doc.UploadID, nil
}

type landedPart struct {
	N    int    `json:"n"`
	ETag string `json:"etag"`
}

func (r *r2) listParts(ctx context.Context, path, uploadID string) ([]landedPart, error) {
	var out []landedPart
	marker := ""
	for {
		query := map[string]string{"uploadId": uploadID, "max-parts": "1000"}
		if marker != "" {
			query["part-number-marker"] = marker
		}
		res, err := r.fetch(ctx, r2Request{method: "GET", path: path, query: query})
		if err != nil {
			return nil, err
		}
		text, err := readXML(res)
		if err != nil {
			return nil, err
		}
		if !ok(res) {
			return nil, errorFromBody(res.StatusCode, text)
		}
		var doc struct {
			Parts []struct {
				PartNumber int    `xml:"PartNumber"`
				ETag       string `xml:"ETag"`
			} `xml:"Part"`
			IsTruncated          bool   `xml:"IsTruncated"`
			NextPartNumberMarker string `xml:"NextPartNumberMarker"`
		}
		if err := xml.Unmarshal([]byte(text), &doc); err != nil {
			return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "storage answered ListParts with an unreadable document", Status: 502, Cause: err})
		}
		for _, p := range doc.Parts {
			out = append(out, landedPart{N: p.PartNumber, ETag: p.ETag})
		}
		if !doc.IsTruncated || doc.NextPartNumberMarker == "" || doc.NextPartNumberMarker == marker {
			return out, nil
		}
		marker = doc.NextPartNumberMarker
	}
}

func (r *r2) listMultipartUploads(ctx context.Context, prefix string) ([]MultipartUpload, error) {
	var out []MultipartUpload
	keyMarker, idMarker := "", ""
	for {
		query := map[string]string{"uploads": "", "max-uploads": "1000"}
		if prefix != "" {
			query["prefix"] = prefix
		}
		if keyMarker != "" {
			query["key-marker"] = keyMarker
		}
		if idMarker != "" {
			query["upload-id-marker"] = idMarker
		}
		res, err := r.fetch(ctx, r2Request{method: "GET", query: query})
		if err != nil {
			return nil, err
		}
		text, err := readXML(res)
		if err != nil {
			return nil, err
		}
		if !ok(res) {
			return nil, errorFromBody(res.StatusCode, text)
		}
		var doc struct {
			Uploads []struct {
				Key       *string `xml:"Key"`
				UploadID  *string `xml:"UploadId"`
				Initiated string  `xml:"Initiated"`
			} `xml:"Upload"`
			IsTruncated        bool   `xml:"IsTruncated"`
			NextKeyMarker      string `xml:"NextKeyMarker"`
			NextUploadIDMarker string `xml:"NextUploadIdMarker"`
		}
		if err := xml.Unmarshal([]byte(text), &doc); err != nil {
			return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "storage answered ListMultipartUploads with an unreadable document", Status: 502, Cause: err})
		}
		for _, u := range doc.Uploads {
			if u.Key == nil || u.UploadID == nil {
				continue
			}
			initiated, _ := time.Parse(time.RFC3339Nano, u.Initiated)
			out = append(out, MultipartUpload{Path: *u.Key, UploadID: *u.UploadID, InitiatedAt: initiated})
		}
		if !doc.IsTruncated || doc.NextKeyMarker == "" || (doc.NextKeyMarker == keyMarker && doc.NextUploadIDMarker == idMarker) {
			return out, nil
		}
		keyMarker, idMarker = doc.NextKeyMarker, doc.NextUploadIDMarker
	}
}

func (r *r2) completeMultipart(ctx context.Context, path, uploadID string, parts []landedPart) (string, error) {
	sorted := append([]landedPart(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].N < sorted[j].N })
	var b strings.Builder
	b.WriteString("<CompleteMultipartUpload>")
	for _, p := range sorted {
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", p.N, escapeXML(p.ETag))
	}
	b.WriteString("</CompleteMultipartUpload>")
	res, err := r.fetch(ctx, r2Request{method: "POST", path: path, query: map[string]string{"uploadId": uploadID}, headers: map[string]string{"content-type": "application/xml"}, body: []byte(b.String())})
	if err != nil {
		return "", err
	}
	text, err := readXML(res)
	if err != nil {
		return "", err
	}
	if !ok(res) {
		return "", errorFromBody(res.StatusCode, text)
	}
	// A 200 can still carry an error document.
	if xmlTag(text, "Code") != "" {
		return "", errorFromBody(500, text)
	}
	var doc struct {
		ETag string `xml:"ETag"`
	}
	_ = xml.Unmarshal([]byte(text), &doc)
	return doc.ETag, nil
}

func (r *r2) abortMultipart(ctx context.Context, path, uploadID string) error {
	res, err := r.fetch(ctx, r2Request{method: "DELETE", path: path, query: map[string]string{"uploadId": uploadID}})
	if err != nil {
		return err
	}
	if !ok(res) && res.StatusCode != 404 {
		return errorFromResponse(res)
	}
	drain(res)
	return nil
}

// xmlTag is the text of the first <name> element, entities decoded; "" when there is none.
var xmlTags = map[string]*regexp.Regexp{
	"Code":    regexp.MustCompile(`<Code>([\s\S]*?)</Code>`),
	"Message": regexp.MustCompile(`<Message>([\s\S]*?)</Message>`),
}

func xmlTag(doc, name string) string {
	m := xmlTags[name].FindStringSubmatch(doc)
	if m == nil {
		return ""
	}
	var s string
	if xml.Unmarshal([]byte("<x>"+m[1]+"</x>"), &s) != nil {
		return m[1]
	}
	return s
}

func errorFromResponse(res *http.Response) error {
	text, _ := readXML(res)
	return errorFromBody(res.StatusCode, text)
}

// errorFromBody maps a storage answer to an *Error. Storage's own message is for whoever debugs
// the app, not for a user it would be shown to, so it rides on the cause.
func errorFromBody(status int, doc string) *Error {
	code := xmlTag(doc, "Code")
	message := xmlTag(doc, "Message")
	switch {
	case status == 404 || code == "NoSuchKey" || code == "NoSuchUpload":
		return NewError(CodeNotFound, ErrorOptions{})
	case status == 412 || code == "PreconditionFailed":
		return NewError(CodeConflict, ErrorOptions{})
	case status == 401:
		return NewError(CodeUnauthorized, ErrorOptions{})
	case status == 403 && code != "" && credentialRejected.MatchString(code):
		return NewError(CodeUnauthorized, ErrorOptions{Message: "storage refused the temporary credential", Hint: "it expired mid-request; the SDK re-mints and retries once"})
	case status == 403:
		return NewError(CodeSignatureMismatch, ErrorOptions{})
	case status == 429 || code == "SlowDown" || code == "TooManyRequests":
		return newErr(CodeRateLimited, "storage rate limited the request")
	case status == 503:
		return NewError(CodeNotReady, ErrorOptions{})
	case status == 413 || code == "EntityTooLarge":
		return NewError(CodeTooLarge, ErrorOptions{})
	}
	msg := fmt.Sprintf("storage responded %d", status)
	if code != "" {
		msg += " " + code
	}
	s := status
	if s >= 500 {
		s = 502
	}
	var cause error
	if message != "" {
		cause = errors.New(message)
	}
	return NewError(CodeRequestFailed, ErrorOptions{Message: msg, Status: s, Cause: cause})
}
