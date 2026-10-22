package blob

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TokenEnv is the variable NewBucketFromEnv and an upload handler with no bucket read.
const TokenEnv = "UPSTASH_BLOB_TOKEN"

// Options configure a Bucket.
type Options struct {
	// Token is the bucket token from the Upstash Console.
	Token string
	// Cache is the Cache-Control written on every object this bucket stores; a per-call Cache
	// overrides it. See CacheImmutable for the values it takes.
	Cache string
	// DisableTelemetry stops sending the SDK version, Go version and platform as headers on
	// credential and signing requests to Upstash. UPSTASH_DISABLE_TELEMETRY in the environment also
	// turns it off.
	DisableTelemetry bool
	// Retry configures retries of failed requests. The zero value keeps the defaults.
	Retry RetryConfig
	// HTTPClient sends every request. Nil is http.DefaultClient.
	HTTPClient *http.Client
}

// Bucket is a client for one Upstash Blob bucket. It is safe for concurrent use, and cheap to build
// per request: buckets on one token share a credential.
type Bucket struct {
	r2 *r2
}

// NewBucket returns a client for the bucket the token names.
func NewBucket(token string) (*Bucket, error) {
	return NewBucketWith(Options{Token: token})
}

// NewBucketFromEnv reads the token from UPSTASH_BLOB_TOKEN.
func NewBucketFromEnv() (*Bucket, error) {
	token := os.Getenv(TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("blob: %s is not set", TokenEnv)
	}
	return NewBucketWith(Options{Token: token})
}

// NewBucketWith returns a client configured by options.
func NewBucketWith(options Options) (*Bucket, error) {
	// A token read from a file carries its newline, which no header can.
	options.Token = strings.TrimSpace(options.Token)
	if options.Token == "" {
		return nil, errors.New("blob: a token is required")
	}
	decoded, err := decodeToken(options.Token)
	if err != nil {
		return nil, err
	}
	if _, err := cacheControl(options.Cache, "public"); err != nil {
		return nil, err
	}
	retry, err := resolveRetry(options.Retry)
	if err != nil {
		return nil, err
	}
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	telemetry := !options.DisableTelemetry
	return &Bucket{r2: &r2{
		bucketID:      decoded.bucketID,
		token:         options.Token,
		hostname:      decoded.hashForDomain + "." + domainSuffix,
		signingSecret: decoded.password,
		defaultCache:  options.Cache,
		telemetry:     telemetry,
		retry:         retry,
		creds:         credentialCacheFor(options.Token, telemetry),
		client:        client,
	}}, nil
}

// BlobObject is the record of a stored blob: what a bucket listing carries, shared by every
// completed write.
type BlobObject struct {
	Path string `json:"path"`
	// URL is "" on a private bucket: no public host serves it, so use SignedReadURL.
	URL string `json:"url,omitempty"`
	// VersionedURL is URL?v=<etag>: the fix for a stable path that gets overwritten. "" when URL is.
	VersionedURL string    `json:"versionedUrl,omitempty"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	UploadedAt   time.Time `json:"uploadedAt"`
}

// CompletedBlob is a completed write, whose stored content type is known.
type CompletedBlob struct {
	BlobObject
	ContentType string `json:"contentType"`
}

// BlobInfo is a blob's record with its content type and metadata.
type BlobInfo struct {
	BlobObject
	ContentType string            `json:"contentType"`
	Metadata    map[string]string `json:"metadata"`
}

// BlobDownload is what Get answers: the blob's facts and its bytes. Close Body.
type BlobDownload struct {
	BlobInfo
	Body io.ReadCloser `json:"-"`
}

// PublicURL is the public object URL, or "" on a private bucket, where nothing serves objects over
// the public host. Whether the bucket is private comes from the backend, so the first call on a
// fresh bucket fetches credentials; after that it is local.
func (b *Bucket) PublicURL(ctx context.Context, path string) (string, error) {
	if _, err := encodeKey(path); err != nil {
		return "", err
	}
	if _, err := b.r2.credentials(ctx); err != nil {
		return "", err
	}
	return b.r2.publicURL(path), nil
}

/* ------------------------------------------------------------------ put */

// PutOptions are the options of Put. The zero value stores the body as application/octet-stream,
// overwriting whatever is at the path.
type PutOptions struct {
	// ContentType is what the object is stored as. Default: the file extension's type for an
	// *os.File, else application/octet-stream.
	ContentType string
	// ContentTypes refuses a ContentType outside the list, and bytes that prove a different type
	// than the one declared. image/*, video/* and audio/* are the only wildcards.
	ContentTypes []string
	// MaxSize refuses a larger body, while streaming too. Zero is no limit.
	MaxSize int64
	// Cache is the Cache-Control this object is stored with, overriding the bucket default.
	Cache string
	// Metadata is stored as x-amz-meta-*: lowercase keys (storage reads them back lowercased) and
	// printable ASCII values.
	Metadata map[string]string
	// Size declares the length of a reader whose length is not otherwise known. Without it, Put
	// buffers such a reader (up to MaxSize) to learn its length. Ignored for *bytes.Reader,
	// *strings.Reader, *bytes.Buffer, regular files and other io.Seekers, which are measured.
	Size int64
	// NoOverwrite refuses the write with CodeAlreadyExists when something is at the path, checked
	// by storage (If-None-Match: *) rather than by a racy read first.
	NoOverwrite bool
	// IfUnchanged is an etag: the write fails with CodeConflict if the object changed (If-Match).
	IfUnchanged string
	// Multipart says when the body goes up in parts. NoOverwrite and IfUnchanged are single-PUT only.
	Multipart Multipart
}

// Put stores body at path. A *bytes.Reader, *strings.Reader, *bytes.Buffer, regular *os.File or
// other io.ReaderAt that is an io.Seeker is measured and retried on a failed request; any other
// reader needs PutOptions.Size or MaxSize, and goes up once. A failed multipart upload is reported
// once the read of a stream in progress returns, since an io.Reader cannot be interrupted.
func (b *Bucket) Put(ctx context.Context, path string, body io.Reader, opts *PutOptions) (*CompletedBlob, error) {
	if opts == nil {
		opts = &PutOptions{}
	}
	if _, err := encodeKey(path); err != nil {
		return nil, err
	}
	var allowed []string
	if opts.ContentTypes != nil {
		var err error
		if allowed, err = expandContentTypes(opts.ContentTypes); err != nil {
			return nil, err
		}
	}
	if opts.MaxSize < 0 || opts.Size < 0 {
		return nil, newErr(CodeInvalidInput, "MaxSize and Size cannot be negative")
	}
	if _, err := cacheControl(opts.Cache, "public"); err != nil {
		return nil, err
	}
	if _, err := metaHeaders(opts.Metadata); err != nil {
		return nil, err
	}
	conditional := opts.NoOverwrite || opts.IfUnchanged != ""
	if opts.Multipart.mode == multipartAlways && conditional {
		return nil, newErr(CodeInvalidInput, "multipart: NoOverwrite and IfUnchanged are single-PUT only")
	}

	body0, err := resolveBody(body)
	if err != nil {
		return nil, err
	}
	contentType := opts.ContentType
	if contentType == "" {
		contentType = body0.contentType
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if !headerValueOK(contentType) {
		return nil, newErr(CodeInvalidInput, "contentType has characters a header cannot carry")
	}

	size := body0.size
	if size < 0 && opts.Size > 0 {
		size = opts.Size
	}
	maxSize := opts.MaxSize
	if maxSize > 0 && size > maxSize {
		return nil, newErr(CodeTooLarge, "the body is "+overLimit(size, maxSize))
	}
	if size < 0 {
		if maxSize == 0 {
			return nil, NewError(CodeLengthRequired, ErrorOptions{})
		}
		data, err := readAll(body0.r, maxSize)
		if err != nil {
			return nil, err
		}
		body0 = bytesBody(data)
		size = body0.size
	}

	if allowed != nil {
		head, peeked, err := peek(body0)
		if err != nil {
			return nil, err
		}
		if err := checkContentType(contentType, head, allowed); err != nil {
			return nil, err
		}
		body0 = peeked
	}

	// Resolved before the header is written: visibility decides public vs private on it.
	if _, err := b.r2.credentials(ctx); err != nil {
		return nil, err
	}
	objectHeaders, err := b.objectHeaders(contentType, opts.Cache, opts.Metadata)
	if err != nil {
		return nil, err
	}

	// Asked before the conditional check, not after: a body over the single-PUT cap is a refusal
	// worth naming whatever else is set. A zero-byte multipart upload is not a thing.
	if size > 0 {
		wants, err := wantsMultipart(opts.Multipart, size, "multipart")
		if err != nil {
			return nil, err
		}
		if wants && !conditional {
			return b.putMultipart(ctx, path, body0.open(), size, maxSize, objectHeaders, contentType)
		}
	}

	headers := objectHeaders
	headers["content-length"] = strconv.FormatInt(size, 10)
	if opts.NoOverwrite {
		headers["if-none-match"] = "*"
	}
	if opts.IfUnchanged != "" {
		headers["if-match"] = opts.IfUnchanged
	}
	q := r2Request{method: "PUT", path: path, headers: headers}
	if size == 0 {
		q.body = []byte{}
	} else {
		q.length = size
		if body0.replayable() {
			q.open = func() io.Reader { return &sizedReader{r: body0.open(), size: size, maxSize: maxSize} }
		} else {
			q.stream = &sizedReader{r: body0.r, size: size, maxSize: maxSize}
		}
	}
	res, err := b.r2.fetch(ctx, q)
	if err != nil {
		if be, ok := asBlobError(err); ok {
			return nil, be
		}
		return nil, err
	}
	if res.StatusCode == 412 {
		drain(res)
		if opts.NoOverwrite {
			head, err := b.r2.head(ctx, path)
			if err != nil {
				return nil, err
			}
			e := NewError(CodeAlreadyExists, ErrorOptions{Message: path + " already exists"})
			if head != nil {
				e.ETag = head.etag
				size := head.size
				e.Size = &size
			}
			return nil, e
		}
		return nil, NewError(CodeConflict, ErrorOptions{})
	}
	if !ok(res) {
		return nil, errorFromResponse(res)
	}
	drain(res)
	return &CompletedBlob{BlobObject: b.r2.blobObject(path, size, res.Header.Get("ETag"), time.Now()), ContentType: contentType}, nil
}

func (b *Bucket) objectHeaders(contentType, cache string, metadata map[string]string) (map[string]string, error) {
	if cache == "" {
		cache = b.r2.defaultCache
	}
	cc, err := cacheControl(cache, b.r2.visibility())
	if err != nil {
		return nil, err
	}
	meta, err := metaHeaders(metadata)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"content-type": contentType, "cache-control": cc}
	for k, v := range meta {
		headers[k] = v
	}
	return headers, nil
}

// putMultipart sends up to four parts at once, each buffered whole so it can be retried. Reading
// waits for a free slot, so the body is never read further ahead than the parts being sent and the
// one filling. A failure cancels the parts in flight, waits for them, then aborts the upload rather
// than leaving parts behind that nothing can see.
func (b *Bucket) putMultipart(ctx context.Context, path string, body io.Reader, size, maxSize int64, headers map[string]string, contentType string) (*CompletedBlob, error) {
	partSize := partSizeFor(size)
	expected := partCount(size, partSize)
	concurrency := partConcurrencyFor(partSize)

	uploadID, err := b.r2.createMultipart(ctx, path, headers)
	if err != nil {
		return nil, err
	}

	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu      sync.Mutex
		failure error
		wg      sync.WaitGroup
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if failure == nil {
			failure = err
			cancel()
		}
	}
	failed := func() error {
		mu.Lock()
		defer mu.Unlock()
		return failure
	}
	slots := make(chan struct{}, concurrency)
	etags := make([]string, expected)

	sendPart := func(n int, chunk []byte) error {
		res, err := b.r2.fetch(pctx, r2Request{
			method:  "PUT",
			path:    path,
			query:   map[string]string{"partNumber": strconv.Itoa(n), "uploadId": uploadID},
			headers: map[string]string{"content-length": strconv.Itoa(len(chunk))},
			body:    chunk,
		})
		if err != nil {
			return err
		}
		if !ok(res) {
			return errorFromResponse(res)
		}
		drain(res)
		etag := res.Header.Get("ETag")
		if etag == "" {
			return NewError(CodeRequestFailed, ErrorOptions{Message: fmt.Sprintf("part %d landed without an etag", n), Status: 502})
		}
		etags[n-1] = etag
		return nil
	}

	run := func() error {
		var sent int64
		for n := 1; n <= expected; n++ {
			if err := failed(); err != nil {
				return err
			}
			length := min(partSize, size-sent)
			chunk := make([]byte, length)
			got, err := io.ReadFull(body, chunk)
			sent += int64(got)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return newErr(CodeInvalidInput, fmt.Sprintf("body was %d bytes, %d were declared", sent, size))
				}
				return err
			}
			select {
			case slots <- struct{}{}:
			case <-pctx.Done():
				if err := failed(); err != nil {
					return err
				}
				return ctx.Err()
			}
			wg.Add(1)
			go func(n int, chunk []byte) {
				defer wg.Done()
				defer func() { <-slots }()
				if err := sendPart(n, chunk); err != nil {
					fail(err)
				}
			}(n, chunk)
		}
		var one [1]byte
		if m, _ := io.ReadFull(body, one[:]); m > 0 {
			if maxSize > 0 && size >= maxSize {
				return newErr(CodeTooLarge, fmt.Sprintf("body exceeds maxSize (%d bytes)", maxSize))
			}
			return newErr(CodeInvalidInput, fmt.Sprintf("body is longer than the declared %d bytes", size))
		}
		wg.Wait()
		if err := failed(); err != nil {
			return err
		}
		return nil
	}

	if err := run(); err != nil {
		// A part still in flight would land after the abort and be billed with nothing to list it.
		fail(err)
		wg.Wait()
		// Nothing lists an incomplete upload, so a failure that left one behind is invisible billing.
		actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_ = b.r2.abortMultipart(actx, path, uploadID)
		acancel()
		err = failed()
		if be, ok := asBlobError(err); ok {
			return nil, be
		}
		return nil, err
	}

	parts := make([]landedPart, expected)
	for i, etag := range etags {
		parts[i] = landedPart{N: i + 1, ETag: etag}
	}
	etag, err := b.r2.completeMultipart(ctx, path, uploadID, parts)
	if err != nil {
		actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_ = b.r2.abortMultipart(actx, path, uploadID)
		acancel()
		return nil, err
	}
	return &CompletedBlob{BlobObject: b.r2.blobObject(path, size, etag, time.Now()), ContentType: contentType}, nil
}

/* ----------------------------------------------------------------- read */

// Get reads a blob and its bytes. Close the returned Body.
func (b *Bucket) Get(ctx context.Context, path string) (*BlobDownload, error) {
	res, err := b.r2.fetch(ctx, r2Request{method: "GET", path: path})
	if err != nil {
		return nil, err
	}
	if !ok(res) {
		return nil, errorFromResponse(res)
	}
	head, err := headFromHeaders(res)
	if err != nil {
		drain(res)
		return nil, err
	}
	return &BlobDownload{
		BlobInfo: BlobInfo{BlobObject: b.r2.blobObject(path, head.size, head.etag, head.uploadedAt), ContentType: head.contentType, Metadata: head.metadata},
		Body:     res.Body,
	}, nil
}

// Info is a blob's record without its bytes. A missing blob is CodeNotFound.
func (b *Bucket) Info(ctx context.Context, path string) (*BlobInfo, error) {
	head, err := b.r2.head(ctx, path)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, newErr(CodeNotFound, path+" not found")
	}
	return &BlobInfo{BlobObject: b.r2.blobObject(path, head.size, head.etag, head.uploadedAt), ContentType: head.contentType, Metadata: head.metadata}, nil
}

// Exists reports whether something is stored at path.
func (b *Bucket) Exists(ctx context.Context, path string) (bool, error) {
	head, err := b.r2.head(ctx, path)
	return head != nil, err
}

// ListOptions are the options of List.
type ListOptions struct {
	Prefix string
	// Limit is the most blobs a page holds, 1 to 1000. Zero is 1000.
	Limit int
	// Cursor is the previous page's Cursor.
	Cursor string
}

// ListPage is one page of a listing. Cursor is set only while more remains.
type ListPage struct {
	Blobs  []BlobObject
	Cursor string
}

// List returns one page of the blobs under a prefix, in key order, without metadata.
func (b *Bucket) List(ctx context.Context, opts *ListOptions) (*ListPage, error) {
	if opts == nil {
		opts = &ListOptions{}
	}
	query := map[string]string{"list-type": "2"}
	if opts.Prefix != "" {
		query["prefix"] = opts.Prefix
	}
	if opts.Limit != 0 {
		query["max-keys"] = strconv.Itoa(min(max(opts.Limit, 1), 1000))
	}
	if opts.Cursor != "" {
		query["continuation-token"] = opts.Cursor
	}
	res, err := b.r2.fetch(ctx, r2Request{method: "GET", query: query})
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
		Contents []struct {
			Key          *string `xml:"Key"`
			Size         int64   `xml:"Size"`
			ETag         string  `xml:"ETag"`
			LastModified string  `xml:"LastModified"`
		} `xml:"Contents"`
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
	}
	if err := xml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "storage answered the listing with an unreadable document", Status: 502, Cause: err})
	}
	page := &ListPage{Blobs: make([]BlobObject, 0, len(doc.Contents))}
	for _, c := range doc.Contents {
		if c.Key == nil {
			continue
		}
		modified, _ := time.Parse(time.RFC3339Nano, c.LastModified)
		page.Blobs = append(page.Blobs, b.r2.blobObject(*c.Key, c.Size, c.ETag, modified))
	}
	if doc.IsTruncated && doc.NextContinuationToken != "" {
		page.Cursor = doc.NextContinuationToken
	}
	return page, nil
}

// SignedReadURLOptions are the options of SignedReadURL.
type SignedReadURLOptions struct {
	// ExpiresIn is how long the link should live, at most 10 minutes; a longer ask gets 10.
	// Zero is 5 minutes. SignedURL.ExpiresAt says when the link actually expires.
	ExpiresIn time.Duration
	// DownloadAs saves the response as this filename instead of displaying it inline.
	DownloadAs string
	// ContentType is what storage answers with as Content-Type, overriding the stored type.
	ContentType string
}

// SignedURL is a link and when it stops working, so a caller can cache it until then.
type SignedURL struct {
	URL       string
	ExpiresAt time.Time
}

const defaultReadSeconds = 300

// SignedReadURL is a link anyone can GET one object with until it expires: how a private bucket's
// objects are shared.
func (b *Bucket) SignedReadURL(ctx context.Context, path string, opts *SignedReadURLOptions) (*SignedURL, error) {
	if opts == nil {
		opts = &SignedReadURLOptions{}
	}
	expiresIn := defaultReadSeconds
	if opts.ExpiresIn < 0 {
		return nil, newErr(CodeInvalidInput, "ExpiresIn cannot be negative")
	}
	if opts.ExpiresIn != 0 {
		expiresIn = durationSeconds(opts.ExpiresIn)
	}
	query := map[string]string{}
	if opts.DownloadAs != "" {
		query["response-content-disposition"] = attachmentDisposition(opts.DownloadAs)
	}
	if opts.ContentType != "" {
		ct, err := safeContentType(opts.ContentType)
		if err != nil {
			return nil, err
		}
		query["response-content-type"] = ct
	}
	p, err := b.r2.presign(ctx, presignInit{method: "GET", path: path, query: query, expiresIn: expiresIn})
	if err != nil {
		return nil, err
	}
	return &SignedURL{URL: p.url, ExpiresAt: p.expiresAt}, nil
}

func durationSeconds(d time.Duration) int {
	s := d / time.Second
	if s > maxPresignSeconds {
		return maxPresignSeconds
	}
	return int(s)
}

// SignedUploadURLOptions are the options of SignedUploadURL.
type SignedUploadURLOptions struct {
	// ExpiresIn is how long the link should live, at most 10 minutes. Zero is 10 minutes.
	ExpiresIn time.Duration
	// ContentType is the Content-Type the upload must send, and what the object is stored as.
	// Default application/octet-stream.
	ContentType string
	// Cache is the Cache-Control the object is stored with.
	Cache string
	// Metadata: lowercase keys and printable ASCII values.
	Metadata map[string]string
	// Size pins the body's exact length, so a url handed out for one file cannot upload another size.
	// Zero leaves it open.
	Size int64
	// NoOverwrite refuses the upload if something is already at the path.
	NoOverwrite bool
}

// SignedUploadURL is a url plus the headers to send with it.
type SignedUploadURL struct {
	URL string
	// Headers are sent verbatim with the PUT. They are part of the signature, so anything the
	// caller changes, drops or adds to them is a 403. With net/http, content-length is not a
	// header: set Request.ContentLength to the size instead, which a *bytes.Reader body does by
	// itself and an *os.File body does not.
	Headers   map[string]string
	ExpiresAt time.Time
}

// SignedUploadURL is a url someone else can PUT one object to: the counterpart of SignedReadURL,
// for a CLI or a server-to-server job. A browser upload wants NewUploadHandler instead, which
// also handles multipart and the completion callback this cannot.
func (b *Bucket) SignedUploadURL(ctx context.Context, path string, opts *SignedUploadURLOptions) (*SignedUploadURL, error) {
	if opts == nil {
		opts = &SignedUploadURLOptions{}
	}
	if err := presignableKey(path); err != nil {
		return nil, err
	}
	expiresIn := maxPresignSeconds
	if opts.ExpiresIn < 0 {
		return nil, newErr(CodeInvalidInput, "ExpiresIn cannot be negative")
	}
	if opts.ExpiresIn != 0 {
		expiresIn = durationSeconds(opts.ExpiresIn)
	}
	ct := opts.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, err := safeContentType(ct)
	if err != nil {
		return nil, err
	}
	if opts.Size < 0 {
		return nil, newErr(CodeInvalidInput, "Size cannot be negative")
	}
	if _, err := b.r2.credentials(ctx); err != nil {
		return nil, err
	}
	headers, err := b.objectHeaders(ct, opts.Cache, opts.Metadata)
	if err != nil {
		return nil, err
	}
	if opts.Size > 0 {
		headers["content-length"] = strconv.FormatInt(opts.Size, 10)
	}
	if opts.NoOverwrite {
		headers["if-none-match"] = "*"
	}
	p, err := b.r2.presign(ctx, presignInit{method: "PUT", path: path, headers: headers, expiresIn: expiresIn})
	if err != nil {
		return nil, err
	}
	return &SignedUploadURL{URL: p.url, Headers: headers, ExpiresAt: p.expiresAt}, nil
}

// attachmentDisposition carries the real name in filename* as an RFC 8187 ext-value, where
// percent-encoding leaves a parser nothing to read as syntax; the filename fallback is cut back to
// characters that cannot end the quoted string. The name reaches storage as a query parameter and
// comes back as a header, so a quote, a semicolon or a CRLF must not add a parameter or a header.
var dispositionUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.\- ]+`)

func attachmentDisposition(name string) string {
	ascii := dispositionUnsafe.ReplaceAllString(name, "_")
	if ascii == "" {
		ascii = "download"
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + uriEncode(name, false)
}

var mediaTypeRE = regexp.MustCompile(`^[\w.+-]+/[\w.+-]+(?:\s*;\s*[\w.+-]+=(?:[\w.+-]+|"[^";\\\x00-\x1f\x7f]*"))*$`)

// safeContentType refuses anything but a media type: it becomes the Content-Type storage answers with.
func safeContentType(t string) (string, error) {
	if !mediaTypeRE.MatchString(t) {
		return "", newErr(CodeInvalidInput, fmt.Sprintf("contentType: %q is not a media type", t))
	}
	return t, nil
}

/* ---------------------------------------------------------------- write */

// Delete removes the blob at path. A missing blob is success.
func (b *Bucket) Delete(ctx context.Context, path string) error {
	res, err := b.r2.fetch(ctx, r2Request{method: "DELETE", path: path})
	if err != nil {
		return err
	}
	if !ok(res) && res.StatusCode != 404 {
		return errorFromResponse(res)
	}
	drain(res)
	return nil
}

// DeleteMany removes every path, a thousand per request. Paths that survive are reported as
// CodePartialDelete with Failed set.
func (b *Bucket) DeleteMany(ctx context.Context, paths []string) error {
	var failed []string
	for i := 0; i < len(paths); i += 1000 {
		f, err := b.deleteBatch(ctx, paths[i:min(i+1000, len(paths))])
		if err != nil {
			return err
		}
		failed = append(failed, f...)
	}
	if len(failed) > 0 {
		return NewError(CodePartialDelete, ErrorOptions{Message: fmt.Sprintf("%d of %d paths were not deleted", len(failed), len(paths)), Failed: failed})
	}
	return nil
}

// DeletePrefix removes every blob whose path starts with prefix. An empty prefix is refused: that
// is DeleteAll.
func (b *Bucket) DeletePrefix(ctx context.Context, prefix string) error {
	if prefix == "" {
		return NewError(CodeInvalidInput, ErrorOptions{
			Message: `DeletePrefix("") would delete every object in the bucket`,
			Hint:    "call DeleteAll if that is what you mean",
		})
	}
	return b.deletePrefix(ctx, prefix)
}

// DeleteAll removes every blob in the bucket.
func (b *Bucket) DeleteAll(ctx context.Context) error {
	return b.deletePrefix(ctx, "")
}

func (b *Bucket) deletePrefix(ctx context.Context, prefix string) error {
	var failed []string
	cursor := ""
	for {
		page, err := b.List(ctx, &ListOptions{Prefix: prefix, Limit: 1000, Cursor: cursor})
		if err != nil {
			return err
		}
		if len(page.Blobs) > 0 {
			paths := make([]string, len(page.Blobs))
			for i, blob := range page.Blobs {
				paths[i] = blob.Path
			}
			f, err := b.deleteBatch(ctx, paths)
			if err != nil {
				return err
			}
			failed = append(failed, f...)
		}
		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}
	if len(failed) > 0 {
		where := "under " + prefix
		if prefix == "" {
			where = "in the bucket"
		}
		return NewError(CodePartialDelete, ErrorOptions{Message: fmt.Sprintf("%d paths %s were not deleted", len(failed), where), Failed: failed})
	}
	return nil
}

func (b *Bucket) deleteBatch(ctx context.Context, paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	var body strings.Builder
	body.WriteString("<Delete>")
	for _, p := range paths {
		if _, err := encodeKey(p); err != nil {
			return nil, err
		}
		body.WriteString("<Object><Key>" + escapeXML(p) + "</Key></Object>")
	}
	body.WriteString("</Delete>")
	res, err := b.r2.fetch(ctx, r2Request{method: "POST", query: map[string]string{"delete": ""}, headers: map[string]string{"content-type": "application/xml"}, body: []byte(body.String())})
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
		Errors []struct {
			Key *string `xml:"Key"`
		} `xml:"Error"`
	}
	_ = xml.Unmarshal([]byte(text), &doc)
	// S3 answers 200 with errors inside; a survivor is the truth, so ask again rather than trust the list.
	var survivors []string
	for _, e := range doc.Errors {
		if e.Key == nil {
			continue
		}
		exists, err := b.Exists(ctx, *e.Key)
		if err != nil {
			return nil, err
		}
		if exists {
			survivors = append(survivors, *e.Key)
		}
	}
	return survivors, nil
}

/* ------------------------------------------------------------ multipart */

// MultipartUpload is a multipart upload that was started and never completed or aborted.
type MultipartUpload struct {
	Path        string
	UploadID    string
	InitiatedAt time.Time
}

// ListMultipartUploads lists multipart uploads that were started and never completed or aborted
// under a prefix. They are billed storage that List cannot see, and a bucket cannot be deleted
// while one exists.
func (b *Bucket) ListMultipartUploads(ctx context.Context, prefix string) ([]MultipartUpload, error) {
	return b.r2.listMultipartUploads(ctx, prefix)
}

// AbortMultipartUpload throws away an incomplete upload and every part that landed for it. Missing
// is success, which is why it takes the record ListMultipartUploads returned rather than two
// strings: a swapped pair would abort nothing and report that it worked.
func (b *Bucket) AbortMultipartUpload(ctx context.Context, upload MultipartUpload) error {
	if upload.UploadID == "" {
		return newErr(CodeInvalidInput, "AbortMultipartUpload: UploadID is required")
	}
	if _, err := encodeKey(upload.Path); err != nil {
		return err
	}
	return b.r2.abortMultipart(ctx, upload.Path, upload.UploadID)
}

// AbortStaleMultipartUploads is list plus abort for a cron: an abandoned upload is not expired for
// you. It aborts the uploads under prefix started longer ago than olderThan and returns them.
func (b *Bucket) AbortStaleMultipartUploads(ctx context.Context, olderThan time.Duration, prefix string) ([]MultipartUpload, error) {
	if olderThan < 0 {
		return nil, newErr(CodeInvalidInput, "olderThan cannot be negative")
	}
	cutoff := time.Now().Add(-olderThan)
	uploads, err := b.ListMultipartUploads(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var stale []MultipartUpload
	for _, u := range uploads {
		if !u.InitiatedAt.After(cutoff) {
			if err := b.r2.abortMultipart(ctx, u.Path, u.UploadID); err != nil {
				return stale, err
			}
			stale = append(stale, u)
		}
	}
	return stale, nil
}

/* ---------------------------------------------------------- copy/move */

// CopyOptions are the options of Copy and Move. Unset, the destination carries the source's
// content type, cache-control and metadata. Storage rewrites the three together or not at all, so
// when any one is given the other two are read off the source first and sent back unchanged.
type CopyOptions struct {
	// ContentType is what the destination is stored as. Default: the source's.
	ContentType string
	// Cache is the Cache-Control the destination is stored with. Default: the source's.
	Cache string
	// Metadata replaces the source's outright rather than merging into it; lowercase keys. A nil map
	// keeps the source's; an empty non-nil map stores none.
	Metadata map[string]string
}

// Copy copies the blob at from to to.
func (b *Bucket) Copy(ctx context.Context, from, to string, opts *CopyOptions) (*BlobObject, error) {
	if opts == nil {
		opts = &CopyOptions{}
	}
	encFrom, err := encodeKey(from)
	if err != nil {
		return nil, err
	}
	creds, err := b.r2.credentials(ctx)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"x-amz-copy-source": "/" + creds.Bucket + "/" + encFrom}
	if opts.ContentType != "" || opts.Cache != "" || opts.Metadata != nil {
		// REPLACE rewrites content-type, cache-control and metadata as one, so the rest is read off
		// the source and sent back as it was.
		src, err := b.r2.head(ctx, from)
		if err != nil {
			return nil, err
		}
		if src == nil {
			return nil, newErr(CodeNotFound, from+" not found")
		}
		ct := opts.ContentType
		if ct == "" {
			ct = src.contentType
		}
		if !headerValueOK(ct) {
			return nil, newErr(CodeInvalidInput, "contentType has characters a header cannot carry")
		}
		var cc string
		switch {
		case opts.Cache != "":
			cc, err = cacheControl(opts.Cache, b.r2.visibility())
		case src.cacheControl != "":
			cc = src.cacheControl
		default:
			cc, err = cacheControl(b.r2.defaultCache, b.r2.visibility())
		}
		if err != nil {
			return nil, err
		}
		metadata := opts.Metadata
		if metadata == nil {
			metadata = src.metadata
		}
		meta, err := metaHeaders(metadata)
		if err != nil {
			return nil, err
		}
		headers["x-amz-metadata-directive"] = "REPLACE"
		headers["content-type"] = ct
		headers["cache-control"] = cc
		for k, v := range meta {
			headers[k] = v
		}
	}
	res, err := b.r2.fetch(ctx, r2Request{method: "PUT", path: to, headers: headers})
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
	if xmlTag(text, "Code") != "" {
		return nil, errorFromBody(500, text)
	}
	head, err := b.r2.head(ctx, to)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, newErr(CodeNotFound, to+" was not found after copy")
	}
	obj := b.r2.blobObject(to, head.size, head.etag, head.uploadedAt)
	return &obj, nil
}

// Move is a Copy followed by a Delete of the source: storage has no rename. A failed delete is
// CodeMoveLeftACopy.
func (b *Bucket) Move(ctx context.Context, from, to string, opts *CopyOptions) (*BlobObject, error) {
	obj, err := b.Copy(ctx, from, to, opts)
	if err != nil {
		return nil, err
	}
	if err := b.Delete(ctx, from); err != nil {
		return nil, NewError(CodeMoveLeftACopy, ErrorOptions{Message: fmt.Sprintf("moved %s to %s but could not delete the source", from, to), Cause: err})
	}
	return obj, nil
}

// UpdateJSONOptions are the options of UpdateJSON.
type UpdateJSONOptions struct {
	// Cache is the Cache-Control the rewritten object is stored with.
	Cache string
	// Metadata replaces the existing metadata; nil keeps it.
	Metadata map[string]string
	// MaxAttempts is how many times to read, transform and write before giving up with
	// CodeConflict. Zero is 6.
	MaxAttempts int
}

// UpdateJSON is a read-modify-write over a JSON document: If-Match on the etag that was read, or
// If-None-Match: * when nothing was there. fn gets nil when nothing, a zero-byte object, or JSON null is stored.
// A write that lost the race is re-read and re-run after a short jittered pause, up to MaxAttempts
// times; then it fails with CodeConflict. fn may run more than once.
func UpdateJSON[T any](ctx context.Context, b *Bucket, path string, fn func(prev *T) (T, error), opts *UpdateJSONOptions) (*BlobObject, error) {
	if opts == nil {
		opts = &UpdateJSONOptions{}
	}
	attempts := opts.MaxAttempts
	if attempts == 0 {
		attempts = 6
	}
	if attempts < 1 {
		return nil, newErr(CodeInvalidInput, "MaxAttempts must be a positive integer")
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		var prev *T
		etag := ""
		var metadata map[string]string
		got, err := b.Get(ctx, path)
		switch {
		case err == nil:
			data, rerr := io.ReadAll(got.Body)
			_ = got.Body.Close()
			if rerr != nil {
				return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "could not read " + path, Status: 502, Cause: rerr})
			}
			// An object that exists but is empty, or holds null, reads as nil: there is no document.
			if t := bytes.TrimSpace(data); len(t) > 0 && string(t) != "null" {
				var v T
				if err := json.Unmarshal(data, &v); err != nil {
					return nil, NewError(CodeInvalidInput, ErrorOptions{Message: path + " is not JSON", Cause: err})
				}
				prev = &v
			}
			etag = got.ETag
			metadata = got.Metadata
		case HasCode(err, CodeNotFound):
		default:
			return nil, err
		}
		next, err := fn(prev)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(next)
		if err != nil {
			return nil, err
		}
		if opts.Metadata != nil {
			metadata = opts.Metadata
		}
		put := &PutOptions{ContentType: "application/json", Cache: opts.Cache, Metadata: metadata}
		if etag == "" {
			put.NoOverwrite = true
		} else {
			put.IfUnchanged = etag
		}
		written, err := b.Put(ctx, path, strings.NewReader(string(data)), put)
		if err == nil {
			return &written.BlobObject, nil
		}
		if !HasCode(err, CodeConflict) && !HasCode(err, CodeAlreadyExists) {
			return nil, err
		}
		lastErr = err
		if attempt < attempts {
			if err := sleep(ctx, backoff(attempt, "", 25*time.Millisecond)); err != nil {
				return nil, err
			}
		}
	}
	plural := "s"
	if attempts == 1 {
		plural = ""
	}
	return nil, NewError(CodeConflict, ErrorOptions{Message: fmt.Sprintf("%s kept changing across %d attempt%s", path, attempts, plural), Cause: lastErr})
}

/* ----------------------------------------------------------- escape hatch */

// S3Credentials are what an S3 client needs to reach the bucket directly. They are temporary:
// call S3 again after Expires.
type S3Credentials struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
}

// S3 returns credentials for an S3 client, for what the SDK does not cover.
func (b *Bucket) S3(ctx context.Context) (*S3Credentials, error) {
	c, err := b.r2.credentials(ctx)
	if err != nil {
		return nil, err
	}
	return &S3Credentials{
		Endpoint:        c.Endpoint,
		Region:          "auto",
		Bucket:          c.Bucket,
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Expires:         c.expiry(),
	}, nil
}
