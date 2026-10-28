package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// UploadProtocol is the version of the upload route protocol this handler speaks with
// @upstash/blob's browser client and React hooks: the same number blob-js's uploadHandler and
// blob-py's UploadHandler speak. It is not the package version. Every upload route JSON body
// carries it as a top-level "protocol" key: the client on every POST, the server on the GET
// constraints document and every 2xx answer. Missing is 1, every change is additive, and nothing
// is refused over the number.
//
// 1: phases begin, parts, end and cancel; the GET constraints document.
const UploadProtocol = 1

// NoLimit on a route's MaxSize clears the handler's MaxSize for that route.
const NoLimit int64 = -1

const (
	// Written onto every single-PUT object, signed into the url so only this SDK can set it, and
	// read back to answer the question a multipart upload answers by construction: are the bytes at
	// this path the ones THIS upload put there? A presigned PUT is written by the browser, so the
	// object at the path may be anybody's: a stale token's, a concurrent upload's, or one that was
	// there all along.
	uploadMarker       = "upstash-upload"
	uploadMarkerHeader = "x-amz-meta-" + uploadMarker

	partsPerBatch  = 16
	tokenTTL       = 7 * 24 * time.Hour
	limitsMaxAge   = 60
	maxRequestBody = 1 << 20
)

// UploadFile is what a route is told about a file before a byte of it is sent: what the browser
// claimed.
type UploadFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// BeforeUploadArgs are what OnBeforeUpload is called with.
type BeforeUploadArgs[C any] struct {
	// Ctx is what the handler's Context returned for this request.
	Ctx C
	// Route is the route this file was sent to; "" when the handler mounts no named routes.
	Route   string
	Request *http.Request
	File    UploadFile
	// Input is what the route's Input returned for the browser's input, or nil.
	Input any
}

// BeforeUploadResult is what OnBeforeUpload decides about one file.
type BeforeUploadResult struct {
	// Path is where the object is stored. Required.
	Path string
	// Cache is the Cache-Control this object is stored with, overriding the bucket default.
	Cache string
	// Metadata: lowercase keys and printable ASCII values.
	Metadata map[string]string
	// ContentTypes and MaxSize may narrow the route's constraints for this upload, never widen them.
	ContentTypes []string
	MaxSize      int64
	// State is carried to OnUploadComplete and OnError as JSON, inside a signed but readable token:
	// an id, never a secret.
	State any
}

// UploadCompleteArgs are what OnUploadComplete is called with: the stored object, flat, plus what
// the route knows about it.
type UploadCompleteArgs[C any] struct {
	CompletedBlob
	Ctx     C
	Route   string
	Request *http.Request
	// File is what the browser declared before a byte was sent: the name only survives here.
	File UploadFile
	// UploadID identifies this upload and is stable across retried completions: an idempotency key.
	UploadID string
	// MultipartUploadID is R2's own multipart id; "" when the file went up as a single PUT.
	MultipartUploadID string
	Metadata          map[string]string
	// State is what OnBeforeUpload returned as State, as JSON; nil when it returned none.
	State json.RawMessage
}

// UploadErrorArgs are what OnError is handed: the error and as much as the request had reached.
type UploadErrorArgs[C any] struct {
	// Ctx is the zero value when Context had not returned.
	Ctx      C
	Route    string
	Request  *http.Request
	Err      error
	File     *UploadFile
	Path     string
	Metadata map[string]string
	State    json.RawMessage
}

// UploadRoute is one named route. Every field left zero inherits the handler's.
type UploadRoute[C any] struct {
	Bucket *Bucket
	// ContentTypes replaces the handler's; a non-nil empty slice clears it.
	ContentTypes []string
	// MaxSize replaces the handler's; NoLimit clears it.
	MaxSize   int64
	Multipart Multipart
	// Input validates what the browser sends as input. Nil inherits the handler's.
	Input            func(raw json.RawMessage) (any, error)
	OnBeforeUpload   func(a BeforeUploadArgs[C]) (BeforeUploadResult, error)
	OnUploadComplete func(a UploadCompleteArgs[C]) (any, error)
	OnError          func(a UploadErrorArgs[C]) error
}

// UploadHandlerOptions configure NewUploadHandler. Bucket, ContentTypes, MaxSize, Multipart,
// Input, OnBeforeUpload, OnUploadComplete and OnError are defaults a route replaces key by key.
type UploadHandlerOptions[C any] struct {
	// Bucket every route inherits. Nil reads UPSTASH_BLOB_TOKEN, once.
	Bucket *Bucket
	// ContentTypes the routes accept: concrete types, or image/*, video/*, audio/*.
	ContentTypes []string
	// MaxSize in bytes. Zero is no limit.
	MaxSize int64
	// Multipart is where a file stops going up as one PUT and starts going up in parts: 16 MB by
	// default. Parts buy pause, resume and per-chunk retry, and are the only way past R2's 5 GiB
	// single-PUT cap. It also decides when the object exists: a multipart file is created at phase
	// 'end'; a single PUT is stored the moment its last byte lands, and deleted again if
	// OnUploadComplete refuses it.
	Multipart Multipart
	// Endpoint is where the handler is mounted. Only used to separate two handlers on one bucket,
	// whose route names would otherwise derive the same completion-token id.
	Endpoint string
	// Context runs on every POST before the route does: the place for the session check. Its result
	// is Ctx in every callback. Return an *Error with CodeUnauthorized (or any error with a
	// StatusCode() int method) to refuse. Not run for GET, which serves a public constraints document.
	Context func(r *http.Request) (C, error)
	// Input validates the browser's input; its result is BeforeUploadArgs.Input. With none, a route
	// refuses input rather than dropping it. See JSONInput.
	Input func(raw json.RawMessage) (any, error)
	// OnBeforeUpload runs once per upload, before anything is signed, and returns the path. Return
	// an error to refuse.
	OnBeforeUpload func(a BeforeUploadArgs[C]) (BeforeUploadResult, error)
	// OnUploadComplete runs after the route verified its signed completion token and that the stored
	// object has the declared size; the browser sees done only after it returns, and what it returns
	// is upload.blob.data there. Return an error to refuse: the object is deleted, unless it can no
	// longer be identified as this upload's, in which case it is kept and logged. It may run more
	// than once, or never if the browser stops before 'end', so write idempotently on UploadID.
	OnUploadComplete func(a UploadCompleteArgs[C]) (any, error)
	// OnError sees every refusal, the handler's own included. Return an *Error to answer with it, or
	// nil to leave the answer alone. The one place to log.
	OnError func(a UploadErrorArgs[C]) error
	// Routes mounts several routes at one endpoint, picked by ?route=<name>. Nil makes the handler
	// the route, reached with no name.
	Routes map[string]UploadRoute[C]
	// Logger receives warnings the request cannot carry: an object a refusal could not delete, a
	// CORS preflight storage refused, an error the handler answered as a 500. Nil is slog.Default().
	Logger *slog.Logger
}

// JSONInput decodes the browser's input into T. Use it as Input, and read BeforeUploadArgs.Input
// as a T. A missing input is refused.
func JSONInput[T any]() func(json.RawMessage) (any, error) {
	return func(raw json.RawMessage) (any, error) {
		if raw == nil {
			return nil, errors.New("input is required")
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

// UploadHandler serves the upload route protocol of @upstash/blob/browser and @upstash/blob/react,
// so a browser uploads straight to storage through a Go backend, with multipart, resume, progress
// and a completion callback. Mount it with http.Handle("/api/upload", h). GET serves the route's
// constraints; POST runs the upload phases.
type UploadHandler[C any] struct {
	opts   UploadHandlerOptions[C]
	named  bool
	table  map[string]*mountedRoute[C]
	sole   *mountedRoute[C]
	logger *slog.Logger
}

// Route names live in a url query, so they are limited to what reads back as one word.
var routeName = regexp.MustCompile(`^[A-Za-z_][\w-]*$`)

// NewUploadHandler builds the server half of a direct browser upload. Check the session in Context,
// return the path from OnBeforeUpload, and record the file in OnUploadComplete, keyed by path. Signing, multipart, retries, cancel and completion checks are the
// SDK's.
func NewUploadHandler[C any](opts UploadHandlerOptions[C]) (*UploadHandler[C], error) {
	if opts.MaxSize < 0 {
		return nil, errors.New("blob: NewUploadHandler: MaxSize cannot be negative")
	}
	named := opts.Routes != nil
	routes := opts.Routes
	if !named {
		routes = map[string]UploadRoute[C]{"": {}}
	}
	if named && len(routes) == 0 {
		return nil, errors.New("blob: NewUploadHandler was given an empty Routes map: name at least one route, or leave Routes nil to make the handler the route")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	h := &UploadHandler[C]{opts: opts, named: named, table: map[string]*mountedRoute[C]{}, logger: logger}

	// Built at most once for the whole handler, and only when nothing named a bucket: two routes
	// falling back to the environment are the same bucket.
	var envBucket *Bucket
	fallback := func(name string) (*Bucket, error) {
		if envBucket != nil {
			return envBucket, nil
		}
		where := "NewUploadHandler has no Bucket"
		if named {
			where = fmt.Sprintf("upload route %q has no Bucket", name)
		}
		if os.Getenv(TokenEnv) == "" {
			return nil, fmt.Errorf("blob: %s and %s is not set: set it, or pass Bucket", where, TokenEnv)
		}
		b, err := NewBucketFromEnv()
		if err != nil {
			return nil, fmt.Errorf("blob: %s, and %s did not work: %w", where, TokenEnv, err)
		}
		envBucket = b
		return b, nil
	}

	for name, route := range routes {
		if named && !routeName.MatchString(name) {
			return nil, fmt.Errorf("blob: upload route names must match %s: %q does not", routeName, name)
		}
		m, err := h.mount(name, route, fallback)
		if err != nil {
			return nil, err
		}
		h.table[name] = m
	}
	if !named {
		h.sole = h.table[""]
	}
	return h, nil
}

type resolvedConstraints struct {
	contentTypes []string
	maxSize      int64 // 0 is no limit
}

func resolveConstraints(contentTypes []string, maxSize int64) (resolvedConstraints, error) {
	var rc resolvedConstraints
	if contentTypes != nil {
		expanded, err := expandContentTypes(contentTypes)
		if err != nil {
			return rc, err
		}
		rc.contentTypes = expanded
	}
	if maxSize > 0 {
		rc.maxSize = maxSize
	}
	return rc, nil
}

type mountedRoute[C any] struct {
	h               *UploadHandler[C]
	name            string
	id              string
	r2              *r2
	constraints     resolvedConstraints
	multipart       Multipart
	input           func(json.RawMessage) (any, error)
	before          func(BeforeUploadArgs[C]) (BeforeUploadResult, error)
	complete        func(UploadCompleteArgs[C]) (any, error)
	onError         func(UploadErrorArgs[C]) error
	constraintsBody []byte
	constraintsETag string
	probe           *corsProbe
}

func (h *UploadHandler[C]) mount(name string, route UploadRoute[C], fallback func(string) (*Bucket, error)) (*mountedRoute[C], error) {
	label := "NewUploadHandler"
	if h.named {
		label = fmt.Sprintf("upload route %q", name)
	}
	bucket := route.Bucket
	if bucket == nil {
		bucket = h.opts.Bucket
	}
	if bucket == nil {
		var err error
		if bucket, err = fallback(name); err != nil {
			return nil, err
		}
	}
	before := route.OnBeforeUpload
	if before == nil {
		before = h.opts.OnBeforeUpload
	}
	if before == nil {
		if h.named {
			return nil, fmt.Errorf("blob: %s has no OnBeforeUpload: write one on the route or on the handler", label)
		}
		return nil, errors.New("blob: NewUploadHandler needs an OnBeforeUpload")
	}
	complete := route.OnUploadComplete
	if complete == nil {
		complete = h.opts.OnUploadComplete
	}
	onError := route.OnError
	if onError == nil {
		onError = h.opts.OnError
	}
	input := route.Input
	if input == nil {
		input = h.opts.Input
	}
	// A route's constraints replace the handler's per key; an empty slice or NoLimit clears one.
	contentTypes := h.opts.ContentTypes
	if route.ContentTypes != nil {
		contentTypes = route.ContentTypes
		if len(contentTypes) == 0 {
			contentTypes = nil
		}
	}
	maxSize := h.opts.MaxSize
	switch {
	case route.MaxSize > 0:
		maxSize = route.MaxSize
	case route.MaxSize == NoLimit:
		maxSize = 0
	case route.MaxSize < 0:
		return nil, fmt.Errorf("blob: %s: MaxSize %d is negative; NoLimit clears the handler's", label, route.MaxSize)
	}
	// Resolved here, not per request: a bad option is a build error, not a 500 raised after
	// OnBeforeUpload has already written the app's row.
	constraints, err := resolveConstraints(contentTypes, maxSize)
	if err != nil {
		return nil, fmt.Errorf("blob: %s: %w", label, err)
	}
	multipart := route.Multipart
	if multipart == (Multipart{}) {
		multipart = h.opts.Multipart
	}
	routeKey := name
	if h.opts.Endpoint != "" {
		routeKey = h.opts.Endpoint + "?route=" + name
	}
	m := &mountedRoute[C]{
		h:           h,
		name:        name,
		id:          deriveRouteID(constraints, input != nil, routeKey),
		r2:          bucket.r2,
		constraints: constraints,
		multipart:   multipart,
		input:       input,
		before:      before,
		complete:    complete,
		onError:     onError,
		probe:       newCorsProbe(bucket.r2.client, h.logger),
	}
	m.constraintsBody, m.constraintsETag = constraintsDocument(constraints)
	return m, nil
}

// ServeHTTP answers GET with the route's constraints and POST with an upload phase.
func (h *UploadHandler[C]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("route")
	var m *mountedRoute[C]
	if h.sole != nil {
		// A name on the query is a client bound to a different handler, and serving it here would
		// upload through a route it never asked for.
		if name == "" {
			m = h.sole
		}
	} else if name != "" {
		m = h.table[name]
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, 405, NewError(CodeInvalidInput, ErrorOptions{Message: "method not allowed", Status: 405}))
		return
	}
	if m == nil {
		// Never the names it does mount, and never a 500: an unknown route is a 404.
		err := newErr(CodeNotFound, "unknown upload route")
		var mapper func(error, *errorDetails) error
		if h.opts.OnError != nil {
			mapper = func(e error, _ *errorDetails) error {
				return h.opts.OnError(UploadErrorArgs[C]{Route: name, Request: r, Err: e})
			}
		}
		h.answerError(w, r, err, mapper, &errorDetails{})
		return
	}
	if r.Method == http.MethodGet {
		m.serveConstraints(w, r)
		return
	}
	var ctx C
	details := &errorDetails{}
	if h.opts.Context != nil {
		c, err := h.opts.Context(r)
		if err != nil {
			h.answerError(w, r, err, m.errorMapper(r, ctx), details)
			return
		}
		ctx = c
	}
	m.post(w, r, ctx, details)
}

func (m *mountedRoute[C]) errorMapper(r *http.Request, ctx C) func(error, *errorDetails) error {
	if m.onError == nil {
		return nil
	}
	return func(e error, d *errorDetails) error {
		return m.onError(UploadErrorArgs[C]{Ctx: ctx, Route: m.name, Request: r, Err: e, File: d.file, Path: d.path, Metadata: d.metadata, State: d.state})
	}
}

// errorDetails is what the handler knows when something failed, as much as the request had reached.
type errorDetails struct {
	file     *UploadFile
	path     string
	metadata map[string]string
	state    json.RawMessage
}

func constraintsDocument(c resolvedConstraints) ([]byte, string) {
	type served struct {
		ContentTypes []string `json:"contentTypes,omitempty"`
		MaxSize      int64    `json:"maxSize,omitempty"`
	}
	body, _ := marshalNoEscape(struct {
		Protocol    int    `json:"protocol"`
		Constraints served `json:"constraints"`
	}{UploadProtocol, served{c.contentTypes, c.maxSize}})
	return body, `"` + fnv36(string(body)) + `"`
}

// serveConstraints is GET on an upload route: what it accepts, so a file picker is filled from the
// same list that does the refusing. Short and revalidated: the constraints change with a deploy.
func (m *mountedRoute[C]) serveConstraints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(limitsMaxAge))
	w.Header().Set("ETag", m.constraintsETag)
	if r.Header.Get("If-None-Match") == m.constraintsETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(m.constraintsBody)
}

func (m *mountedRoute[C]) post(w http.ResponseWriter, r *http.Request, ctx C, details *errorDetails) {
	answer, err := m.dispatch(r, ctx, details)
	if err != nil {
		m.h.answerError(w, r, err, m.errorMapper(r, ctx), details)
		return
	}
	// Every successful answer carries the protocol of the server that wrote it: on a deploy,
	// instances of two releases answer one upload side by side.
	answer["protocol"] = UploadProtocol
	raw, err := marshalNoEscape(answer)
	if err != nil {
		// Only OnUploadComplete's data can fail to encode. The object is kept: the callback accepted it.
		m.h.logger.Error("upstash-blob: an upload route answer could not be encoded", "path", details.path, "err", err)
		writeJSON(w, 500, NewError(CodeRequestFailed, ErrorOptions{}))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func (m *mountedRoute[C]) dispatch(r *http.Request, ctx C, details *errorDetails) (map[string]any, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxRequestBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, newErr(CodeTooLarge, "the request body is over 1 MB")
		}
		return nil, newErr(CodeInvalidInput, "expected a JSON body with a phase")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, newErr(CodeInvalidInput, "expected a JSON body with a phase")
	}
	phase, ok := jsonString(body["phase"])
	if !ok {
		return nil, newErr(CodeInvalidInput, "expected a JSON body with a phase")
	}
	switch phase {
	case "begin":
		return m.begin(r, ctx, body, details)
	case "parts":
		return m.parts(r, ctx, body, details)
	case "end":
		// Run to the end even if the browser leaves: a multipart completed and then abandoned is a
		// stored object OnUploadComplete never saw. The browser counts on 'end' finishing without it.
		return m.end(r.WithContext(context.WithoutCancel(r.Context())), ctx, body, details)
	case "cancel":
		return m.cancel(r.WithContext(context.WithoutCancel(r.Context())), ctx, body, details)
	}
	return nil, newErr(CodeInvalidInput, "unknown phase "+phase)
}

func (m *mountedRoute[C]) begin(r *http.Request, ctx C, body map[string]json.RawMessage, details *errorDetails) (map[string]any, error) {
	file, err := readFile(body["file"])
	if err != nil {
		return nil, err
	}
	details.file = &file
	if file.Size == 0 {
		return nil, NewError(CodeEmptyBody, ErrorOptions{})
	}
	// The browser sends the file's first bytes so a mislabelled file is refused here, before a
	// multipart exists and before OnBeforeUpload has written anything down. Ergonomics, not a
	// control: the part bodies never reach this server.
	head := readHead(body["head"])
	if err := enforce(m.constraints, file, head); err != nil {
		return nil, err
	}

	input, err := m.validateInput(body["input"])
	if err != nil {
		return nil, err
	}
	decided, err := m.before(BeforeUploadArgs[C]{Ctx: ctx, Route: m.name, Request: r, File: file, Input: input})
	if err != nil {
		return nil, err
	}
	if decided.Path == "" {
		return nil, errors.New("blob: OnBeforeUpload must return a Path")
	}
	// The path is often built from the browser's file name, so a "../" in it can be the client's.
	if err := presignableKey(decided.Path); err != nil {
		return nil, err
	}
	details.path = decided.Path
	var state json.RawMessage
	if decided.State != nil {
		if state, err = json.Marshal(decided.State); err != nil {
			return nil, fmt.Errorf("blob: OnBeforeUpload returned a State that is not JSON: %w", err)
		}
		details.state = state
	}

	if decided.ContentTypes != nil || decided.MaxSize != 0 {
		if decided.MaxSize < 0 {
			return nil, errors.New("blob: OnBeforeUpload returned a negative MaxSize")
		}
		narrowed, err := resolveConstraints(decided.ContentTypes, decided.MaxSize)
		if err != nil {
			return nil, err
		}
		if narrowed.maxSize > 0 && m.constraints.maxSize > 0 && narrowed.maxSize > m.constraints.maxSize {
			return nil, fmt.Errorf("blob: OnBeforeUpload widened MaxSize (%d > %d)", narrowed.maxSize, m.constraints.maxSize)
		}
		if narrowed.contentTypes != nil && m.constraints.contentTypes != nil {
			var wider []string
			for _, t := range narrowed.contentTypes {
				if !containsString(m.constraints.contentTypes, t) {
					wider = append(wider, t)
				}
			}
			if len(wider) > 0 {
				return nil, fmt.Errorf("blob: OnBeforeUpload widened ContentTypes (%s)", strings.Join(wider, ", "))
			}
		}
		if err := enforce(narrowed, file, head); err != nil {
			return nil, err
		}
	}

	if _, err := m.r2.credentials(r.Context()); err != nil {
		return nil, err
	}
	cache := decided.Cache
	if cache == "" {
		cache = m.r2.defaultCache
	}
	cc, err := cacheControl(cache, m.r2.visibility())
	if err != nil {
		return nil, err
	}
	metadata := decided.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	details.metadata = metadata
	if _, reserved := metadata[uploadMarker]; reserved {
		return nil, newErr(CodeInvalidInput, "metadata."+uploadMarker+" is reserved by the SDK")
	}
	meta, err := metaHeaders(metadata)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"content-type": file.Type, "cache-control": cc}
	for k, v := range meta {
		headers[k] = v
	}

	// The path is OnBeforeUpload's to decide, so the multipart cannot be created before it runs; a
	// create that fails afterwards is told back to the app, with the path, through OnError.
	multipart, err := wantsMultipart(m.multipart, file.Size, "multipart")
	if err != nil {
		return nil, err
	}
	id := randomUUID()
	uploadID := ""
	if multipart {
		uploadID, err = m.r2.createMultipart(r.Context(), decided.Path, headers)
		if err != nil {
			if _, ok := asBlobError(err); !ok {
				err = NewError(CodeRequestFailed, ErrorOptions{Message: "could not start the upload", Status: 502, Cause: err})
			}
			return nil, err
		}
	} else {
		headers[uploadMarkerHeader] = id
	}
	// One part covering the whole file is how a single PUT is expressed: the browser runs the same
	// loop over one url, and only this side knows the url is an object PUT and not a part.
	partSize := file.Size
	if multipart {
		partSize = partSizeFor(file.Size)
	}
	payload := &tokenPayload{
		V:        1,
		B:        m.r2.bucketID,
		R:        m.id,
		ID:       id,
		Path:     decided.Path,
		N:        file.Name,
		Type:     file.Type,
		Size:     file.Size,
		Headers:  headers,
		Ctx:      state,
		Exp:      time.Now().Add(tokenTTL).UnixMilli(),
		UploadID: uploadID,
		PartSize: partSize,
	}
	token, err := signCompletionToken(payload, m.r2.signingSecret)
	if err != nil {
		return nil, err
	}
	parts, err := m.presignParts(r.Context(), payload, 1)
	if err != nil {
		// The browser never gets the token it would cancel with, so a multipart nobody can sign
		// parts for is aborted here rather than left billed until something sweeps it.
		if uploadID != "" {
			actx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
			if aerr := m.r2.abortMultipart(actx, decided.Path, uploadID); aerr != nil {
				m.h.logger.Error("upstash-blob: an upload could not be signed and its multipart could not be aborted", "path", decided.Path, "err", aerr)
			}
			cancel()
		}
		return nil, err
	}
	if len(parts) > 0 {
		m.probe.check(r, parts[0].URL, parts[0].Headers)
	}
	return map[string]any{
		"completionToken": token,
		"path":            decided.Path,
		"upload":          map[string]any{"partSize": partSize, "multipart": multipart, "parts": parts},
	}, nil
}

func (m *mountedRoute[C]) parts(r *http.Request, ctx C, body map[string]json.RawMessage, details *errorDetails) (map[string]any, error) {
	t, err := m.verify(body["completionToken"], details)
	if err != nil {
		return nil, err
	}
	from := 1
	if n, ok := jsonInt(body["from"]); ok && n >= 1 && n <= math.MaxInt32 {
		from = int(n)
	}
	// Nothing lands early on a single PUT: it is one object write, so a resumed upload runs it again.
	landed := []landedPart{}
	if t.UploadID != "" {
		if landed, err = m.r2.listParts(r.Context(), t.Path, t.UploadID); err != nil {
			return nil, err
		}
		if landed == nil {
			landed = []landedPart{}
		}
	}
	parts, err := m.presignParts(r.Context(), t, from)
	if err != nil {
		return nil, err
	}
	return map[string]any{"partSize": t.PartSize, "size": t.Size, "multipart": t.UploadID != "", "parts": parts, "landed": landed}, nil
}

func (m *mountedRoute[C]) end(r *http.Request, ctx C, body map[string]json.RawMessage, details *errorDetails) (map[string]any, error) {
	t, err := m.verify(body["completionToken"], details)
	if err != nil {
		return nil, err
	}
	rctx := r.Context()
	file := UploadFile{Name: t.N, Type: t.Type, Size: t.Size}
	details.file = &file

	expected := partCount(t.Size, t.PartSize)
	var raw []json.RawMessage
	if b := body["parts"]; len(b) > 0 && b[0] == '[' {
		_ = json.Unmarshal(b, &raw)
	}
	var list []landedPart
	if len(raw) != expected && t.UploadID != "" {
		if list, err = m.r2.listParts(rctx, t.Path, t.UploadID); err != nil {
			return nil, err
		}
	} else {
		for _, p := range raw {
			var part map[string]json.RawMessage
			if json.Unmarshal(p, &part) != nil {
				return nil, newErr(CodeInvalidInput, "parts must be [{ n, etag }]")
			}
			n, okN := jsonInt(part["n"])
			etag, okE := jsonString(part["etag"])
			if !okN || !okE || n < math.MinInt32 || n > math.MaxInt32 {
				return nil, newErr(CodeInvalidInput, "parts must be [{ n, etag }]")
			}
			list = append(list, landedPart{N: int(n), ETag: etag})
		}
	}
	if len(list) != expected {
		return nil, newErr(CodeInvalidInput, fmt.Sprintf("expected %d parts, %d landed", expected, len(list)))
	}

	// Kept for discard: what says the object still holds this upload's bytes and not a later
	// upload's. For a multipart that is the etag complete answered with; on a retried 'end' there is
	// none, and a refusal then leaves the object rather than delete one it cannot identify.
	completedETag := ""
	if t.UploadID != "" {
		completedETag, err = m.r2.completeMultipart(rctx, t.Path, t.UploadID, list)
		if err != nil {
			// NoSuchUpload after the object landed is a retried 'end': the earlier call completed it.
			if !HasCode(err, CodeNotFound) {
				return nil, err
			}
			if h, herr := m.r2.head(rctx, t.Path); herr != nil || h == nil {
				return nil, err
			}
		}
	}

	head, err := m.r2.head(rctx, t.Path)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, newErr(CodeNotFound, "the upload never landed")
	}
	if t.UploadID == "" {
		// A single PUT stored the object itself, so nothing says the object at this path came from
		// this upload rather than a stale token, a concurrent upload or whatever was there before.
		// The marker signed into the PUT is that proof, and what a refusal below deletes on.
		if head.metadata[uploadMarker] != t.ID {
			return nil, newErr(CodeNotFound, "the upload never landed")
		}
		delete(head.metadata, uploadMarker)
		completedETag = head.etag
	}
	// A refusal here deletes an object that is already stored and, on a public bucket, already
	// served. Deleting bounds that exposure; it does not undo it.
	if head.size != t.Size {
		m.discard(rctx, t.Path, completedETag)
		return nil, newErr(CodeSignatureMismatch, fmt.Sprintf("stored %d bytes, %d were declared", head.size, t.Size))
	}

	blob := CompletedBlob{BlobObject: m.r2.blobObject(t.Path, head.size, head.etag, head.uploadedAt), ContentType: head.contentType}
	details.metadata = head.metadata
	var data any
	if m.complete != nil {
		data, err = m.complete(UploadCompleteArgs[C]{
			CompletedBlob:     blob,
			Ctx:               ctx,
			Route:             m.name,
			Request:           r,
			File:              file,
			UploadID:          t.ID,
			MultipartUploadID: t.UploadID,
			Metadata:          head.metadata,
			State:             t.Ctx,
		})
		if err != nil {
			// The object exists only if OnUploadComplete returned. On a public bucket it has been
			// readable since it landed; the delete ends the storage, not the exposure.
			m.discard(rctx, t.Path, completedETag)
			return nil, err
		}
	}
	out := map[string]any{"blob": wireBlob(blob)}
	if data != nil {
		out["data"] = data
	}
	return out, nil
}

func wireBlob(b CompletedBlob) map[string]any {
	out := map[string]any{
		"path":        b.Path,
		"size":        b.Size,
		"etag":        b.ETag,
		"uploadedAt":  b.UploadedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		"contentType": b.ContentType,
	}
	if b.URL != "" {
		out["url"] = b.URL
		out["versionedUrl"] = b.VersionedURL
	}
	return out
}

// discard deletes the object a rejected upload left behind, unless it is no longer that object.
// R2 has no conditional delete, so this re-reads the etag first: on a stable path a later upload can
// already have replaced these bytes, and deleting then would destroy a file that was accepted.
func (m *mountedRoute[C]) discard(ctx context.Context, path, etag string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	log := m.h.logger
	// No etag is no permission. An orphan costs storage and a log line; a blind delete costs
	// somebody else's accepted file.
	if etag == "" {
		log.Error("upstash-blob: a refused upload could not be identified and was left stored rather than risk deleting a newer object", "path", path)
		return
	}
	current, err := m.r2.head(ctx, path)
	if err != nil {
		log.Error("upstash-blob: a refused upload could not be deleted and is still stored", "path", path, "err", err)
		return
	}
	if current == nil {
		return
	}
	if current.etag != etag {
		log.Warn("upstash-blob: a refused upload was replaced before it could be deleted; leaving the newer object alone", "path", path)
		return
	}
	res, err := m.r2.fetch(ctx, r2Request{method: "DELETE", path: path})
	if err == nil {
		drain(res)
		if !ok(res) && res.StatusCode != 404 {
			err = fmt.Errorf("storage responded %d", res.StatusCode)
		}
	}
	if err != nil {
		// The refusal is the answer; a delete that fails must not replace it with its own error.
		log.Error("upstash-blob: a refused upload could not be deleted and is still stored", "path", path, "err", err)
	}
}

func (m *mountedRoute[C]) cancel(r *http.Request, ctx C, body map[string]json.RawMessage, details *errorDetails) (map[string]any, error) {
	t, err := m.verify(body["completionToken"], details)
	if err != nil {
		return nil, err
	}
	if t.UploadID != "" {
		if err := m.r2.abortMultipart(r.Context(), t.Path, t.UploadID); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	}
	// A single PUT has nothing to abort: a PUT the browser aborted stores nothing, and a cancel that
	// arrives after the bytes landed is a whole object no callback accepted. The marker tells those
	// apart, so a cancel cannot be aimed at an object this upload did not write.
	head, err := m.r2.head(r.Context(), t.Path)
	if err != nil {
		return nil, err
	}
	if head != nil && head.metadata[uploadMarker] == t.ID {
		m.discard(r.Context(), t.Path, head.etag)
	}
	return map[string]any{"ok": true}, nil
}

func (m *mountedRoute[C]) verify(raw json.RawMessage, details *errorDetails) (*tokenPayload, error) {
	token, ok := jsonString(raw)
	if !ok {
		return nil, newErr(CodeInvalidInput, "completionToken is required")
	}
	t := verifyCompletionToken(token, m.r2.signingSecret)
	if t == nil || t.B != m.r2.bucketID || t.R != m.id {
		return nil, newErr(CodeForbidden, "completionToken is not valid for this route")
	}
	if t.Exp < time.Now().UnixMilli() {
		return nil, newErr(CodeForbidden, "completionToken has expired")
	}
	details.path = t.Path
	details.state = t.Ctx
	return t, nil
}

type wirePart struct {
	N   int    `json:"n"`
	URL string `json:"url"`
	// Headers pinned into the signature, sent with the PUT verbatim. Only a single PUT carries any.
	Headers map[string]string `json:"headers,omitempty"`
}

func (m *mountedRoute[C]) presignParts(ctx context.Context, t *tokenPayload, from int) ([]wirePart, error) {
	// A single PUT writes the object itself, so what a multipart upload pins at create has to be
	// signed into this url instead and sent with it: an unsigned header would be the browser's to
	// choose, and metadata the app reads back in OnUploadComplete is not the client's to write.
	if t.UploadID == "" {
		if from > 1 {
			return []wirePart{}, nil
		}
		headers := make(map[string]string, len(t.Headers)+1)
		for k, v := range t.Headers {
			headers[k] = v
		}
		headers["content-length"] = strconv.FormatInt(t.Size, 10)
		p, err := m.r2.presign(ctx, presignInit{method: "PUT", path: t.Path, expiresIn: maxPresignSeconds, headers: headers})
		if err != nil {
			return nil, err
		}
		sent := make(map[string]string, len(t.Headers))
		for k, v := range t.Headers {
			sent[k] = v
		}
		return []wirePart{{N: 1, URL: p.url, Headers: sent}}, nil
	}
	count := partCount(t.Size, t.PartSize)
	var numbers []int
	for n := from; n < from+partsPerBatch && n <= count; n++ {
		numbers = append(numbers, n)
	}
	out := make([]wirePart, len(numbers))
	errs := make([]error, len(numbers))
	var wg sync.WaitGroup
	// One agent request per url, so the batch is signed concurrently.
	for i, n := range numbers {
		wg.Add(1)
		go func(i, n int) {
			defer wg.Done()
			length := t.PartSize
			if n == count {
				length = t.Size - t.PartSize*int64(count-1)
			}
			p, err := m.r2.presign(ctx, presignInit{
				method:     "PUT",
				path:       t.Path,
				expiresIn:  maxPresignSeconds,
				headers:    map[string]string{"content-length": strconv.FormatInt(length, 10)},
				partNumber: n,
				uploadID:   t.UploadID,
			})
			out[i], errs[i] = wirePart{N: n, URL: p.url}, err
		}(i, n)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (m *mountedRoute[C]) validateInput(raw json.RawMessage) (any, error) {
	if m.input == nil {
		if raw != nil {
			return nil, newErr(CodeInvalidInput, "this route takes no input")
		}
		return nil, nil
	}
	v, err := m.input(raw)
	if err != nil {
		if be, ok := asBlobError(err); ok {
			return nil, be
		}
		return nil, NewError(CodeInvalidInput, ErrorOptions{Message: err.Error(), Cause: err})
	}
	return v, nil
}

func enforce(c resolvedConstraints, file UploadFile, head []byte) error {
	if c.maxSize > 0 && file.Size > c.maxSize {
		return newErr(CodeTooLarge, file.Name+" is "+overLimit(file.Size, c.maxSize))
	}
	if c.contentTypes != nil {
		return checkContentType(file.Type, head, c.contentTypes)
	}
	return nil
}

// readHead decodes the leading bytes a browser may send at 'begin'. Anything unreadable is no head.
func readHead(raw json.RawMessage) []byte {
	s, ok := jsonString(raw)
	if !ok || s == "" {
		return nil
	}
	// Clamped before decoding, not after: raw is whatever the client chose to send.
	if limit := (sniffBytes + 2) / 3 * 4; len(s) > limit {
		s = s[:limit]
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return nil
		}
	}
	if len(b) > sniffBytes {
		b = b[:sniffBytes]
	}
	return b
}

func readFile(raw json.RawMessage) (UploadFile, error) {
	bad := newErr(CodeInvalidInput, "file must be { name, type, size }")
	var f map[string]json.RawMessage
	if json.Unmarshal(raw, &f) != nil || f == nil {
		return UploadFile{}, bad
	}
	name, okName := jsonString(f["name"])
	size, okSize := jsonInt(f["size"])
	if !okName || !okSize || size < 0 {
		return UploadFile{}, bad
	}
	t := "application/octet-stream"
	if s, ok := jsonString(f["type"]); ok && s != "" {
		bare, _, _ := strings.Cut(strings.ToLower(s), ";")
		t = strings.TrimSpace(bare)
	}
	if !headerValueOK(t) {
		return UploadFile{}, bad
	}
	return UploadFile{Name: name, Type: t, Size: size}, nil
}

// answerError writes every refusal as the *Error JSON shape, so the browser rebuilds it with its
// code intact. An error with no code and no status is the app's bug: logged, and answered as a 500.
func (h *UploadHandler[C]) answerError(w http.ResponseWriter, r *http.Request, err error, mapper func(error, *errorDetails) error, details *errorDetails) {
	// OnError answers with an *Error it returns; anything else leaves the answer alone.
	if mapper != nil {
		if mapped, ok := asBlobError(mapper(err, details)); ok {
			err = mapped
		}
	}
	if be, ok := asBlobError(err); ok {
		writeJSON(w, be.httpStatus(), be)
		return
	}
	if status, ok := statusOf(err); ok {
		// An auth check that returned its own 401 reaches the browser as code 'unauthorized'.
		msg := err.Error()
		if msg == "" {
			msg = "request failed"
		}
		writeJSON(w, status, ErrorFromStatus(status, ErrorOptions{Message: msg}))
		return
	}
	h.logger.Error("upstash-blob: upload route failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeJSON(w, 500, NewError(CodeRequestFailed, ErrorOptions{}))
}

// statusOf reads an HTTP status off an app error that names one with a StatusCode() int method.
func statusOf(err error) (int, bool) {
	var s interface{ StatusCode() int }
	if errors.As(err, &s) && !isNilPointer(s) {
		if code := s.StatusCode(); code >= 400 && code < 600 {
			return code, true
		}
	}
	return 0, false
}

func isNilPointer(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// writeJSON writes an answer whose encoding cannot fail: an *Error or the constraints document.
func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := marshalNoEscape(v)
	if err != nil {
		status, raw = 500, []byte(`{"code":"request_failed","message":"Request failed","status":500}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// jsonInt reads a JSON number with an integer value, the way Number.isInteger does, within the
// range a double holds exactly.
func jsonInt(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || !(raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')) {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// deriveRouteID separates routes in a completion token, the same derivation blob-js uses.
func deriveRouteID(c resolvedConstraints, hasInput bool, route string) string {
	var types any
	if c.contentTypes != nil {
		types = c.contentTypes
	}
	var maxSize any
	if c.maxSize > 0 {
		maxSize = c.maxSize
	}
	raw, _ := marshalNoEscape([]any{route, types, maxSize, hasInput})
	return fnv36(string(raw))
}

// fnv36 is FNV-1a over UTF-16 code units, in base 36. Not a security boundary: the token's MAC is.
// This only separates routes and versions a body.
func fnv36(s string) string {
	h := uint32(0x811c9dc5)
	for _, u := range utf16.Encode([]rune(s)) {
		h ^= uint32(u)
		h *= 0x01000193
	}
	return strconv.FormatUint(uint64(h), 36)
}
