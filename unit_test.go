package blob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSignHeadersMatchesBlobJS(t *testing.T) {
	u, _ := url.Parse("https://acct.r2.cloudflarestorage.com")
	u.Path, u.RawPath = "/bucket-id/some key/x.png", "/bucket-id/some%20key/x.png"
	u.RawQuery = encodeQuery(map[string]string{"partNumber": "3", "uploadId": "abc/def"})
	got := signHeaders(signingCredentials{"AKIAEXAMPLE", "secretsecretsecret", "tok/en+123", "auto"}, "PUT", u,
		map[string]string{"content-type": "image/png", "content-length": "12", "x-amz-meta-foo": "bar  baz"},
		time.Date(2026, 8, 24, 12, 34, 56, 0, time.UTC))
	// Golden value from blob-js signHeaders, itself checked against @smithy/signature-v4.
	want := "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260824/auto/s3/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-foo;x-amz-security-token, Signature=d4d8ca16ed25d665d7b8d64583cf7450c93168d49a242822dc235e8871c0922d"
	if got["authorization"] != want {
		t.Fatalf("authorization:\n got %s\nwant %s", got["authorization"], want)
	}
	if _, ok := got["host"]; ok || got["x-amz-security-token"] != "tok/en+123" || got["x-amz-date"] != "20260824T123456Z" {
		t.Fatalf("headers: %v", got)
	}
	if u.EscapedPath() != "/bucket-id/some%20key/x.png" {
		t.Fatalf("the request sends the path it signed: %s", u.EscapedPath())
	}
}

func TestURIEncode(t *testing.T) {
	for in, want := range map[string]string{"a b": "a%20b", "a/b": "a%2Fb", "A-Za-z0-9-_.~": "A-Za-z0-9-_.~", "*!()'": "%2A%21%28%29%27", "+=&?#%": "%2B%3D%26%3F%23%25", "日本": "%E6%97%A5%E6%9C%AC"} {
		if got := uriEncode(in, false); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeToken(t *testing.T) {
	d, err := decodeToken("AgAIAAkGYnVja2V0LTFwdy1zZWNyZXRhYmMxMjM") // from blob-js encodeToken
	if err != nil || d.bucketID != "bucket-1" || d.password != "pw-secret" || d.hashForDomain != "abc123" {
		t.Fatalf("%+v %v", d, err)
	}
	for _, bad := range []string{"", "!!!", encodeToken("b", "p", "h", 0) + "AA", "AQAAAAAA"} {
		if _, err := decodeToken(bad); err == nil {
			t.Errorf("decodeToken(%q) accepted", bad)
		}
	}
	if _, err := NewBucket("nope"); err == nil {
		t.Fatal("NewBucket accepted a bad token")
	}
}

func TestUnits(t *testing.T) {
	for in, want := range map[string]int64{"2MB": 2_000_000, "32MiB": 32 * MiB, "500kb": 500_000, "10": 10, " 1.5 KB ": 1500, "1gib": GiB} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "MB", "2XB", "-1", "1e3"} {
		if _, err := ParseSize(bad); !HasCode(err, CodeInvalidInput) {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
	for in, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1 KB", 1500: "1.5 KB", 999_950: "1.0 MB", 12_345_678: "12 MB", 32 * MiB: "34 MB"} {
		if got := FormatBytes(in); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := overLimit(2_000_001, 2_000_000); got != "2,000,001 bytes, over the 2,000,000 byte limit" {
		t.Errorf("overLimit: %q", got)
	}
	if got := overLimit(3_000_000, 2_000_000); got != "3 MB, over the 2 MB limit" {
		t.Errorf("overLimit: %q", got)
	}
	for in, want := range map[string]string{"": "public, max-age=3600", "immutable": "public, max-age=31536000, immutable", "revalidate": "public, max-age=0, must-revalidate", "no-store": "no-store", "15m": "public, max-age=900", "3600": "public, max-age=3600", "1h30m": "public, max-age=5400", " s-maxage=60, public ": "s-maxage=60, public"} {
		if got, err := cacheControl(in, "public"); err != nil || got != want {
			t.Errorf("cacheControl(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if got, _ := cacheControl("", "private"); got != "private, max-age=3600" {
		t.Errorf("private: %q", got)
	}
	for _, bad := range []string{"soon", "max-age=1\r\nx: y"} {
		if _, err := cacheControl(bad, "public"); err == nil {
			t.Errorf("cacheControl(%q) accepted", bad)
		}
	}
}

func TestContentTypes(t *testing.T) {
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13}, "IHDR"...)
	if sniff(png) != "image/png" || sniff([]byte("%PDF-1.7")) != "application/pdf" || sniff([]byte("hello")) != "" {
		t.Fatal("sniff")
	}
	images, err := expandContentTypes([]string{"image/*", "IMAGE/JPG"})
	if err != nil || !containsString(images, "image/jpeg") || containsString(images, "image/svg+xml") || len(images) != 10 {
		t.Fatalf("expand: %v %v", images, err)
	}
	for _, bad := range [][]string{{}, {"*/*"}, {"text/*"}, {"nope"}} {
		if _, err := expandContentTypes(bad); !HasCode(err, CodeInvalidContentTypePattern) {
			t.Errorf("expand(%v) accepted", bad)
		}
	}
	if err := checkContentType("image/jpg; q=1", nil, images); err != nil {
		t.Fatal("an alias is the canonical type:", err)
	}
	if err := checkContentType("application/pdf", nil, images); !HasCode(err, CodeContentTypeNotAllowed) || err.Error() != "application/pdf is not allowed (allowed: "+strings.Join(images, ", ")+")" {
		t.Fatalf("not allowed: %v", err)
	}
	if err := checkContentType("image/jpeg", png, images); !HasCode(err, CodeContentTypeNotAllowed) {
		t.Fatal("png bytes declared jpeg")
	}
	zip := []byte{0x50, 0x4b, 0x03, 0x04}
	docx := "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	if err := checkContentType(docx, zip, []string{docx}); err != nil {
		t.Fatal("a docx really is a zip:", err)
	}
}

func TestErrors(t *testing.T) {
	e := NewError(CodeLengthRequired, ErrorOptions{})
	if e.Status != 411 || e.Message != "Length required (pass Size or MaxSize so the length is known before the first byte)" {
		t.Fatalf("%+v", e)
	}
	if m := newErr(CodeContentTypeNotAllowed, "image/png is not allowed").Message; m != "image/png is not allowed" {
		t.Fatalf("an identifier keeps its case: %q", m)
	}
	size := int64(5)
	raw, _ := json.Marshal(NewError(CodeAlreadyExists, ErrorOptions{Message: "a already exists", ETag: `"x"`, Size: &size, Cause: errors.New("secret")}))
	if string(raw) != `{"code":"already_exists","message":"A already exists","status":409,"etag":"\"x\"","size":5}` {
		t.Fatalf("json: %s", raw)
	}
	raw, _ = json.Marshal(NewError(CodeMintBackoff, ErrorOptions{RetryAfter: 30 * time.Second}))
	if !strings.Contains(string(raw), `"retryAfter":30`) {
		t.Fatalf("retryAfter in seconds: %s", raw)
	}
	wrapped := errors.Join(errors.New("ctx"), newErr(CodeNotFound, "x not found"))
	if !errors.Is(wrapped, ErrNotFound) || errors.Is(wrapped, ErrConflict) || !HasCode(wrapped, CodeNotFound) {
		t.Fatal("errors.Is by code")
	}
	if ErrorFromStatus(401, ErrorOptions{}).Code != CodeUnauthorized || ErrorFromStatus(418, ErrorOptions{}).Code != CodeRequestFailed {
		t.Fatal("from status")
	}
}

func TestKeys(t *testing.T) {
	if got, err := encodeKey("a b/ü/x.png"); err != nil || got != "a%20b/%C3%BC/x.png" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "a/../b", "./a", "..", "a/.", "\xff"} {
		if _, err := encodeKey(bad); !HasCode(err, CodeInvalidInput) {
			t.Errorf("encodeKey(%q) accepted", bad)
		}
	}
	for _, bad := range []string{"a//b", "/a", "a/", "a\nb"} {
		if err := presignableKey(bad); !HasCode(err, CodeInvalidInput) {
			t.Errorf("presignableKey(%q) accepted", bad)
		}
	}
	if _, err := metaHeaders(map[string]string{"recordId": "1"}); !HasCode(err, CodeInvalidInput) {
		t.Error("uppercase metadata key")
	}
	if _, err := metaHeaders(map[string]string{"note": "café"}); !HasCode(err, CodeInvalidInput) {
		t.Error("non-ASCII metadata value")
	}
	if _, err := metaHeaders(map[string]string{"bad key": "x"}); !HasCode(err, CodeInvalidInput) {
		t.Error("bad header name")
	}
}

func TestCompletionTokenAndRouteIDMatchBlobJS(t *testing.T) {
	// Minted by blob-js signToken with key "pw-secret".
	js := "eyJ2IjoxLCJiIjoiYnVja2V0LTEiLCJyIjoicjEiLCJpZCI6InUtMSIsInBhdGgiOiJhL2IucG5nIiwibiI6ImIucG5nIiwidHlwZSI6ImltYWdlL3BuZyIsInNpemUiOjEwLCJoZWFkZXJzIjp7ImNvbnRlbnQtdHlwZSI6ImltYWdlL3BuZyJ9LCJjdHgiOnsiayI6InYifSwiZXhwIjo0MTAyNDQ0ODAwMDAwLCJvIjoiYWxpY2UiLCJwYXJ0U2l6ZSI6MTB9.BI8wo5Scg61pbyhyasIPzckWSGHZtJ2e9w2VMKD11I0"
	p := verifyCompletionToken(js, "pw-secret")
	if p == nil || p.Path != "a/b.png" || *p.O != "alice" || string(p.Ctx) != `{"k":"v"}` || p.Exp != 4102444800000 {
		t.Fatalf("%+v", p)
	}
	if verifyCompletionToken(js, "other") != nil || verifyCompletionToken(js[:len(js)-2]+"AA", "pw-secret") != nil || verifyCompletionToken("x", "pw-secret") != nil {
		t.Fatal("accepted a bad token")
	}
	tok, _ := signCompletionToken(p, "pw-secret")
	if q := verifyCompletionToken(tok, "pw-secret"); q == nil || q.ID != "u-1" {
		t.Fatal("round trip")
	}
	images, _ := resolveConstraints([]string{"image/*"}, 5*MB)
	pdf, _ := resolveConstraints([]string{"application/pdf"}, 0)
	for _, c := range []struct {
		got, want string
	}{
		{deriveRouteID(images, true, "/api/uploads?route=avatar"), "pc9jf8"},
		{deriveRouteID(resolvedConstraints{}, false, ""), "v64t6m"},
		{deriveRouteID(pdf, false, "é<&>"), "jszftx"},
	} {
		if c.got != c.want {
			t.Errorf("route id %s, blob-js %s", c.got, c.want)
		}
	}
}

func TestUniquePath(t *testing.T) {
	for in, re := range map[string]string{
		"users/a/Q3 Report.pdf": `^users/a/Q3 Report-[1-9A-HJ-NP-Za-km-z]{8}\.pdf$`,
		"x/":                    `^x/file-[1-9A-HJ-NP-Za-km-z]{8}$`,
		".env":                  `^\.env-[1-9A-HJ-NP-Za-km-z]{8}$`,
		"a.tar.gz":              `^a\.tar-[1-9A-HJ-NP-Za-km-z]{8}\.gz$`,
	} {
		if got := UniquePath(in); !regexpMatch(re, got) {
			t.Errorf("UniquePath(%q) = %q", in, got)
		}
	}
}

func TestPutRetriesAndBodies(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	ctx := context.Background()
	fails := 1
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "PUT" && strings.Contains(req.URL.Path, "/flaky") && fails > 0 {
			fails--
			return respond(503, "", "Retry-After", "0")
		}
		return nil
	}
	// A seekable body is sent again whole after a 503.
	if _, err := b.Put(ctx, "flaky.bin", strings.NewReader("abcdef"), nil); err != nil {
		t.Fatal(err)
	}
	sent := f.bodies["PUT acct.r2.cloudflarestorage.com/bucket-1/flaky.bin"]
	if len(sent) != 2 || string(sent[0]) != "abcdef" || string(sent[1]) != "abcdef" {
		t.Fatalf("resent: %q", sent)
	}
	// A plain stream is sent once.
	fails = 1
	_, err := b.Put(ctx, "flaky2.bin", io.MultiReader(strings.NewReader("ab")), &PutOptions{Size: 2})
	mustCode(t, err, CodeNotReady)
	if n := f.called("PUT acct.r2.cloudflarestorage.com/bucket-1/flaky2.bin"); n != 1 {
		t.Fatalf("a stream was sent %d times", n)
	}
	// A seekable body is sent from where it was, not from 0.
	r := strings.NewReader("skip-this")
	_, _ = r.Seek(5, io.SeekStart)
	if put, err := b.Put(ctx, "offset.bin", r, nil); err != nil || put.Size != 4 || string(f.objects["offset.bin"].data) != "this" {
		t.Fatalf("offset: %+v %v", put, err)
	}
	// Content type from a file's extension, headers on the stored object.
	if _, err := b.Put(ctx, "c.txt", bytes.NewBufferString("x"), &PutOptions{Metadata: map[string]string{"a": "b"}, Cache: "1h"}); err != nil {
		t.Fatal(err)
	}
	h := f.objects["c.txt"].headers
	if h.Get("Content-Type") != "application/octet-stream" || h.Get("Cache-Control") != "public, max-age=3600" || h.Get("X-Amz-Meta-A") != "b" {
		t.Fatalf("stored headers: %v", h)
	}
	// Reads ask for the stored representation.
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "GET" && req.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("GET without Accept-Encoding: identity")
		}
		return nil
	}
	if _, err := b.Info(ctx, "c.txt"); err != nil {
		t.Fatal(err)
	}
	g, err := b.Get(ctx, "c.txt")
	if err != nil {
		t.Fatal(err)
	}
	g.Body.Close()
}

func TestRetryConfig(t *testing.T) {
	f := newFake()
	var counts []int
	b := f.bucket(t, func(o *Options) {
		o.Retry = RetryConfig{Retries: 3, Backoff: func(n int) time.Duration { counts = append(counts, n); return time.Millisecond }}
	})
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "HEAD" {
			return respond(500, "")
		}
		return nil
	}
	_, err := b.Exists(context.Background(), "x")
	mustCode(t, err, CodeRequestFailed)
	if len(counts) != 3 || counts[0] != 0 || counts[2] != 2 || f.called("HEAD") != 4 {
		t.Fatalf("backoff calls %v, %d HEADs", counts, f.called("HEAD"))
	}
	f2 := newFake()
	b2 := f2.bucket(t, func(o *Options) { o.Retry = RetryConfig{Disabled: true} })
	f2.hook = f.hook
	_, _ = b2.Exists(context.Background(), "x")
	if f2.called("HEAD") != 1 {
		t.Fatalf("disabled sent %d", f2.called("HEAD"))
	}
	// A POST is never retried.
	f3 := newFake()
	b3 := f3.bucket(t)
	f3.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "POST" && strings.Contains(req.URL.RawQuery, "delete") {
			return respond(500, "")
		}
		return nil
	}
	_ = b3.DeleteMany(context.Background(), []string{"a"})
	if f3.called("POST acct") != 1 {
		t.Fatalf("POST sent %d times", f3.called("POST acct"))
	}
	if _, err := NewBucketWith(Options{Token: encodeToken("b", "p", "h", 0), Retry: RetryConfig{Retries: -1}}); err == nil {
		t.Fatal("negative retries accepted")
	}
}

func TestCredentialRemintAndSharing(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	ctx := context.Background()
	refused := 1
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "GET" && refused > 0 {
			refused--
			return respond(403, "<Error><Code>ExpiredToken</Code></Error>")
		}
		return nil
	}
	f.objects["k"] = &fakeObject{data: []byte("v"), headers: http.Header{}, etag: `"1"`}
	g, err := b.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	g.Body.Close()
	if f.mints.Load() != 2 {
		t.Fatalf("re-minted %d times", f.mints.Load()-1)
	}
	// Another bucket on the same token shares the credential, and concurrent callers one mint.
	resetCredentialCaches()
	f.mints.Store(0)
	f.hook = nil
	token := encodeToken("bucket-1", "pw-secret", "abc123", 0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bb, _ := NewBucketWith(Options{Token: token, HTTPClient: f.client(), DisableTelemetry: true})
			if _, err := bb.Exists(ctx, "k"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.mints.Load() != 1 {
		t.Fatalf("minted %d times", f.mints.Load())
	}
	// A 403 that is not about the credential is a signature mismatch, not a re-mint.
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "GET" {
			return respond(403, "<Error><Code>AccessDenied</Code></Error>")
		}
		return nil
	}
	_, err = b.Get(ctx, "k")
	mustCode(t, err, CodeSignatureMismatch)
}

func TestMintFailures(t *testing.T) {
	cases := []struct {
		res  func() *http.Response
		code ErrorCode
	}{
		{func() *http.Response { return respond(429, "", "Retry-After", "30") }, CodeMintBackoff},
		{func() *http.Response { return respond(401, "") }, CodeUnauthorized},
		{func() *http.Response {
			return respond(200, `{"endpoint":"https://evil.example.com","bucket":"b","expiresAt":9999999999}`)
		}, CodeRequestFailed},
	}
	for _, c := range cases {
		f := newFake()
		b := f.bucket(t)
		f.hook = func(req *http.Request, body []byte) *http.Response {
			if req.URL.Path == "/v1/credentials" {
				return c.res()
			}
			return nil
		}
		_, err := b.Exists(context.Background(), "x")
		mustCode(t, err, c.code)
	}
	// A caller whose ctx ends stops waiting on a mint that is still running.
	f := newFake()
	b := f.bucket(t)
	release := make(chan struct{})
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.URL.Path == "/v1/credentials" {
			<-release
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := b.Exists(ctx, "x")
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the ctx error, got %v", err)
	}
}

func TestPresign(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	ctx := context.Background()
	s, err := b.SignedReadURL(ctx, "a b.pdf", &SignedReadURLOptions{ExpiresIn: time.Hour, DownloadAs: `r"e;p\n.pdf`, ContentType: "application/pdf"})
	if err != nil || !strings.HasPrefix(s.URL, fakeEndpoint) {
		t.Fatalf("%+v %v", s, err)
	}
	var sent map[string]any
	_ = json.Unmarshal(f.bodies["POST blob.upstash.io/v1/presign"][0], &sent)
	q := sent["query"].(map[string]any)
	if sent["expiresIn"] != float64(600) || q["response-content-disposition"] != `attachment; filename="r_e_p_n.pdf"; filename*=UTF-8''r%22e%3Bp%5Cn.pdf` {
		t.Fatalf("presign body: %v", sent)
	}
	if _, err := b.SignedReadURL(ctx, "x", &SignedReadURLOptions{ContentType: "text/html\r\nx: y"}); !HasCode(err, CodeInvalidInput) {
		t.Fatal("a header-injecting content type was accepted")
	}
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.URL.Path == "/v1/presign" {
			return respond(403, `{"error":"bucket suspended for billing"}`)
		}
		return nil
	}
	_, err = b.SignedReadURL(ctx, "x", nil)
	mustCode(t, err, CodeForbidden)
	if strings.Contains(err.Error(), "billing") || !strings.Contains(errors.Unwrap(err).Error(), "billing") {
		t.Fatalf("the owner's notice rides on the cause: %v", err)
	}
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.URL.Path == "/v1/presign" {
			return respond(200, `{"url":"https://evil.example.com/x","expiresAt":1}`)
		}
		return nil
	}
	_, err = b.SignedReadURL(ctx, "x", nil)
	mustCode(t, err, CodeRequestFailed)
	f.hook = nil
	up, err := b.SignedUploadURL(ctx, "u.bin", &SignedUploadURLOptions{Size: 3, NoOverwrite: true})
	if err != nil || up.Headers["content-length"] != "3" || up.Headers["if-none-match"] != "*" || up.Headers["cache-control"] != "public, max-age=3600" {
		t.Fatalf("%+v %v", up, err)
	}
	if _, err := b.SignedUploadURL(ctx, "a//b", nil); !HasCode(err, CodeInvalidInput) {
		t.Fatal("an empty segment was signed")
	}
}

func TestMultipartFailureAborts(t *testing.T) {
	f := newFake()
	f.partDelay = 20 * time.Millisecond
	b := f.bucket(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("x"), int(30*MiB))
	if _, err := b.Put(ctx, "ok.bin", bytes.NewReader(data), &PutOptions{Multipart: MultipartAlways}); err != nil {
		t.Fatal(err)
	}
	if got := f.objects["ok.bin"]; got == nil || !bytes.Equal(got.data, data) {
		t.Fatal("multipart round trip")
	}
	if m := f.maxPart.Load(); m < 2 || m > 4 {
		t.Fatalf("parts in flight peaked at %d", m)
	}
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.URL.Query().Get("partNumber") == "3" {
			return respond(400, "<Error><Code>InvalidPart</Code></Error>")
		}
		return nil
	}
	_, err := b.Put(ctx, "bad.bin", bytes.NewReader(data), &PutOptions{Multipart: MultipartAlways})
	mustCode(t, err, CodeRequestFailed)
	if len(f.uploads) != 0 || f.called("DELETE acct.r2.cloudflarestorage.com/bucket-1/bad.bin?uploadId=") != 1 {
		t.Fatalf("a failed multipart was not aborted: %d left", len(f.uploads))
	}
	if _, ok := f.objects["bad.bin"]; ok {
		t.Fatal("a failed multipart was stored")
	}
	// The single-PUT cap: MultipartNever cannot carry 6 GiB.
	_, err = b.Put(ctx, "huge.bin", io.MultiReader(), &PutOptions{Size: 6 * GiB, Multipart: MultipartNever})
	mustCode(t, err, CodeTooLarge)
	if partConcurrencyFor(partSizeFor(100*MB)) != 4 || partConcurrencyFor(25*MiB) != 1 || partSizeFor(5*GiB) != 21*MiB {
		t.Fatal("part math")
	}
}

func TestBucketOps(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	ctx := context.Background()
	for _, p := range []string{"a/1", "a/2", "b/1"} {
		if _, err := b.Put(ctx, p, strings.NewReader(p), &PutOptions{ContentType: "text/plain", Metadata: map[string]string{"k": "v"}}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := b.List(ctx, &ListOptions{Prefix: "a/"})
	if err != nil || len(page.Blobs) != 2 || page.Blobs[0].URL != "https://abc123.blob.upstash.io/a/1" || page.Cursor != "" {
		t.Fatalf("%+v %v", page, err)
	}
	if _, err := b.Copy(ctx, "a/1", "c/1", &CopyOptions{Metadata: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if h := f.objects["c/1"].headers; h.Get("Content-Type") != "text/plain" || h.Get("X-Amz-Meta-K") != "" || h.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("copy with emptied metadata: %v", h)
	}
	if _, err := b.Copy(ctx, "nope", "c/2", &CopyOptions{ContentType: "text/plain"}); !HasCode(err, CodeNotFound) {
		t.Fatalf("copy from nothing: %v", err)
	}
	if err := b.DeletePrefix(ctx, "a/"); err != nil {
		t.Fatal(err)
	}
	if len(f.objects) != 2 {
		t.Fatalf("left %d", len(f.objects))
	}
	if err := b.DeleteAll(ctx); err != nil || len(f.objects) != 0 {
		t.Fatalf("delete all: %v, %d left", err, len(f.objects))
	}
	_, err = b.Put(ctx, "../x", strings.NewReader("x"), nil)
	mustCode(t, err, CodeInvalidInput)
	_, err = b.Put(ctx, "x", strings.NewReader("x"), &PutOptions{Metadata: map[string]string{"Bad": "x"}})
	mustCode(t, err, CodeInvalidInput)

	// UpdateJSON under a racing writer converges.
	n := 0
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "PUT" && req.Header.Get("If-Match") != "" && n < 2 {
			n++
			return respond(412, "<Error><Code>PreconditionFailed</Code></Error>")
		}
		return nil
	}
	type doc struct{ N int }
	if _, err := UpdateJSON(ctx, b, "d.json", func(prev *doc) (doc, error) { return doc{N: 1}, nil }, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateJSON(ctx, b, "d.json", func(prev *doc) (doc, error) { return doc{N: prev.N + 1}, nil }, nil); err != nil {
		t.Fatal(err)
	}
	if string(f.objects["d.json"].data) != `{"N":2}` || n != 2 {
		t.Fatalf("updateJSON: %s after %d conflicts", f.objects["d.json"].data, n)
	}
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "PUT" && req.Header.Get("If-Match") != "" {
			return respond(412, "<Error><Code>PreconditionFailed</Code></Error>")
		}
		return nil
	}
	_, err = UpdateJSON(ctx, b, "d.json", func(prev *doc) (doc, error) { return *prev, nil }, &UpdateJSONOptions{MaxAttempts: 2})
	mustCode(t, err, CodeConflict)
}

func TestPrivateVisibility(t *testing.T) {
	f := newFake()
	f.visibility = "private"
	b := f.bucket(t)
	put, err := b.Put(context.Background(), "s", strings.NewReader("s"), nil)
	if err != nil || put.URL != "" || f.objects["s"].headers.Get("Cache-Control") != "private, max-age=3600" {
		t.Fatalf("%+v %v", put, err)
	}
}

func TestRound1Regressions(t *testing.T) {
	// A token read from a file keeps working.
	f := newFake()
	resetCredentialCaches()
	b, err := NewBucketWith(Options{Token: encodeToken("bucket-1", "pw-secret", "abc123", 0) + "\n", HTTPClient: f.client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Exists(context.Background(), "x"); err != nil {
		t.Fatal("a token with a trailing newline:", err)
	}
	// A file body retried after a 503 is sent whole, from its own reader.
	path := t.TempDir() + "/body.txt"
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Open(path)
	defer file.Close()
	_, _ = file.Seek(2, io.SeekStart)
	fails := 1
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method == "PUT" && fails > 0 {
			fails--
			return respond(503, "")
		}
		return nil
	}
	put, err := b.Put(context.Background(), "f.txt", file, nil)
	sent := f.bodies["PUT acct.r2.cloudflarestorage.com/bucket-1/f.txt"]
	if err != nil || put.Size != 8 || put.ContentType != "text/plain; charset=utf-8" || len(sent) != 2 || string(sent[1]) != "23456789" {
		t.Fatalf("%+v %v %q", put, err, sent)
	}
}

func TestRound2Regressions(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	ctx := context.Background()
	f.objects["n.json"] = &fakeObject{data: []byte(" null\n"), headers: http.Header{}, etag: `"n"`}
	if _, err := UpdateJSON(ctx, b, "n.json", func(prev *map[string]int) (map[string]int, error) {
		if prev != nil {
			t.Fatalf("JSON null reached fn as %v", *prev)
		}
		return map[string]int{"x": 1}, nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBufferString("keep")
	if _, err := b.Put(ctx, "buf", buf, nil); err != nil || buf.String() != "keep" {
		t.Fatalf("a *bytes.Buffer was drained: %q %v", buf.String(), err)
	}
	if _, err := b.SignedReadURL(ctx, "x", &SignedReadURLOptions{ExpiresIn: -time.Second}); !HasCode(err, CodeInvalidInput) {
		t.Fatal("negative ExpiresIn accepted")
	}
	if e := (&Error{Code: "custom"}); e.Error() != "Request failed" {
		t.Fatalf("unknown code message: %q", e.Error())
	}
	if _, err := b.SignedUploadURL(ctx, "x", &SignedUploadURLOptions{ExpiresIn: -time.Second}); !HasCode(err, CodeInvalidInput) {
		t.Fatal("negative upload ExpiresIn accepted")
	}
}

func TestXMLReading(t *testing.T) {
	doc := "<R><Contents><Key>a\rb&amp;&#13;&#x41;&lt;&bogus;</Key></Contents><Contents><Key></Key></Contents><IsTruncated>false</IsTruncated></R>"
	blocks := xmlBlocks(doc, "Contents")
	if k, _ := xmlTag(blocks[0], "Key"); len(blocks) != 2 || k != "a\rb&\rA<&bogus;" {
		t.Fatalf("%q %q", blocks, k)
	}
	if k, ok := xmlTag(blocks[1], "Key"); !ok || k != "" {
		t.Fatal("an empty element is present")
	}
	if _, ok := xmlTag(doc, "NextContinuationToken"); ok {
		t.Fatal("a missing element is absent")
	}
	if escapeXML("a\r&<>") != "a&#13;&amp;&lt;&gt;" || xmlCarries("a\x01") || !xmlCarries("a\t\r\nb") {
		t.Fatal("escape")
	}
}

func TestRound5Regressions(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	ctx := context.Background()

	// A move onto itself keeps the object.
	f.objects["x"] = &fakeObject{data: []byte("x"), headers: http.Header{"Content-Type": {"text/plain"}}, etag: `"x"`}
	if _, err := b.Move(ctx, "x", "x", &CopyOptions{ContentType: "text/csv"}); err != nil || f.objects["x"] == nil {
		t.Fatalf("move onto itself: %v", err)
	}

	// A conditional PUT stored by an attempt whose answer was lost is not a conflict on the retry.
	storeThenLose := func(req *http.Request, body []byte) *http.Response {
		if req.Method != "PUT" {
			return nil
		}
		f.hook = nil
		res, _ := f.RoundTrip(cloneWithBody(req, body))
		res.Body.Close()
		return respond(503, "")
	}
	f.objects["n.json"] = &fakeObject{data: []byte(`{"n":0}`), headers: http.Header{}, etag: `"n0"`}
	runs := 0
	f.hook = storeThenLose
	if _, err := UpdateJSON(ctx, b, "n.json", func(prev *map[string]int) (map[string]int, error) {
		runs++
		return map[string]int{"n": (*prev)["n"] + 1}, nil
	}, nil); err != nil || runs != 1 || string(f.objects["n.json"].data) != `{"n":1}` {
		t.Fatalf("UpdateJSON after a lost answer: runs=%d %s %v", runs, f.objects["n.json"].data, err)
	}
	f.hook = storeThenLose
	if _, err := b.Put(ctx, "new", strings.NewReader("mine"), &PutOptions{NoOverwrite: true}); err != nil {
		t.Fatalf("NoOverwrite after a lost answer: %v", err)
	}
	// Someone else's object is still a refusal after a resend.
	f.hook = func(req *http.Request, body []byte) *http.Response {
		if req.Method != "PUT" {
			return nil
		}
		f.hook = nil
		f.objects["taken"] = &fakeObject{data: []byte("theirs"), headers: http.Header{}, etag: `"t"`}
		return respond(503, "")
	}
	if _, err := b.Put(ctx, "taken", strings.NewReader("mine"), &PutOptions{NoOverwrite: true}); !HasCode(err, CodeAlreadyExists) {
		t.Fatalf("someone else's object: %v", err)
	}
}

func cloneWithBody(req *http.Request, body []byte) *http.Request {
	c := req.Clone(req.Context())
	c.Body = io.NopCloser(bytes.NewReader(body))
	return c
}
