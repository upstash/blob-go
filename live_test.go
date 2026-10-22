package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Live tests run against real buckets and need UPSTASH_BLOB_PUBLIC_TOKEN and
// UPSTASH_BLOB_PRIVATE_TOKEN. They write only under go-live/<run>/ and delete it afterwards.

func liveBucket(t *testing.T, env string) (*Bucket, string) {
	t.Helper()
	token := os.Getenv(env)
	if token == "" {
		t.Skipf("%s is not set", env)
	}
	b, err := NewBucket(token)
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("go-live/%d-%s/", time.Now().UnixNano(), randomSuffix())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := b.AbortStaleMultipartUploads(ctx, 0, prefix); err != nil {
			t.Errorf("cleanup aborts: %v", err)
		}
		if err := b.DeletePrefix(ctx, prefix); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return b, prefix
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func mustCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if !HasCode(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestLiveBucket(t *testing.T) {
	b, p := liveBucket(t, "UPSTASH_BLOB_PUBLIC_TOKEN")
	ctx := context.Background()

	put, err := b.Put(ctx, p+"hello world.txt", strings.NewReader("hello"), &PutOptions{ContentType: "text/plain", Metadata: map[string]string{"owner": "go"}, Cache: CacheImmutable})
	if err != nil {
		t.Fatal(err)
	}
	if put.Size != 5 || put.ETag == "" || !strings.HasPrefix(put.URL, "https://") || !strings.Contains(put.URL, "hello%20world.txt") {
		t.Fatalf("put: %+v", put)
	}

	// The public URL serves the bytes.
	res, err := http.Get(put.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("public url: %d %q", res.StatusCode, body)
	}

	got, err := b.Get(ctx, p+"hello world.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if string(data) != "hello" || got.ContentType != "text/plain" || got.Metadata["owner"] != "go" || got.ETag != put.ETag || got.Size != 5 {
		t.Fatalf("get: %+v %q", got.BlobInfo, data)
	}

	info, err := b.Info(ctx, p+"hello world.txt")
	if err != nil || info.Size != 5 || info.Metadata["owner"] != "go" {
		t.Fatalf("info: %+v %v", info, err)
	}
	if ok, err := b.Exists(ctx, p+"nope"); err != nil || ok {
		t.Fatalf("exists: %v %v", ok, err)
	}
	_, err = b.Info(ctx, p+"nope")
	mustCode(t, err, CodeNotFound)
	_, err = b.Get(ctx, p+"nope")
	mustCode(t, err, CodeNotFound)

	// Conditional writes.
	_, err = b.Put(ctx, p+"hello world.txt", strings.NewReader("x"), &PutOptions{NoOverwrite: true})
	mustCode(t, err, CodeAlreadyExists)
	var be *Error
	if !errorsAs(err, &be) || be.ETag != put.ETag || be.Size == nil || *be.Size != 5 {
		t.Fatalf("already_exists carries the existing object: %+v", be)
	}
	_, err = b.Put(ctx, p+"hello world.txt", strings.NewReader("x"), &PutOptions{IfUnchanged: `"nope"`})
	mustCode(t, err, CodeConflict)
	if _, err := b.Put(ctx, p+"hello world.txt", strings.NewReader("hello2"), &PutOptions{IfUnchanged: put.ETag, ContentType: "text/plain", Metadata: map[string]string{"owner": "go"}}); err != nil {
		t.Fatal(err)
	}

	// Copy keeps metadata, or replaces it.
	cp, err := b.Copy(ctx, p+"hello world.txt", p+"copy.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ci, _ := b.Info(ctx, cp.Path); ci.Metadata["owner"] != "go" || ci.ContentType != "text/plain" {
		t.Fatalf("copy kept: %+v", ci)
	}
	if _, err := b.Copy(ctx, p+"hello world.txt", p+"copy2.txt", &CopyOptions{ContentType: "text/markdown"}); err != nil {
		t.Fatal(err)
	}
	if ci, _ := b.Info(ctx, p+"copy2.txt"); ci.Metadata["owner"] != "go" || ci.ContentType != "text/markdown" {
		t.Fatalf("copy replace: %+v", ci)
	}
	if _, err := b.Move(ctx, p+"copy2.txt", p+"moved.txt", nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.Exists(ctx, p+"copy2.txt"); ok {
		t.Fatal("move left the source")
	}

	// List pages through.
	for i := 0; i < 3; i++ {
		if _, err := b.Put(ctx, fmt.Sprintf("%slist/%d & <x>.bin", p, i), bytes.NewReader([]byte{byte(i)}), nil); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	cursor := ""
	for {
		page, err := b.List(ctx, &ListOptions{Prefix: p + "list/", Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range page.Blobs {
			seen = append(seen, o.Path)
		}
		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}
	if len(seen) != 3 || seen[0] != p+"list/0 & <x>.bin" {
		t.Fatalf("list: %q", seen)
	}

	// UpdateJSON from nothing, then from what is there.
	type doc struct{ N int }
	for i := 1; i <= 2; i++ {
		if _, err := UpdateJSON(ctx, b, p+"doc.json", func(prev *doc) (doc, error) {
			if prev == nil {
				return doc{N: 1}, nil
			}
			return doc{N: prev.N + 1}, nil
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := b.Get(ctx, p+"doc.json")
	raw, _ := io.ReadAll(d.Body)
	d.Body.Close()
	if string(raw) != `{"N":2}` || d.ContentType != "application/json" {
		t.Fatalf("updateJSON: %s %s", raw, d.ContentType)
	}

	// Signed read and upload urls.
	read, err := b.SignedReadURL(ctx, p+"hello world.txt", &SignedReadURLOptions{DownloadAs: `report "q3".txt`})
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.Get(read.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "hello2" || !strings.Contains(res.Header.Get("Content-Disposition"), "attachment") || time.Until(read.ExpiresAt) > 6*time.Minute {
		t.Fatalf("signed read: %d %q %q", res.StatusCode, body, res.Header.Get("Content-Disposition"))
	}
	up, err := b.SignedUploadURL(ctx, p+"signed.bin", &SignedUploadURLOptions{ContentType: "application/pdf", Size: 3, Metadata: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("PUT", up.URL, bytes.NewReader([]byte("pdf")))
	for k, v := range up.Headers {
		if k != "content-length" {
			req.Header.Set(k, v)
		}
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("signed upload: %d", res.StatusCode)
	}
	if si, _ := b.Info(ctx, p+"signed.bin"); si == nil || si.ContentType != "application/pdf" || si.Metadata["k"] != "v" {
		t.Fatalf("signed upload stored: %+v", si)
	}

	// Content-type checks against the bytes.
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13}, []byte("IHDR")...)
	_, err = b.Put(ctx, p+"fake.jpg", bytes.NewReader(png), &PutOptions{ContentType: "image/jpeg", ContentTypes: []string{"image/*"}})
	mustCode(t, err, CodeContentTypeNotAllowed)
	if _, err := b.Put(ctx, p+"real.png", bytes.NewReader(png), &PutOptions{ContentType: "image/png", ContentTypes: []string{"image/*"}}); err != nil {
		t.Fatal(err)
	}

	// Streams: a declared size, a buffered one under MaxSize, and one over it.
	if r, err := b.Put(ctx, p+"stream.bin", io.MultiReader(strings.NewReader("ab"), strings.NewReader("cd")), &PutOptions{Size: 4}); err != nil || r.Size != 4 {
		t.Fatalf("stream with size: %+v %v", r, err)
	}
	if r, err := b.Put(ctx, p+"stream2.bin", io.MultiReader(strings.NewReader("abc")), &PutOptions{MaxSize: 10}); err != nil || r.Size != 3 {
		t.Fatalf("stream with maxSize: %+v %v", r, err)
	}
	_, err = b.Put(ctx, p+"stream3.bin", io.MultiReader(strings.NewReader("abcdef")), &PutOptions{MaxSize: 3})
	mustCode(t, err, CodeTooLarge)
	_, err = b.Put(ctx, p+"stream4.bin", io.MultiReader(strings.NewReader("abcdef")), &PutOptions{Size: 3})
	mustCode(t, err, CodeInvalidInput)
	if ok, _ := b.Exists(ctx, p+"stream4.bin"); ok {
		t.Fatal("an overlong stream was stored")
	}
	_, err = b.Put(ctx, p+"stream5.bin", io.MultiReader(strings.NewReader("ab")), &PutOptions{Size: 3})
	mustCode(t, err, CodeInvalidInput)
	_, err = b.Put(ctx, p+"stream6.bin", io.MultiReader(strings.NewReader("ab")), nil)
	mustCode(t, err, CodeLengthRequired)
	if r, err := b.Put(ctx, p+"empty.bin", nil, nil); err != nil || r.Size != 0 {
		t.Fatalf("empty: %+v %v", r, err)
	}

	// Delete, DeleteMany, and the prefix guard.
	if err := b.Delete(ctx, p+"moved.txt"); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, p+"moved.txt"); err != nil {
		t.Fatal("deleting a missing blob is success:", err)
	}
	if err := b.DeleteMany(ctx, []string{p + "copy.txt", p + "signed.bin", p + "never-there"}); err != nil {
		t.Fatal(err)
	}
	mustCode(t, b.DeletePrefix(ctx, ""), CodeInvalidInput)
	if err := b.DeletePrefix(ctx, p+"list/"); err != nil {
		t.Fatal(err)
	}
	if page, _ := b.List(ctx, &ListOptions{Prefix: p + "list/"}); len(page.Blobs) != 0 {
		t.Fatalf("prefix delete left %d", len(page.Blobs))
	}

	s3, err := b.S3(ctx)
	if err != nil || s3.AccessKeyID == "" || !strings.HasSuffix(s3.Endpoint, ".r2.cloudflarestorage.com") || time.Until(s3.Expires) <= 0 {
		t.Fatalf("s3: %+v %v", s3, err)
	}
}

func TestLiveMultipart(t *testing.T) {
	b, p := liveBucket(t, "UPSTASH_BLOB_PUBLIC_TOKEN")
	ctx := context.Background()
	data := randomBytes(int(17 * MiB))

	// A seekable body over the threshold goes up in four parts.
	r, err := b.Put(ctx, p+"big.bin", bytes.NewReader(data), &PutOptions{Metadata: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.ETag, "-") {
		t.Fatalf("expected a multipart etag, got %s", r.ETag)
	}
	got, err := b.Get(ctx, p+"big.bin")
	if err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if !bytes.Equal(back, data) || got.Metadata["k"] != "v" {
		t.Fatalf("multipart round trip: %d bytes, %v", len(back), got.Metadata)
	}

	// A stream of a declared size goes up in parts too, and an overlong one is refused and aborted.
	if _, err := b.Put(ctx, p+"stream.bin", io.MultiReader(bytes.NewReader(data[:11*MiB])), &PutOptions{Size: 11 * MiB, Multipart: MultipartAlways}); err != nil {
		t.Fatal(err)
	}
	_, err = b.Put(ctx, p+"long.bin", io.MultiReader(bytes.NewReader(data)), &PutOptions{Size: 6 * MiB, Multipart: MultipartAlways})
	mustCode(t, err, CodeInvalidInput)
	_, err = b.Put(ctx, p+"short.bin", io.MultiReader(bytes.NewReader(data[:6*MiB])), &PutOptions{Size: 11 * MiB, Multipart: MultipartAlways})
	mustCode(t, err, CodeInvalidInput)
	uploads, err := b.ListMultipartUploads(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(uploads) != 0 {
		t.Fatalf("failed uploads were left behind: %+v", uploads)
	}
	if ok, _ := b.Exists(ctx, p+"long.bin"); ok {
		t.Fatal("an overlong multipart stream was stored")
	}

	// A conditional write never goes multipart.
	_, err = b.Put(ctx, p+"cond.bin", bytes.NewReader(data), &PutOptions{NoOverwrite: true, Multipart: MultipartAlways})
	mustCode(t, err, CodeInvalidInput)
}

func TestLivePrivate(t *testing.T) {
	b, p := liveBucket(t, "UPSTASH_BLOB_PRIVATE_TOKEN")
	ctx := context.Background()
	r, err := b.Put(ctx, p+"secret.txt", strings.NewReader("s"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.URL != "" || r.VersionedURL != "" {
		t.Fatalf("a private blob has no url: %+v", r)
	}
	if u, err := b.PublicURL(ctx, p+"secret.txt"); err != nil || u != "" {
		t.Fatalf("public url on private: %q %v", u, err)
	}
	h, err := b.r2.head(ctx, p+"secret.txt")
	if err != nil || h.cacheControl != "private, max-age=3600" {
		t.Fatalf("private cache-control: %+v %v", h, err)
	}
	read, err := b.SignedReadURL(ctx, p+"secret.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(read.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "s" {
		t.Fatalf("signed read on private: %d %q", res.StatusCode, body)
	}
}

// browser plays the part of @upstash/blob/browser against a handler: begin, PUT every part
// straight to storage, end.
type browser struct {
	t      *testing.T
	url    string
	header http.Header
}

func (c *browser) post(body map[string]any) (int, map[string]any) {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.header {
		req.Header[k] = v
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (c *browser) putParts(data []byte, partSize int, parts []any) []map[string]any {
	c.t.Helper()
	var landed []map[string]any
	for _, raw := range parts {
		part := raw.(map[string]any)
		n := int(part["n"].(float64))
		start := (n - 1) * partSize
		end := min(start+partSize, len(data))
		req, _ := http.NewRequest("PUT", part["url"].(string), bytes.NewReader(data[start:end]))
		if h, ok := part["headers"].(map[string]any); ok {
			for k, v := range h {
				req.Header.Set(k, v.(string))
			}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			c.t.Fatal(err)
		}
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			c.t.Fatalf("part %d: %d %s", n, res.StatusCode, msg)
		}
		landed = append(landed, map[string]any{"n": n, "etag": res.Header.Get("ETag")})
	}
	return landed
}

func (c *browser) upload(name, typ string, data []byte, input any) (int, map[string]any) {
	c.t.Helper()
	head := data
	if len(head) > sniffBytes {
		head = head[:sniffBytes]
	}
	begin := map[string]any{"phase": "begin", "protocol": 1, "file": map[string]any{"name": name, "type": typ, "size": len(data)}, "head": b64(head)}
	if input != nil {
		begin["input"] = input
	}
	status, out := c.post(begin)
	if status != 200 {
		return status, out
	}
	plan := out["upload"].(map[string]any)
	token := out["completionToken"].(string)
	partSize := int(plan["partSize"].(float64))
	parts := plan["parts"].([]any)
	landed := c.putParts(data, partSize, parts)
	// More than one batch: ask for the rest the way the client does.
	for len(landed) < (len(data)+partSize-1)/partSize {
		status, more := c.post(map[string]any{"phase": "parts", "completionToken": token, "from": len(landed) + 1})
		if status != 200 {
			c.t.Fatalf("parts: %d %v", status, more)
		}
		landed = append(landed, c.putParts(data, partSize, more["parts"].([]any))...)
	}
	return c.post(map[string]any{"phase": "end", "completionToken": token, "parts": landed})
}

func TestLiveUploadHandler(t *testing.T) {
	b, p := liveBucket(t, "UPSTASH_BLOB_PUBLIC_TOKEN")
	type user struct{ ID string }
	completed := map[string]UploadCompleteArgs[*user]{}
	h, err := NewUploadHandler(UploadHandlerOptions[*user]{
		Bucket: b,
		Context: func(r *http.Request) (*user, error) {
			id := r.Header.Get("X-User")
			if id == "" {
				return nil, newErr(CodeUnauthorized, "sign in first")
			}
			return &user{ID: id}, nil
		},
		Owner: func(u *user) string { return u.ID },
		OnBeforeUpload: func(a BeforeUploadArgs[*user]) (BeforeUploadResult, error) {
			return BeforeUploadResult{Path: UniquePath(p + a.Ctx.ID + "/" + a.File.Name), Metadata: map[string]string{"user": a.Ctx.ID}, State: map[string]string{"route": a.Route}}, nil
		},
		OnUploadComplete: func(a UploadCompleteArgs[*user]) (any, error) {
			if a.File.Name == "refuse.txt" {
				return nil, newErr(CodeForbidden, "no thanks")
			}
			completed[a.Path] = a
			return map[string]string{"url": a.URL}, nil
		},
		Routes: map[string]UploadRoute[*user]{
			"avatar": {ContentTypes: []string{"image/*"}, MaxSize: 5 * MB},
			"file":   {},
			"thread": {Input: JSONInput[struct{ ThreadID string }](), OnBeforeUpload: func(a BeforeUploadArgs[*user]) (BeforeUploadResult, error) {
				in := a.Input.(struct{ ThreadID string })
				return BeforeUploadResult{Path: p + "threads/" + in.ThreadID + "/" + a.File.Name}, nil
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	alice := &browser{t: t, url: srv.URL + "?route=file", header: http.Header{"X-User": {"alice"}}}

	// GET serves the constraints, cacheable.
	res, err := http.Get(srv.URL + "?route=avatar")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(res.Body).Decode(&doc)
	res.Body.Close()
	if doc["protocol"] != float64(1) || doc["constraints"].(map[string]any)["maxSize"] != float64(5*MB) || res.Header.Get("ETag") == "" {
		t.Fatalf("constraints: %v", doc)
	}

	// A single PUT.
	status, out := alice.upload("note.txt", "text/plain", []byte("hello"), nil)
	if status != 200 || out["protocol"] != float64(1) {
		t.Fatalf("single: %d %v", status, out)
	}
	blob := out["blob"].(map[string]any)
	path := blob["path"].(string)
	if blob["size"] != float64(5) || out["data"].(map[string]any)["url"] != blob["url"] || !strings.HasPrefix(path, p+"alice/note-") {
		t.Fatalf("single answer: %v", out)
	}
	c := completed[path]
	if c.Metadata["user"] != "alice" || c.MultipartUploadID != "" || string(c.State) != `{"route":"file"}` || c.Ctx.ID != "alice" {
		t.Fatalf("complete args: %+v", c)
	}
	if info, _ := b.Info(context.Background(), path); info == nil || info.Metadata[uploadMarker] == "" {
		t.Fatalf("the single PUT carries its marker: %+v", info)
	}

	// A multipart upload, over two batches of signed parts (17 parts of 5 MiB).
	big := randomBytes(int(81 * MiB))
	status, out = alice.upload("big.bin", "application/octet-stream", big, nil)
	if status != 200 {
		t.Fatalf("multipart: %d %v", status, out)
	}
	path = out["blob"].(map[string]any)["path"].(string)
	if c := completed[path]; c.MultipartUploadID == "" || c.Size != int64(len(big)) {
		t.Fatalf("multipart complete args: %+v", c)
	}

	// Refused in OnUploadComplete: the object is deleted again.
	status, out = alice.upload("refuse.txt", "text/plain", []byte("x"), nil)
	if status != 403 || out["code"] != "forbidden" || out["message"] != "No thanks" {
		t.Fatalf("refusal: %d %v", status, out)
	}
	if page, _ := b.List(context.Background(), &ListOptions{Prefix: p + "alice/refuse"}); len(page.Blobs) != 0 {
		t.Fatal("a refused upload was left stored")
	}

	// Constraints, the session check, and owner binding.
	avatar := &browser{t: t, url: srv.URL + "?route=avatar", header: alice.header}
	status, out = avatar.upload("x.pdf", "application/pdf", []byte("%PDF-1.4"), nil)
	if status != 400 || out["code"] != "content_type_not_allowed" {
		t.Fatalf("type refusal: %d %v", status, out)
	}
	anon := &browser{t: t, url: srv.URL + "?route=file"}
	status, out = anon.upload("a.txt", "text/plain", []byte("a"), nil)
	if status != 401 || out["code"] != "unauthorized" {
		t.Fatalf("no session: %d %v", status, out)
	}
	status, out = alice.post(map[string]any{"phase": "begin", "file": map[string]any{"name": "m.bin", "type": "application/octet-stream", "size": 6 * MiB}})
	if status != 200 {
		t.Fatalf("begin: %d %v", status, out)
	}
	token := out["completionToken"].(string)
	bob := &browser{t: t, url: alice.url, header: http.Header{"X-User": {"bob"}}}
	status, out = bob.post(map[string]any{"phase": "end", "completionToken": token, "parts": []any{}})
	if status != 403 || out["code"] != "forbidden" {
		t.Fatalf("another user's token: %d %v", status, out)
	}
	thread := &browser{t: t, url: srv.URL + "?route=thread", header: alice.header}
	status, out = thread.upload("t.txt", "text/plain", []byte("t"), map[string]any{"ThreadID": "42"})
	if status != 200 || out["blob"].(map[string]any)["path"] != p+"threads/42/t.txt" {
		t.Fatalf("input: %d %v", status, out)
	}
	status, out = alice.upload("i.txt", "text/plain", []byte("i"), map[string]any{"x": 1})
	if status != 400 || out["code"] != "invalid_input" {
		t.Fatalf("input on a route without one: %d %v", status, out)
	}

	// Cancel aborts the multipart started above.
	status, out = alice.post(map[string]any{"phase": "cancel", "completionToken": token})
	if status != 200 || out["ok"] != true {
		t.Fatalf("cancel: %d %v", status, out)
	}
	if uploads, _ := b.ListMultipartUploads(context.Background(), p); len(uploads) != 0 {
		t.Fatalf("cancel left %d uploads", len(uploads))
	}

	// Unknown routes are 404s.
	status, out = (&browser{t: t, url: srv.URL + "?route=nope", header: alice.header}).post(map[string]any{"phase": "begin"})
	if status != 404 || out["code"] != "not_found" {
		t.Fatalf("unknown route: %d %v", status, out)
	}
}

// Keys XML reads back differently, or cannot carry at all, still list and delete as written.
func TestLiveOddKeys(t *testing.T) {
	b, p := liveBucket(t, "UPSTASH_BLOB_PUBLIC_TOKEN")
	ctx := context.Background()
	keys := []string{p + "a\x01b", p + "c\rd", p + "e\r\nf", p + "g&<h>'\"", p + "tab\tx"}
	for _, k := range keys {
		if _, err := b.Put(ctx, k, strings.NewReader("x"), nil); err != nil {
			t.Fatalf("put %q: %v", k, err)
		}
	}
	page, err := b.List(ctx, &ListOptions{Prefix: p})
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, o := range page.Blobs {
		listed[o.Path] = true
	}
	for _, k := range keys {
		if !listed[k] {
			t.Fatalf("%q not listed as written: %q", k, page.Blobs)
		}
	}
	if err := b.DeleteMany(ctx, keys[1:]); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys[1:] {
		if ok, err := b.Exists(ctx, k); err != nil || ok {
			t.Fatalf("%q survived DeleteMany: %v %v", k, ok, err)
		}
	}
	if err := b.DeletePrefix(ctx, p); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.Exists(ctx, keys[0]); err != nil || ok {
		t.Fatalf("%q survived DeletePrefix: %v %v", keys[0], ok, err)
	}
}
