package blob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type statusErr struct{ code int }

func (e statusErr) Error() string   { return "teapot says no" }
func (e statusErr) StatusCode() int { return e.code }

func serve(h http.Handler, method, target string, body any, headers ...string) (int, map[string]any, http.Header) {
	var r io.Reader
	if s, ok := body.(string); ok {
		r = strings.NewReader(s)
	} else if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, r)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func begin(name, typ string, size int64) map[string]any {
	return map[string]any{"phase": "begin", "protocol": 1, "file": map[string]any{"name": name, "type": typ, "size": size}}
}

func TestHandlerProtocolAndRouting(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	var logs bytes.Buffer
	h, err := NewUploadHandler(UploadHandlerOptions[struct{}]{
		Bucket:       b,
		ContentTypes: []string{"image/png"},
		MaxSize:      5 * MB,
		Logger:       slog.New(slog.NewTextHandler(&logs, nil)),
		OnBeforeUpload: func(a BeforeUploadArgs[struct{}]) (BeforeUploadResult, error) {
			switch a.File.Name {
			case "teapot.png":
				return BeforeUploadResult{}, statusErr{418}
			case "bug.png":
				return BeforeUploadResult{}, errors.New("database is down: password=hunter2")
			case "dots.png":
				return BeforeUploadResult{Path: "u/../x.png"}, nil
			case "reserved.png":
				return BeforeUploadResult{Path: "u/r.png", Metadata: map[string]string{"upstash-upload": "x"}}, nil
			case "wider.png":
				return BeforeUploadResult{Path: "u/w.png", MaxSize: 6 * MB}, nil
			case "narrow.png":
				return BeforeUploadResult{Path: "u/n.png", MaxSize: 10}, nil
			}
			return BeforeUploadResult{Path: "u/" + a.File.Name, State: map[string]int{"row": 7}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	status, out, hdr := serve(h, "GET", "/api/upload", nil)
	if status != 200 || out["protocol"] != float64(1) || hdr.Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("GET: %d %v", status, out)
	}
	if status, _, _ := serve(h, "GET", "/api/upload", nil, "If-None-Match", hdr.Get("ETag")); status != 304 {
		t.Fatalf("revalidated GET: %d", status)
	}
	if status, _, hdr := serve(h, "PUT", "/api/upload", nil); status != 405 || hdr.Get("Allow") != "GET, POST" {
		t.Fatalf("PUT: %d", status)
	}
	// A handler with no routes refuses a name: that client was bound to another handler.
	if status, out, _ := serve(h, "POST", "/api/upload?route=avatar", begin("a.png", "image/png", 1)); status != 404 || out["code"] != "not_found" {
		t.Fatalf("named on a sole route: %d %v", status, out)
	}
	for _, body := range []any{"not json", "[]", map[string]any{"phase": 1}, map[string]any{"phase": "nope"}, map[string]any{"phase": "begin", "file": map[string]any{"name": "a", "size": 1.5}}} {
		if status, out, _ := serve(h, "POST", "/api/upload", body); status != 400 || out["code"] != "invalid_input" || out["protocol"] != nil {
			t.Errorf("%v: %d %v", body, status, out)
		}
	}
	if status, out, _ := serve(h, "POST", "/api/upload", strings.Repeat(" ", 2<<20)); status != 413 {
		t.Errorf("a huge body: %d %v", status, out)
	}

	status, out, _ = serve(h, "POST", "/api/upload", begin("a.png", "IMAGE/PNG; x=y", 100))
	if status != 200 || out["protocol"] != float64(1) || out["path"] != "u/a.png" {
		t.Fatalf("begin: %d %v", status, out)
	}
	plan := out["upload"].(map[string]any)
	part := plan["parts"].([]any)[0].(map[string]any)
	ph := part["headers"].(map[string]any)
	if plan["multipart"] != false || plan["partSize"] != float64(100) || ph["content-type"] != "image/png" || ph[uploadMarkerHeader] == nil {
		t.Fatalf("single PUT plan: %v", plan)
	}

	cases := []struct {
		name   string
		status int
		code   string
	}{
		{"teapot.png", 418, "request_failed"},
		{"bug.png", 500, "request_failed"},
		{"dots.png", 400, "invalid_input"},
		{"reserved.png", 400, "invalid_input"},
		{"wider.png", 500, "request_failed"},
		{"narrow.png", 413, "too_large"},
	}
	for _, c := range cases {
		status, out, _ := serve(h, "POST", "/api/upload", begin(c.name, "image/png", 100))
		if status != c.status || out["code"] != c.code {
			t.Errorf("%s: %d %v", c.name, status, out)
		}
	}
	if strings.Contains(logs.String(), "hunter2") == false {
		t.Error("an app bug is logged for whoever runs the server")
	}
	if _, out, _ := serve(h, "POST", "/api/upload", begin("bug.png", "image/png", 100)); strings.Contains(out["message"].(string), "hunter2") {
		t.Error("an app bug's message reached the browser")
	}
	if status, out, _ := serve(h, "POST", "/api/upload", begin("big.png", "image/png", 6*MB)); status != 413 || out["code"] != "too_large" {
		t.Errorf("over MaxSize: %d %v", status, out)
	}
	if status, out, _ := serve(h, "POST", "/api/upload", begin("e.png", "image/png", 0)); status != 400 || out["code"] != "empty_body" {
		t.Errorf("empty: %d %v", status, out)
	}
	pdf := begin("x.png", "image/png", 100)
	pdf["head"] = b64([]byte("%PDF-1.7"))
	if status, out, _ := serve(h, "POST", "/api/upload", pdf); status != 400 || out["code"] != "content_type_not_allowed" {
		t.Errorf("lying head: %d %v", status, out)
	}
}

func TestHandlerLifecycle(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	type user struct{ ID string }
	var completes int
	var lastState string
	opts := UploadHandlerOptions[user]{
		Bucket:  b,
		Context: func(r *http.Request) (user, error) { return user{ID: r.Header.Get("X-User")}, nil },
		Owner:   func(u user) string { return u.ID },
		OnBeforeUpload: func(a BeforeUploadArgs[user]) (BeforeUploadResult, error) {
			return BeforeUploadResult{Path: "u/" + a.File.Name, State: map[string]string{"by": a.Ctx.ID}}, nil
		},
		OnUploadComplete: func(a UploadCompleteArgs[user]) (any, error) {
			completes++
			lastState = string(a.State)
			if a.File.Name == "no.bin" {
				return nil, NewError(CodeForbidden, ErrorOptions{Message: "not today"})
			}
			return map[string]any{"ok": a.Ctx.ID}, nil
		},
		OnError: func(a UploadErrorArgs[user]) error {
			if errors.Is(a.Err, ErrForbidden) && a.Path == "u/mapped.bin" {
				return NewError(CodeConflict, ErrorOptions{Message: "mapped"})
			}
			return nil
		},
		Routes: map[string]UploadRoute[user]{"file": {}, "big": {Multipart: MultipartAlways}},
	}
	h, err := NewUploadHandler(opts)
	if err != nil {
		t.Fatal(err)
	}
	post := func(route string, body any, user string) (int, map[string]any) {
		status, out, _ := serve(h, "POST", "/api/upload?route="+route, body, "X-User", user)
		return status, out
	}
	putParts := func(plan map[string]any, data []byte) []any {
		var landed []any
		partSize := int(plan["partSize"].(float64))
		for _, raw := range plan["parts"].([]any) {
			p := raw.(map[string]any)
			n := int(p["n"].(float64))
			end := min(n*partSize, len(data))
			req, _ := http.NewRequest("PUT", p["url"].(string), bytes.NewReader(data[(n-1)*partSize:end]))
			if hs, ok := p["headers"].(map[string]any); ok {
				for k, v := range hs {
					req.Header.Set(k, v.(string))
				}
			}
			res, err := f.client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			landed = append(landed, map[string]any{"n": n, "etag": res.Header.Get("ETag")})
		}
		return landed
	}

	// No owner is a 401 before anything else happens.
	if status, out := post("file", begin("a.bin", "", 3), ""); status != 401 || out["code"] != "unauthorized" {
		t.Fatalf("no owner: %d %v", status, out)
	}

	// A single PUT, ended twice: the second is idempotent.
	status, out := post("file", begin("a.bin", "", 3), "alice")
	if status != 200 {
		t.Fatalf("begin: %d %v", status, out)
	}
	token := out["completionToken"].(string)
	landed := putParts(out["upload"].(map[string]any), []byte("abc"))
	end := map[string]any{"phase": "end", "completionToken": token, "parts": landed}
	if status, out := post("file", end, "bob"); status != 403 || out["message"] != "This upload belongs to another user" {
		t.Fatalf("bob ends alice's upload: %d %v", status, out)
	}
	if status, out := post("big", end, "alice"); status != 403 {
		t.Fatalf("a token from another route: %d %v", status, out)
	}
	for i := 0; i < 2; i++ {
		status, out = post("file", end, "alice")
		blob, _ := out["blob"].(map[string]any)
		if status != 200 || blob["size"] != float64(3) || blob["contentType"] != "application/octet-stream" || out["data"].(map[string]any)["ok"] != "alice" || !strings.HasSuffix(blob["uploadedAt"].(string), ".000Z") {
			t.Fatalf("end %d: %d %v", i, status, out)
		}
	}
	if completes != 2 || lastState != `{"by":"alice"}` {
		t.Fatalf("completes %d, state %s", completes, lastState)
	}

	// A path someone else overwrote since is not this upload's: no marker, never landed.
	f.objects["u/a.bin"] = &fakeObject{data: []byte("xyz"), headers: http.Header{}, etag: `"other"`}
	if status, out := post("file", end, "alice"); status != 404 || out["code"] != "not_found" {
		t.Fatalf("someone else's object: %d %v", status, out)
	}
	if f.objects["u/a.bin"] == nil {
		t.Fatal("someone else's object was deleted")
	}

	// Refused in OnUploadComplete: deleted; OnError can remap.
	status, out = post("file", begin("no.bin", "", 2), "alice")
	if status != 200 {
		t.Fatalf("begin: %d %v", status, out)
	}
	putParts(out["upload"].(map[string]any), []byte("no"))
	status, out = post("file", map[string]any{"phase": "end", "completionToken": out["completionToken"], "parts": []any{map[string]any{"n": 1, "etag": "x"}}}, "alice")
	if status != 403 || out["message"] != "Not today" || f.objects["u/no.bin"] != nil {
		t.Fatalf("refusal: %d %v", status, out)
	}

	// Multipart: parts in batches, a size check, and cancel.
	data := bytes.Repeat([]byte("m"), int(6*MiB))
	status, out = post("big", begin("m.bin", "application/octet-stream", int64(len(data))), "alice")
	plan := out["upload"].(map[string]any)
	if status != 200 || plan["multipart"] != true || len(plan["parts"].([]any)) != 2 {
		t.Fatalf("multipart begin: %d %v", status, out)
	}
	mtoken := out["completionToken"].(string)
	putParts(plan, data)
	status, out = post("big", map[string]any{"phase": "parts", "completionToken": mtoken, "from": 2}, "alice")
	mlanded := out["landed"]
	if status != 200 || len(out["landed"].([]any)) != 2 || len(out["parts"].([]any)) != 1 || out["parts"].([]any)[0].(map[string]any)["n"] != float64(2) {
		t.Fatalf("parts: %d %v", status, out)
	}
	// End without a parts list reads them back from storage.
	status, out = post("big", map[string]any{"phase": "end", "completionToken": mtoken}, "alice")
	if status != 200 || out["blob"].(map[string]any)["etag"] != `"mp-2"` {
		t.Fatalf("multipart end: %d %v", status, out)
	}
	// A retried end after the upload completed, carrying its parts the way the client does.
	if status, out := post("big", map[string]any{"phase": "end", "completionToken": mtoken, "parts": mlanded}, "alice"); status != 200 {
		t.Fatalf("retried multipart end: %d %v", status, out)
	}

	status, out = post("big", begin("c.bin", "", int64(len(data))), "alice")
	if status != 200 {
		t.Fatalf("begin: %d %v", status, out)
	}
	ctoken := out["completionToken"].(string)
	if len(f.uploads) != 1 {
		t.Fatalf("%d uploads open", len(f.uploads))
	}
	if status, out := post("big", map[string]any{"phase": "cancel", "completionToken": ctoken}, "alice"); status != 200 || out["ok"] != true || out["protocol"] != float64(1) {
		t.Fatalf("cancel: %d %v", status, out)
	}
	if len(f.uploads) != 0 {
		t.Fatal("cancel left the multipart")
	}

	// A declared size the bytes do not match is refused and deleted.
	status, out = post("file", begin("short.bin", "", 5), "alice")
	if status != 200 {
		t.Fatalf("begin: %d %v", status, out)
	}
	putParts(out["upload"].(map[string]any), []byte("abcde"))
	f.objects["u/short.bin"].data = []byte("ab")
	status, out = post("file", map[string]any{"phase": "end", "completionToken": out["completionToken"], "parts": []any{map[string]any{"n": 1, "etag": "x"}}}, "alice")
	if status != 403 || out["code"] != "signature_mismatch" || f.objects["u/short.bin"] != nil {
		t.Fatalf("size mismatch: %d %v", status, out)
	}

	// A tampered token.
	if status, out := post("file", map[string]any{"phase": "end", "completionToken": token[:len(token)-3] + "abc"}, "alice"); status != 403 {
		t.Fatalf("tampered: %d %v", status, out)
	}
}

func TestHandlerConfigErrors(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	before := func(a BeforeUploadArgs[int]) (BeforeUploadResult, error) { return BeforeUploadResult{Path: "x"}, nil }
	for name, opts := range map[string]UploadHandlerOptions[int]{
		"owner without context": {Bucket: b, OnBeforeUpload: before, Owner: func(int) string { return "" }},
		"no before":             {Bucket: b},
		"empty routes":          {Bucket: b, OnBeforeUpload: before, Routes: map[string]UploadRoute[int]{}},
		"bad route name":        {Bucket: b, OnBeforeUpload: before, Routes: map[string]UploadRoute[int]{"a b": {}}},
		"bad pattern":           {Bucket: b, OnBeforeUpload: before, ContentTypes: []string{"*/*"}},
	} {
		if _, err := NewUploadHandler(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	t.Setenv(TokenEnv, "")
	if _, err := NewUploadHandler(UploadHandlerOptions[int]{OnBeforeUpload: before}); err == nil {
		t.Error("no bucket and no env accepted")
	}
	// Route constraints replace per key, and clear.
	h, err := NewUploadHandler(UploadHandlerOptions[int]{
		Bucket: b, OnBeforeUpload: before, ContentTypes: []string{"image/png"}, MaxSize: 10,
		Routes: map[string]UploadRoute[int]{"any": {ContentTypes: []string{}, MaxSize: NoLimit}, "pdf": {ContentTypes: []string{"application/pdf"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := serve(h, "GET", "/?route=any", nil); len(out["constraints"].(map[string]any)) != 0 {
		t.Fatalf("cleared: %v", out)
	}
	if _, out, _ := serve(h, "GET", "/?route=pdf", nil); out["constraints"].(map[string]any)["maxSize"] != float64(10) {
		t.Fatalf("inherited: %v", out)
	}
}

func TestHandlerRound1Regressions(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	var logs bytes.Buffer
	h, err := NewUploadHandler(UploadHandlerOptions[int]{
		Bucket:  b,
		MaxSize: 10,
		Logger:  slog.New(slog.NewTextHandler(&logs, nil)),
		OnBeforeUpload: func(a BeforeUploadArgs[int]) (BeforeUploadResult, error) {
			if a.File.Name == "hand.bin" {
				return BeforeUploadResult{}, &Error{Code: CodeForbidden}
			}
			return BeforeUploadResult{Path: "u/" + a.File.Name}, nil
		},
		OnUploadComplete: func(a UploadCompleteArgs[int]) (any, error) { return math.NaN(), nil },
		OnError:          func(a UploadErrorArgs[int]) error { return errors.New("logged it") },
	})
	if err != nil {
		t.Fatal(err)
	}
	// A hand-built *Error with no Status answers with its code's.
	if status, out, _ := serve(h, "POST", "/", begin("hand.bin", "", 1)); status != 403 || out["code"] != "forbidden" || out["message"] != "Forbidden" || out["status"] != float64(403) {
		t.Fatalf("hand-built error: %d %v", status, out)
	}
	// OnError returning a plain error leaves the answer alone.
	if status, out, _ := serve(h, "POST", "/", begin("big.bin", "", 11)); status != 413 || out["code"] != "too_large" {
		t.Fatalf("OnError plain error: %d %v", status, out)
	}
	// Data that cannot be encoded is a 500, never a 200 with an error body.
	_, out, _ := serve(h, "POST", "/", begin("nan.bin", "", 1))
	part := out["upload"].(map[string]any)["parts"].([]any)[0].(map[string]any)
	req, _ := http.NewRequest("PUT", part["url"].(string), strings.NewReader("x"))
	for k, v := range part["headers"].(map[string]any) {
		req.Header.Set(k, v.(string))
	}
	res, _ := f.client().Do(req)
	res.Body.Close()
	status, out, _ := serve(h, "POST", "/", map[string]any{"phase": "end", "completionToken": out["completionToken"], "parts": []any{map[string]any{"n": 1, "etag": "x"}}})
	if status != 500 || out["code"] != "request_failed" || !strings.Contains(logs.String(), "could not be encoded") {
		t.Fatalf("unencodable data: %d %v", status, out)
	}
}

func TestHandlerRound2Regressions(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	before := func(a BeforeUploadArgs[int]) (BeforeUploadResult, error) {
		return BeforeUploadResult{Path: "u/" + a.File.Name}, nil
	}
	if _, err := NewUploadHandler(UploadHandlerOptions[int]{Bucket: b, OnBeforeUpload: before, Routes: map[string]UploadRoute[int]{"a": {MaxSize: -5}}}); err == nil {
		t.Fatal("a negative route MaxSize other than NoLimit was accepted")
	}
	completed := false
	h, _ := NewUploadHandler(UploadHandlerOptions[int]{Bucket: b, OnBeforeUpload: before, Multipart: MultipartAlways,
		OnUploadComplete: func(a UploadCompleteArgs[int]) (any, error) { completed = true; return nil, nil }})
	_, out, _ := serve(h, "POST", "/", begin("m.bin", "", 10))
	token := out["completionToken"]
	part := out["upload"].(map[string]any)["parts"].([]any)[0].(map[string]any)
	req, _ := http.NewRequest("PUT", part["url"].(string), strings.NewReader("0123456789"))
	res, _ := f.client().Do(req)
	res.Body.Close()
	// The browser left: the request context is already cancelled, and 'end' still finishes.
	raw, _ := json.Marshal(map[string]any{"phase": "end", "completionToken": token, "parts": []any{map[string]any{"n": 1, "etag": res.Header.Get("ETag")}}})
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", bytes.NewReader(raw)).WithContext(gone))
	if w.Code != 200 || !completed || f.objects["u/m.bin"] == nil {
		t.Fatalf("end after the browser left: %d %s", w.Code, w.Body)
	}
}

type nilStatus struct{ code int }

func (e *nilStatus) Error() string   { return "nil status" }
func (e *nilStatus) StatusCode() int { return e.code }

func TestHandlerRound3Regressions(t *testing.T) {
	f := newFake()
	b := f.bucket(t)
	var logs bytes.Buffer
	h, _ := NewUploadHandler(UploadHandlerOptions[int]{
		Bucket: b,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		OnBeforeUpload: func(a BeforeUploadArgs[int]) (BeforeUploadResult, error) {
			if a.File.Name == "status.bin" {
				var e *nilStatus
				return BeforeUploadResult{}, e
			}
			var e *Error
			return BeforeUploadResult{}, e
		},
		OnError: func(a UploadErrorArgs[int]) error { var e *Error; return e },
	})
	// A typed-nil *Error, or a typed-nil error with a StatusCode method, is the app's bug: a 500.
	for _, name := range []string{"nil.bin", "status.bin"} {
		if status, out, _ := serve(h, "POST", "/", begin(name, "", 1)); status != 500 || out["code"] != "request_failed" {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	var e *Error
	if errors.Is(e, ErrNotFound) || errors.Is(ErrNotFound, e) || HasCode(e, CodeNotFound) {
		t.Fatal("a nil *Error matched")
	}
}
