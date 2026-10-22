package blob

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fake is the Upstash agent and an S3-shaped store behind one http.RoundTripper, so the SDK's real
// URLs, signing and parsing run without the network. hook runs first and may answer any request.
type fake struct {
	mu      sync.Mutex
	objects map[string]*fakeObject
	uploads map[string]*fakeUpload
	nextID  int
	mints   atomic.Int32
	calls   []string
	bodies  map[string][][]byte
	inPart  atomic.Int32
	maxPart atomic.Int32
	// hook answers a request before the store does; nil to fall through.
	hook       func(req *http.Request, body []byte) *http.Response
	visibility string
	partDelay  time.Duration
}

type fakeObject struct {
	data    []byte
	headers http.Header
	etag    string
}

type fakeUpload struct {
	path    string
	headers http.Header
	parts   map[int][]byte
	started time.Time
}

const fakeEndpoint = "https://acct.r2.cloudflarestorage.com"

func newFake() *fake {
	return &fake{objects: map[string]*fakeObject{}, uploads: map[string]*fakeUpload{}, bodies: map[string][][]byte{}, visibility: "public"}
}

func respond(status int, body string, headers ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Set(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func (f *fake) client() *http.Client { return &http.Client{Transport: f} }

func (f *fake) bucket(t *testing.T, opts ...func(*Options)) *Bucket {
	t.Helper()
	resetCredentialCaches()
	o := Options{Token: encodeToken("bucket-1", "pw-secret", "abc123", 0), HTTPClient: f.client(), DisableTelemetry: true}
	for _, fn := range opts {
		fn(&o)
	}
	b, err := NewBucketWith(o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fake) called(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fake) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		if req.ContentLength >= 0 && int64(len(body)) != req.ContentLength && req.Method != "POST" {
			return nil, fmt.Errorf("http: ContentLength=%d with Body length %d", req.ContentLength, len(body))
		}
	}
	key := req.Method + " " + req.URL.Host + req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		key += "?" + req.URL.RawQuery
	}
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.bodies[key] = append(f.bodies[key], body)
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		if res := hook(req, body); res != nil {
			res.Request = req
			return res, nil
		}
	}
	var res *http.Response
	switch {
	case req.URL.Host == "blob.upstash.io" && req.URL.Path == "/v1/credentials":
		f.mints.Add(1)
		creds := map[string]any{
			"accessKeyId": "AK", "secretAccessKey": "SK", "sessionToken": "ST",
			"endpoint": fakeEndpoint, "bucket": "bucket-1", "region": "auto",
			"expiresAt": time.Now().Add(10 * time.Minute).Unix(), "visibility": f.visibility,
		}
		raw, _ := json.Marshal(creds)
		res = respond(200, string(raw), "Content-Type", "application/json")
	case req.URL.Host == "blob.upstash.io" && req.URL.Path == "/v1/presign":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		u := fakeEndpoint + "/bucket-1/" + uriEncode(in["key"].(string), true) + "?X-Amz-Signature=x"
		if n, ok := in["partNumber"].(float64); ok {
			u += fmt.Sprintf("&partNumber=%d&uploadId=%s", int(n), in["uploadId"])
		}
		raw, _ := json.Marshal(map[string]any{"url": u, "expiresAt": time.Now().Add(10 * time.Minute).Unix()})
		res = respond(200, string(raw), "Content-Type", "application/json")
	case req.URL.Host == "acct.r2.cloudflarestorage.com":
		res = f.store(req, body)
	default:
		return nil, fmt.Errorf("fake: unexpected request %s", key)
	}
	res.Request = req
	return res, nil
}

func (f *fake) store(req *http.Request, body []byte) *http.Response {
	rawPath := strings.TrimPrefix(req.URL.EscapedPath(), "/bucket-1")
	path, _ := url.PathUnescape(strings.TrimPrefix(rawPath, "/"))
	q := req.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case req.Method == "POST" && q.Has("delete"):
		var doc struct {
			Objects []struct{ Key string } `xml:"Object"`
		}
		_ = xml.Unmarshal(body, &doc)
		for _, o := range doc.Objects {
			delete(f.objects, o.Key)
		}
		return respond(200, "<DeleteResult></DeleteResult>")
	case req.Method == "POST" && q.Has("uploads"):
		f.nextID++
		id := fmt.Sprintf("up-%d", f.nextID)
		f.uploads[id] = &fakeUpload{path: path, headers: req.Header.Clone(), parts: map[int][]byte{}, started: time.Now()}
		return respond(200, "<InitiateMultipartUploadResult><UploadId>"+id+"</UploadId></InitiateMultipartUploadResult>")
	case req.Method == "PUT" && q.Has("partNumber"):
		u := f.uploads[q.Get("uploadId")]
		if u == nil {
			return respond(404, "<Error><Code>NoSuchUpload</Code></Error>")
		}
		n, _ := strconv.Atoi(q.Get("partNumber"))
		in := f.inPart.Add(1)
		for {
			m := f.maxPart.Load()
			if in <= m || f.maxPart.CompareAndSwap(m, in) {
				break
			}
		}
		f.mu.Unlock()
		time.Sleep(f.partDelay)
		f.mu.Lock()
		f.inPart.Add(-1)
		u.parts[n] = append([]byte(nil), body...)
		return respond(200, "", "ETag", fmt.Sprintf(`"p%d"`, n))
	case req.Method == "POST" && q.Has("uploadId"):
		u := f.uploads[q.Get("uploadId")]
		if u == nil {
			return respond(404, "<Error><Code>NoSuchUpload</Code></Error>")
		}
		var nums []int
		for n := range u.parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		var data []byte
		for _, n := range nums {
			data = append(data, u.parts[n]...)
		}
		etag := fmt.Sprintf(`"mp-%d"`, len(nums))
		f.objects[u.path] = &fakeObject{data: data, headers: u.headers, etag: etag}
		delete(f.uploads, q.Get("uploadId"))
		return respond(200, "<CompleteMultipartUploadResult><ETag>"+escapeXML(etag)+"</ETag></CompleteMultipartUploadResult>")
	case req.Method == "DELETE" && q.Has("uploadId"):
		delete(f.uploads, q.Get("uploadId"))
		return respond(204, "")
	case req.Method == "GET" && q.Has("uploadId"):
		u := f.uploads[q.Get("uploadId")]
		if u == nil {
			return respond(404, "<Error><Code>NoSuchUpload</Code></Error>")
		}
		var b strings.Builder
		b.WriteString("<ListPartsResult>")
		var nums []int
		for n := range u.parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		for _, n := range nums {
			fmt.Fprintf(&b, `<Part><PartNumber>%d</PartNumber><ETag>"p%d"</ETag><Size>%d</Size></Part>`, n, n, len(u.parts[n]))
		}
		b.WriteString("</ListPartsResult>")
		return respond(200, b.String())
	case req.Method == "GET" && q.Has("uploads"):
		var b strings.Builder
		b.WriteString("<ListMultipartUploadsResult>")
		for id, u := range f.uploads {
			fmt.Fprintf(&b, "<Upload><Key>%s</Key><UploadId>%s</UploadId><Initiated>%s</Initiated></Upload>", escapeXML(u.path), id, u.started.UTC().Format(time.RFC3339))
		}
		b.WriteString("</ListMultipartUploadsResult>")
		return respond(200, b.String())
	case req.Method == "GET" && q.Get("list-type") == "2":
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, q.Get("prefix")) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("<ListBucketResult>")
		for _, k := range keys {
			o := f.objects[k]
			fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><ETag>%s</ETag><LastModified>2026-10-22T10:00:00.000Z</LastModified></Contents>", escapeXML(k), len(o.data), escapeXML(o.etag))
		}
		b.WriteString("<IsTruncated>false</IsTruncated></ListBucketResult>")
		return respond(200, b.String())
	case req.Method == "PUT" && req.Header.Get("X-Amz-Copy-Source") != "":
		src, _ := url.PathUnescape(strings.TrimPrefix(req.Header.Get("X-Amz-Copy-Source"), "/bucket-1/"))
		o := f.objects[src]
		if o == nil {
			return respond(404, "<Error><Code>NoSuchKey</Code></Error>")
		}
		headers := o.headers
		if req.Header.Get("X-Amz-Metadata-Directive") == "REPLACE" {
			headers = req.Header.Clone()
		}
		f.objects[path] = &fakeObject{data: o.data, headers: headers, etag: o.etag}
		return respond(200, "<CopyObjectResult><ETag>"+escapeXML(o.etag)+"</ETag></CopyObjectResult>")
	case req.Method == "PUT":
		cur := f.objects[path]
		if req.Header.Get("If-None-Match") == "*" && cur != nil {
			return respond(412, "<Error><Code>PreconditionFailed</Code></Error>")
		}
		if m := req.Header.Get("If-Match"); m != "" && (cur == nil || cur.etag != m) {
			return respond(412, "<Error><Code>PreconditionFailed</Code></Error>")
		}
		f.nextID++
		etag := fmt.Sprintf(`"e%d"`, f.nextID)
		f.objects[path] = &fakeObject{data: append([]byte(nil), body...), headers: req.Header.Clone(), etag: etag}
		return respond(200, "", "ETag", etag)
	case req.Method == "GET" || req.Method == "HEAD":
		o := f.objects[path]
		if o == nil {
			if req.Method == "HEAD" {
				return respond(404, "")
			}
			return respond(404, "<Error><Code>NoSuchKey</Code></Error>")
		}
		res := respond(200, string(o.data), "ETag", o.etag, "Content-Length", strconv.Itoa(len(o.data)), "Last-Modified", "Thu, 22 Oct 2026 10:00:00 GMT")
		for k, v := range o.headers {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-amz-meta-") || lk == "content-type" || lk == "cache-control" {
				res.Header[k] = v
			}
		}
		if req.Method == "HEAD" {
			res.Body = io.NopCloser(bytes.NewReader(nil))
		}
		return res
	case req.Method == "DELETE":
		delete(f.objects, path)
		return respond(204, "")
	}
	return respond(400, "<Error><Code>NotImplemented</Code></Error>")
}
