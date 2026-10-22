# upstash/blob-go

Go SDK for [Upstash Blob](https://upstash.com/docs/blob). Standard library only.

```bash
go get github.com/upstash/blob-go
```

## Usage

```go
import blob "github.com/upstash/blob-go"

bucket, err := blob.NewBucketFromEnv() // reads UPSTASH_BLOB_TOKEN, or blob.NewBucket(token)

f, _ := os.Open("me.png")
b, err := bucket.Put(ctx, "avatars/me.png", f, nil)
b.URL  // "" on a private bucket
b.ETag

got, err := bucket.Get(ctx, "avatars/me.png") // record + Body; close it
info, err := bucket.Info(ctx, "avatars/me.png")
ok, err := bucket.Exists(ctx, "avatars/me.png")
page, err := bucket.List(ctx, &blob.ListOptions{Prefix: "avatars/", Limit: 100}) // page.Cursor
bucket.Copy(ctx, "tmp/9f3c", "avatars/7.png", nil)
bucket.Move(ctx, "tmp/9f3c", "avatars/7.png", &blob.CopyOptions{ContentType: "image/png"})
bucket.Delete(ctx, "a.png") // also DeleteMany, DeletePrefix, DeleteAll
blob.UpdateJSON(ctx, bucket, "u/7.json", func(prev *Settings) (Settings, error) { ... }, nil)
```

- `Put` takes any `io.Reader`. A `*bytes.Reader`, `*strings.Reader`, `*bytes.Buffer`, regular
  `*os.File` or other `io.ReadSeeker` is measured and retried on a failed request; any other reader
  needs `Size` or `MaxSize` and goes up once. A file's content type comes from its extension, else
  `application/octet-stream`.
- `ContentTypes: []string{"image/*"}` checks the declared type and the body's first bytes;
  `MaxSize: 20*blob.MB` refuses anything larger, while streaming too.
- A body over 16 MB goes up as multipart, four parts at a time; `Multipart: blob.MultipartOver(100*blob.MB)`,
  `blob.MultipartAlways` or `blob.MultipartNever` move the line. `NoOverwrite` and `IfUnchanged`
  are single-PUT only.
- `Get` and `Info` fail with `not_found` rather than returning nil; `List` returns keys, sizes, etags
  and URLs, without metadata.
- `UpdateJSON` is a compare-and-set loop, retried on conflict up to `MaxAttempts` times (default 6).
- `Copy` and `Move` take `ContentType`, `Cache`, `Metadata`; whatever is not given is carried over.
  `Move` is a copy plus a delete: a failed delete is `move_left_a_copy`.
- Metadata keys are lowercase and values printable ASCII; anything else is `invalid_input`.
- `Cache` takes `blob.CacheImmutable`, `blob.CacheRevalidate`, `blob.CacheNoStore`, a duration
  (`"15m"`, `"3600"`, `"1h30m"`), or a verbatim header (`"s-maxage=60, public"`).
- Sizes count bytes. `blob.KB`, `MB`, `GB`, `TB` are powers of 1,000 and `KiB`, `MiB`, `GiB`, `TiB`
  powers of 1,024: `32*blob.MB` refuses a 32 MiB file. `blob.ParseSize("32MiB")` reads one from config.
- `Options.Retry` configures retries (`Retries`, `Backoff`, `Disabled`); a Retry-After from the
  service wins over a custom backoff.

### Signed URLs

```go
read, err := bucket.SignedReadURL(ctx, "private/report.pdf", &blob.SignedReadURLOptions{DownloadAs: "report.pdf"})
up, err := bucket.SignedUploadURL(ctx, "u/7/report.pdf", &blob.SignedUploadURLOptions{ContentType: "application/pdf", Size: size})
// PUT up.URL with up.Headers
```

Links are signed by Upstash and live at most 10 minutes (read default: 5); `ExpiresAt` is the
answer per link. `Headers` on an upload URL are pinned into the signature. A private bucket has no
`URL` on any blob and `PublicURL` returns "".

### Browser uploads

`NewUploadHandler` serves the protocol of `@upstash/blob/browser` and `@upstash/blob/react`, so a
React app uploads straight to storage through a Go backend, with multipart, resume, progress and a
completion callback.

```go
uploads, err := blob.NewUploadHandler(blob.UploadHandlerOptions[*User]{
	Context: requireUser, // func(*http.Request) (*User, error); return a 401 to refuse
	Owner:   func(u *User) string { return u.ID },
	OnBeforeUpload: func(a blob.BeforeUploadArgs[*User]) (blob.BeforeUploadResult, error) {
		return blob.BeforeUploadResult{Path: blob.UniquePath("u/" + a.Ctx.ID + "/" + a.File.Name)}, nil
	},
	OnUploadComplete: func(a blob.UploadCompleteArgs[*User]) (any, error) {
		return map[string]string{"url": a.URL}, nil // reaches the browser as upload.blob.data
	},
	Routes: map[string]blob.UploadRoute[*User]{
		"avatar": {ContentTypes: []string{"image/*"}, MaxSize: 5 * blob.MB},
		"video":  {ContentTypes: []string{"video/*"}, MaxSize: 2 * blob.GB},
	},
})
http.Handle("/api/upload", uploads)
```

```tsx
const upload = useUpload('avatar'); // POSTs to /api/upload?route=avatar
```

- Leave `Bucket` nil to use `UPSTASH_BLOB_TOKEN`. Every handler option is a default a route may
  replace; on a route, `ContentTypes: []string{}` or `MaxSize: blob.NoLimit` clears the handler's.
- `Input` validates what the browser sends as `input`; `blob.JSONInput[T]()` decodes it into a `T`.
- `OnUploadComplete` runs at least once per upload; `UploadID` is stable across deliveries.
  Returning an error deletes the object. `State` rides in a signed but readable token: an id, never
  a secret.
- `OnError` sees every refusal; return a `*blob.Error` to answer with it. An error with a
  `StatusCode() int` method answers with that status; any other error is logged and answered as a 500.
- The handler speaks the same versioned upload protocol as `@upstash/blob`'s `uploadHandler`, so
  any release of the browser client works against it.

### Incomplete uploads

A multipart upload that was never finished is invisible to `List` and blocks bucket deletion. The
SDK aborts the ones it starts; sweep the rest from a cron:

```go
bucket.AbortStaleMultipartUploads(ctx, 24*time.Hour, "uploads/")
```

### The S3 escape hatch

```go
c, err := bucket.S3(ctx)
cfg, _ := config.LoadDefaultConfig(ctx, config.WithRegion(c.Region),
	config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
s3c := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = &c.Endpoint })
```

The credentials are short-lived; call `S3` again after `c.Expires`.

## Errors

Everything the SDK refuses is a `*blob.Error` with a `Code` from a closed list, a `Status`, and a
printable message. `errors.Is(err, blob.ErrNotFound)` and `blob.HasCode(err, blob.CodeTooLarge)`
match by code; its JSON is the shape the TypeScript SDK's browser half decodes.

## Telemetry

Credential and signing requests carry the SDK version, Go version, and platform. Set
`UPSTASH_DISABLE_TELEMETRY` or `Options.DisableTelemetry`.

## Development

```bash
go vet ./... && go test -race ./...
```

Live tests run against real buckets when `UPSTASH_BLOB_PUBLIC_TOKEN` and
`UPSTASH_BLOB_PRIVATE_TOKEN` are set, and write only under `go-live/`.

## License

[MIT](./LICENSE)
