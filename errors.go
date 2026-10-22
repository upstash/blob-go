package blob

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ErrorCode is the closed list of reasons a [*Error] carries. Switch on it rather than on Status or
// the message text.
type ErrorCode string

const (
	CodeNotFound                  ErrorCode = "not_found"
	CodeAlreadyExists             ErrorCode = "already_exists"
	CodeConflict                  ErrorCode = "conflict"
	CodeContentTypeNotAllowed     ErrorCode = "content_type_not_allowed"
	CodeInvalidInput              ErrorCode = "invalid_input"
	CodeTooLarge                  ErrorCode = "too_large"
	CodeEmptyBody                 ErrorCode = "empty_body"
	CodeLengthRequired            ErrorCode = "length_required"
	CodeSignatureMismatch         ErrorCode = "signature_mismatch"
	CodeUnauthorized              ErrorCode = "unauthorized"
	CodeForbidden                 ErrorCode = "forbidden"
	CodeRateLimited               ErrorCode = "rate_limited"
	CodeMintBackoff               ErrorCode = "mint_backoff"
	CodeNotReady                  ErrorCode = "not_ready"
	CodePartialDelete             ErrorCode = "partial_delete"
	CodeMoveLeftACopy             ErrorCode = "move_left_a_copy"
	CodeInvalidContentTypePattern ErrorCode = "invalid_content_type_pattern"
	CodeRequestFailed             ErrorCode = "request_failed"
)

var codeStatus = map[ErrorCode]int{
	CodeNotFound:                  404,
	CodeAlreadyExists:             409,
	CodeConflict:                  409,
	CodeContentTypeNotAllowed:     400,
	CodeInvalidInput:              400,
	CodeTooLarge:                  413,
	CodeEmptyBody:                 400,
	CodeLengthRequired:            411,
	CodeSignatureMismatch:         403,
	CodeUnauthorized:              401,
	CodeForbidden:                 403,
	CodeRateLimited:               429,
	CodeMintBackoff:               429,
	CodeNotReady:                  503,
	CodePartialDelete:             500,
	CodeMoveLeftACopy:             500,
	CodeInvalidContentTypePattern: 500,
	CodeRequestFailed:             500,
}

var defaultMessage = map[ErrorCode]string{
	CodeNotFound:                  "not found",
	CodeAlreadyExists:             "already exists",
	CodeConflict:                  "the object changed since it was read",
	CodeContentTypeNotAllowed:     "content type not allowed",
	CodeInvalidInput:              "invalid input",
	CodeTooLarge:                  "too large",
	CodeEmptyBody:                 "empty body",
	CodeLengthRequired:            "length required",
	CodeSignatureMismatch:         "signature mismatch",
	CodeUnauthorized:              "unauthorized",
	CodeForbidden:                 "forbidden",
	CodeRateLimited:               "rate limited",
	CodeMintBackoff:               "the credential service asked for a backoff longer than a request can wait",
	CodeNotReady:                  "bucket is not ready",
	CodePartialDelete:             "some paths were not deleted",
	CodeMoveLeftACopy:             "move left a copy at the source",
	CodeInvalidContentTypePattern: "invalid content type pattern",
	CodeRequestFailed:             "request failed",
}

var defaultHint = map[ErrorCode]string{
	CodeSignatureMismatch: "the upload did not match what was authorized, usually a different size or content type",
	CodeLengthRequired:    "pass Size or MaxSize so the length is known before the first byte",
}

// The code a bare HTTP status means, for an answer that carried a status and no code of its own.
var codeForStatus = map[int]ErrorCode{
	401: CodeUnauthorized,
	403: CodeForbidden,
	404: CodeNotFound,
	409: CodeConflict,
	411: CodeLengthRequired,
	413: CodeTooLarge,
	429: CodeRateLimited,
}

// Error is every failure the SDK reports on purpose: a Code from a closed list, the HTTP Status an
// upload route answers with, and a message that is safe to show a user. It never carries a
// credential, a token or storage's own error text; those ride on the wrapped cause, which
// [errors.Unwrap] reaches and MarshalJSON never sends.
type Error struct {
	Code    ErrorCode
	Status  int
	Message string
	Hint    string
	// CodePartialDelete: the paths that survived.
	Failed []string
	// CodeAlreadyExists: what is already there.
	ETag string
	Size *int64
	// CodeMintBackoff and CodeRateLimited: how long the service asked the caller to wait.
	RetryAfter time.Duration

	cause error
}

// ErrorOptions are the optional fields of [NewError].
type ErrorOptions struct {
	Message    string
	Hint       string
	Status     int
	Failed     []string
	ETag       string
	Size       *int64
	RetryAfter time.Duration
	Cause      error
}

// A message that opens with an identifier (a MIME type, a file name, a metadata key) keeps its
// case, because "Image/png is not allowed" names a type that does not exist.
var opensWithIdentifier = regexp.MustCompile(`^[a-z][\w+*-]*[./][\w.+*/-]*`)

func sentenceCase(message string) string {
	if message == "" || opensWithIdentifier.MatchString(message) {
		return message
	}
	r, size := utf8.DecodeRuneInString(message)
	return string(unicode.ToUpper(r)) + message[size:]
}

// NewError builds an *Error the way the SDK does: a default message and hint per code, the message
// sentence-cased with the hint folded in, and the status the code maps to unless one is given.
// Return one from an upload handler callback to refuse with that code.
func NewError(code ErrorCode, opts ErrorOptions) *Error {
	raw := opts.Message
	if raw == "" {
		raw = defaultMessage[code]
		if raw == "" {
			raw = string(code)
		}
	}
	hint := opts.Hint
	if hint == "" {
		hint = defaultHint[code]
	}
	message := sentenceCase(raw)
	if hint != "" && !strings.Contains(raw, hint) {
		message += " (" + hint + ")"
	}
	status := opts.Status
	if status == 0 {
		status = codeStatus[code]
		if status == 0 {
			status = 500
		}
	}
	return &Error{
		Code:       code,
		Status:     status,
		Message:    message,
		Hint:       hint,
		Failed:     opts.Failed,
		ETag:       opts.ETag,
		Size:       opts.Size,
		RetryAfter: opts.RetryAfter,
		cause:      opts.Cause,
	}
}

func newErr(code ErrorCode, message string) *Error {
	return NewError(code, ErrorOptions{Message: message})
}

// ErrorFromStatus is the best code for a status that arrived without one, falling back to
// CodeRequestFailed.
func ErrorFromStatus(status int, opts ErrorOptions) *Error {
	code, ok := codeForStatus[status]
	if !ok {
		code = CodeRequestFailed
	}
	opts.Status = status
	return NewError(code, opts)
}

func (e *Error) Error() string {
	if e.Message == "" {
		return sentenceCase(defaultMessage[e.Code])
	}
	return e.Message
}

// httpStatus is Status, or the code's own for an *Error built by hand without one.
func (e *Error) httpStatus() int {
	if e.Status >= 400 && e.Status < 600 {
		return e.Status
	}
	if s, ok := codeStatus[e.Code]; ok {
		return s
	}
	return 500
}

// Unwrap returns what caused the error, when the SDK knows: a network error, storage's own message,
// or the signing service's reason for refusing a suspended or read-only bucket.
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is an *Error with the same Code, so errors.Is(err, blob.ErrNotFound)
// works for any not_found the SDK returns.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.Code == e.Code
}

// Sentinels for errors.Is. Only the Code is compared.
var (
	ErrNotFound          = &Error{Code: CodeNotFound, Status: 404, Message: "Not found"}
	ErrAlreadyExists     = &Error{Code: CodeAlreadyExists, Status: 409, Message: "Already exists"}
	ErrConflict          = &Error{Code: CodeConflict, Status: 409, Message: "The object changed since it was read"}
	ErrTooLarge          = &Error{Code: CodeTooLarge, Status: 413, Message: "Too large"}
	ErrInvalidInput      = &Error{Code: CodeInvalidInput, Status: 400, Message: "Invalid input"}
	ErrUnauthorized      = &Error{Code: CodeUnauthorized, Status: 401, Message: "Unauthorized"}
	ErrForbidden         = &Error{Code: CodeForbidden, Status: 403, Message: "Forbidden"}
	ErrContentTypeDenied = &Error{Code: CodeContentTypeNotAllowed, Status: 400, Message: "Content type not allowed"}
)

// HasCode reports whether err is or wraps an *Error with this code.
func HasCode(err error, code ErrorCode) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

type errorJSON struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Status     int       `json:"status"`
	Hint       string    `json:"hint,omitempty"`
	Failed     []string  `json:"failed,omitempty"`
	ETag       string    `json:"etag,omitempty"`
	Size       *int64    `json:"size,omitempty"`
	RetryAfter *float64  `json:"retryAfter,omitempty"`
}

// MarshalJSON writes the shape @upstash/blob's browser client rebuilds its BlobError from, with
// RetryAfter in seconds. The cause is never sent.
func (e *Error) MarshalJSON() ([]byte, error) {
	code := e.Code
	if _, known := codeStatus[code]; !known {
		code = CodeRequestFailed
	}
	out := errorJSON{Code: code, Message: e.Error(), Status: e.httpStatus(), Hint: e.Hint, Failed: e.Failed, ETag: e.ETag, Size: e.Size}
	if e.RetryAfter > 0 {
		s := e.RetryAfter.Seconds()
		out.RetryAfter = &s
	}
	return json.Marshal(out)
}

// asBlobError finds the *Error in err's chain, if there is one.
func asBlobError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
