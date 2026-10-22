package blob

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
)

// resolvedBody is a Put body with what could be learned about it without reading it.
type resolvedBody struct {
	r io.Reader
	// -1 when the length is unknown up front.
	size        int64
	contentType string
	// Set when the body can be read again from start: every attempt gets its own reader over it,
	// since the transport may still be reading the previous attempt's after Do returns.
	ra    io.ReaderAt
	start int64
}

func (b resolvedBody) replayable() bool { return b.ra != nil }

// open is a fresh reader over a replayable body, or the one-shot reader.
func (b resolvedBody) open() io.Reader {
	if b.ra != nil {
		return io.NewSectionReader(b.ra, b.start, b.size)
	}
	return b.r
}

type readerAtSeeker interface {
	io.ReaderAt
	io.Seeker
}

func resolveBody(body io.Reader) (resolvedBody, error) {
	switch b := body.(type) {
	case nil:
		return bytesBody(nil), nil
	case *bytes.Buffer:
		// Read in place, like the other replayable bodies, so a retry can send it again.
		return bytesBody(b.Bytes()), nil
	case *os.File:
		if info, err := b.Stat(); err == nil && info.Mode().IsRegular() {
			out := measure(b)
			out.contentType = mime.TypeByExtension(filepath.Ext(b.Name()))
			return out, nil
		}
		return resolvedBody{r: b, size: -1}, nil
	case io.ReadSeeker:
		return measure(b), nil
	}
	return resolvedBody{r: body, size: -1}, nil
}

func bytesBody(data []byte) resolvedBody {
	return resolvedBody{size: int64(len(data)), ra: bytes.NewReader(data)}
}

// measure sizes a seeker from its current offset to its end. One that can also ReadAt is
// replayable; one that cannot measure itself is read as a plain stream.
func measure(s io.ReadSeeker) resolvedBody {
	start, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return resolvedBody{r: s, size: -1}
	}
	end, err := s.Seek(0, io.SeekEnd)
	if _, serr := s.Seek(start, io.SeekStart); err != nil || serr != nil || end < start {
		return resolvedBody{r: s, size: -1}
	}
	if ra, ok := s.(readerAtSeeker); ok {
		return resolvedBody{r: s, size: end - start, ra: ra, start: start}
	}
	return resolvedBody{r: s, size: end - start}
}

func readAll(r io.Reader, maxSize int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, newErr(CodeTooLarge, fmt.Sprintf("body exceeds maxSize (%d bytes)", maxSize))
	}
	return data, nil
}

// peek reads the leading bytes a type check looks at. A replayable body is read at its start and
// left as it was; a stream comes back as a reader that replays them ahead of the rest.
func peek(b resolvedBody) ([]byte, resolvedBody, error) {
	head := make([]byte, sniffBytes)
	n, err := io.ReadFull(b.open(), head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, b, err
	}
	head = head[:n]
	if !b.replayable() {
		b.r = io.MultiReader(bytes.NewReader(head), b.r)
	}
	return head, b, nil
}

// sizedReader passes exactly size bytes and fails on a body that is shorter or longer than
// declared, or over maxSize, rather than letting the transport send a truncated object.
type sizedReader struct {
	r       io.Reader
	size    int64
	maxSize int64
	seen    int64
}

func (s *sizedReader) Read(p []byte) (int, error) {
	if s.seen >= s.size {
		// Past the declared end: one more byte means the body is longer than declared.
		var one [1]byte
		n, err := s.r.Read(one[:])
		if n > 0 {
			return 0, s.over()
		}
		if err == nil {
			return 0, nil
		}
		return 0, err
	}
	if rem := s.size - s.seen; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := s.r.Read(p)
	s.seen += int64(n)
	if errors.Is(err, io.EOF) && s.seen < s.size {
		return n, newErr(CodeInvalidInput, fmt.Sprintf("body was %d bytes, %d were declared", s.seen, s.size))
	}
	if s.seen == s.size && err == nil {
		// Look for the end now, so the transport sees EOF or the overrun with the last bytes.
		var one [1]byte
		m, rerr := s.r.Read(one[:])
		if m > 0 {
			return n, s.over()
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return n, rerr
		}
		if errors.Is(rerr, io.EOF) {
			return n, io.EOF
		}
	}
	return n, err
}

func (s *sizedReader) over() error {
	if s.maxSize > 0 && s.size >= s.maxSize {
		return newErr(CodeTooLarge, fmt.Sprintf("body exceeds maxSize (%d bytes)", s.maxSize))
	}
	return newErr(CodeInvalidInput, fmt.Sprintf("body is longer than the declared %d bytes", s.size))
}
