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
	// Non-nil when the reader can be sent again from where it started.
	rewind func() error
}

func resolveBody(body io.Reader) (resolvedBody, error) {
	switch b := body.(type) {
	case nil:
		return resolvedBody{r: bytes.NewReader(nil), size: 0}, nil
	case *bytes.Buffer:
		// Taken whole, so a retry can send it again.
		data := b.Next(b.Len())
		return bytesBody(data), nil
	case *os.File:
		if info, err := b.Stat(); err == nil && info.Mode().IsRegular() {
			if out, ok := seekableBody(b); ok {
				out.contentType = mime.TypeByExtension(filepath.Ext(b.Name()))
				return out, nil
			}
		}
		return resolvedBody{r: b, size: -1}, nil
	case io.ReadSeeker:
		if out, ok := seekableBody(b); ok {
			return out, nil
		}
		return resolvedBody{r: b, size: -1}, nil
	}
	return resolvedBody{r: body, size: -1}, nil
}

func bytesBody(data []byte) resolvedBody {
	r := bytes.NewReader(data)
	return resolvedBody{r: r, size: int64(len(data)), rewind: func() error {
		_, err := r.Seek(0, io.SeekStart)
		return err
	}}
}

// seekableBody sends what is left from the current offset, and can rewind to it. ok is false for
// a seeker that cannot measure itself, which is then read as a plain stream.
func seekableBody(s io.ReadSeeker) (resolvedBody, bool) {
	start, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return resolvedBody{}, false
	}
	end, err := s.Seek(0, io.SeekEnd)
	if err != nil || end < start {
		_, _ = s.Seek(start, io.SeekStart)
		return resolvedBody{}, false
	}
	rewind := func() error {
		_, err := s.Seek(start, io.SeekStart)
		return err
	}
	if rewind() != nil {
		return resolvedBody{}, false
	}
	return resolvedBody{r: s, size: end - start, rewind: rewind}, true
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

// peek reads the leading bytes a type check looks at, and a reader that replays them ahead of the
// rest. A body that can rewind is rewound instead, so it stays retriable.
func peek(b resolvedBody) ([]byte, resolvedBody, error) {
	head := make([]byte, sniffBytes)
	n, err := io.ReadFull(b.r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, b, err
	}
	head = head[:n]
	if b.rewind != nil {
		if err := b.rewind(); err != nil {
			return nil, b, err
		}
		return head, b, nil
	}
	b.r = io.MultiReader(bytes.NewReader(head), b.r)
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
