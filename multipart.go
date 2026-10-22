package blob

import (
	"fmt"
)

// MultipartThreshold is where the multipart path starts by default: under it a body goes up as one
// PUT, over it in parts. Decimal, and the same line for Bucket.Put and a browser upload.
//
// Parts are three round trips and one more per chunk where a PUT is one, and an upload begun and
// never finished lingers until something aborts it. So parts are what a big file needs, past R2's
// single-PUT cap and for a chunk that can be retried or resumed on its own, rather than the shape of
// every upload.
const MultipartThreshold = 16 * MB

// singlePutMax is the largest single PUT R2 accepts; past it there is no choice but parts.
const singlePutMax = 5 * GiB

// Multipart says when a body goes up in parts. The zero value is the default: over
// MultipartThreshold. A conditional write (NoOverwrite, IfUnchanged) is single-PUT only.
type Multipart struct {
	mode      uint8
	threshold int64
}

const (
	multipartDefault uint8 = iota
	multipartAlways
	multipartNever
	multipartOver
)

var (
	// MultipartAlways sends every non-empty body in parts.
	MultipartAlways = Multipart{mode: multipartAlways}
	// MultipartNever sends every body as one PUT; a body over R2's 5 GiB single-PUT cap is refused.
	MultipartNever = Multipart{mode: multipartNever}
)

// MultipartOver moves the line: a body over threshold bytes goes up in parts. A threshold above the
// single-PUT cap is honoured up to the cap; a negative one is 0, which parts every non-empty body.
func MultipartOver(threshold int64) Multipart {
	return Multipart{mode: multipartOver, threshold: max(threshold, 0)}
}

// wantsMultipart reports whether a body of this size goes up in parts. It fails only for a
// MultipartNever that R2 cannot honour.
func wantsMultipart(m Multipart, size int64, what string) (bool, error) {
	if size > singlePutMax {
		if m.mode == multipartNever {
			return false, NewError(CodeTooLarge, ErrorOptions{
				Message: fmt.Sprintf("%s is over the %s a single PUT can carry", FormatBytes(size), FormatBytes(singlePutMax)),
				Hint:    what + ": MultipartNever forbids the parts this body needs",
			})
		}
		return true, nil
	}
	switch m.mode {
	case multipartAlways:
		return true, nil
	case multipartNever:
		return false, nil
	case multipartOver:
		return size > m.threshold, nil
	}
	return size > MultipartThreshold, nil
}

// Part math is binary: R2's floor for every part but the last is 5 MiB, checked at complete.
const (
	minPart     = 5 * MiB
	targetParts = 250
)

// partSizeFor is max(5 MiB, ceil(size / 250)) rounded up to a MiB.
func partSizeFor(size int64) int64 {
	per := (size + targetParts - 1) / targetParts
	per = (per + MiB - 1) / MiB * MiB
	return max(minPart, per)
}

func partCount(size, partSize int64) int {
	return int(max(1, (size+partSize-1)/partSize))
}

// Every part is buffered whole so a failed one can be sent again, and one more fills while the rest
// are in flight, so each costs its size in memory. Four overlap the round trips the way the AWS SDK
// does; bigger parts (bodies over about 3 GB) go fewer at once to stay within the budget.
const (
	partConcurrency  = 4
	partBufferBudget = 64 * MiB
)

// partConcurrencyFor is how many parts are sent at once: up to four, with the one filling, within
// 64 MiB, and never under one.
func partConcurrencyFor(partSize int64) int {
	return int(max(1, min(partConcurrency, partBufferBudget/partSize-1)))
}
