package blob

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Sizes always count bytes. Decimal units match storage billing (2*MB is 2,000,000 bytes); binary
// units match file limits (2*MiB is 2,097,152). MaxSize: 32*MB refuses a 32 MiB file.
const (
	B   int64 = 1
	KB  int64 = 1000
	MB  int64 = 1000 * KB
	GB  int64 = 1000 * MB
	TB  int64 = 1000 * GB
	KiB int64 = 1024
	MiB int64 = 1024 * KiB
	GiB int64 = 1024 * MiB
	TiB int64 = 1024 * GiB
)

var sizeUnits = map[string]float64{
	"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1024, "mib": 1024 * 1024, "gib": 1024 * 1024 * 1024, "tib": 1024 * 1024 * 1024 * 1024,
}

var unitNumber = regexp.MustCompile(`^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]*)\s*$`)

// ParseSize reads a size with a unit, the way the other Upstash Blob SDKs take one: "2MB",
// "32MiB", "500kb", or a bare number of bytes. Unit names ignore case. For a limit read from
// configuration; in code, write 32*blob.MiB.
func ParseSize(s string) (int64, error) {
	return parseSize(s, "size")
}

func parseSize(s, what string) (int64, error) {
	m := unitNumber.FindStringSubmatch(s)
	if m == nil {
		return 0, newErr(CodeInvalidInput, fmt.Sprintf("%s: cannot parse %q (try '2MB', '32MiB', '500KB')", what, s))
	}
	unit := strings.ToLower(m[2])
	if unit == "" {
		unit = "b"
	}
	mult, ok := sizeUnits[unit]
	if !ok {
		return 0, newErr(CodeInvalidInput, fmt.Sprintf("%s: unknown unit %q in %q (b, kb, mb, gb, tb, kib, mib, gib, tib)", what, m[2], s))
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	v := math.Floor(n * mult)
	if v > math.MaxInt64/2 {
		return 0, newErr(CodeInvalidInput, fmt.Sprintf("%s: %q is too large", what, s))
	}
	return int64(v), nil
}

// FormatBytes formats a byte count in decimal units, including values parsed from binary ones. An
// exact multiple of the unit prints whole and anything else keeps a decimal; past 10 of a unit the
// decimal is dropped.
func FormatBytes(bytes int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	n := float64(bytes)
	unit := 0
	// >= 999.95 and not 1000: at one decimal it would print as "1000 KB", which is a megabyte.
	for n >= 999.95 && unit < len(units)-1 {
		n /= 1000
		unit++
	}
	var num string
	switch {
	case n == math.Trunc(n):
		num = strconv.FormatFloat(n, 'f', -1, 64)
	case n < 10:
		num = strconv.FormatFloat(n, 'f', 1, 64)
	default:
		num = strconv.FormatFloat(n, 'f', 0, 64)
	}
	return num + " " + units[unit]
}

// overLimit is the "X, over the Y limit" half of a size refusal. When both sides round to the same
// text, exact byte counts are shown instead.
func overLimit(size, limit int64) string {
	s, l := FormatBytes(size), FormatBytes(limit)
	if strings.Replace(s, ".0 ", " ", 1) != strings.Replace(l, ".0 ", " ", 1) {
		return s + ", over the " + l + " limit"
	}
	return groupThousands(size) + " bytes, over the " + groupThousands(limit) + " byte limit"
}

func groupThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

var durationUnits = map[string]float64{
	"ms": 1,
	"s":  1000, "sec": 1000, "second": 1000, "seconds": 1000,
	"m": 60_000, "min": 60_000, "minute": 60_000, "minutes": 60_000,
	"h": 3_600_000, "hr": 3_600_000, "hour": 3_600_000, "hours": 3_600_000,
	"d": 86_400_000, "day": 86_400_000, "days": 86_400_000,
}

// parseDuration reads "15m", "2h", "7d", a bare number of seconds, or anything time.ParseDuration
// takes ("1h30m").
func parseDuration(s, what string) (time.Duration, error) {
	if m := unitNumber.FindStringSubmatch(s); m != nil {
		unit := strings.ToLower(m[2])
		if unit == "" {
			unit = "s"
		}
		if mult, ok := durationUnits[unit]; ok {
			n, _ := strconv.ParseFloat(m[1], 64)
			ms := math.Floor(n * mult)
			if ms > float64(math.MaxInt64/int64(time.Millisecond)) {
				return 0, newErr(CodeInvalidInput, fmt.Sprintf("%s: %q is too long", what, s))
			}
			return time.Duration(ms) * time.Millisecond, nil
		}
	}
	if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d >= 0 {
		return d, nil
	}
	return 0, newErr(CodeInvalidInput, fmt.Sprintf("%s: cannot parse %q (try '15m', '2h', '7d')", what, s))
}

// Cache values with a meaning of their own. Anything else is a duration ("15m", "3600", "1h30m"),
// which is public, max-age=<seconds>, or a header written out (anything containing "=" or ","),
// which is stored exactly as written.
const (
	// CacheImmutable is public, max-age=31536000, immutable: for a versioned path that never changes.
	CacheImmutable = "immutable"
	// CacheRevalidate is public, max-age=0, must-revalidate: for a stable path that gets overwritten.
	CacheRevalidate = "revalidate"
	// CacheNoStore is no-store.
	CacheNoStore = "no-store"
)

// The Cache-Control an object is stored with. Unset is public, max-age=3600; private replaces
// public on a private bucket, since a shared cache must not keep what only a signed request may read.
func cacheControl(cache string, visibility string) (string, error) {
	scope := visibility
	if scope == "" {
		scope = "public"
	}
	switch cache {
	case "":
		return scope + ", max-age=3600", nil
	case CacheImmutable:
		return scope + ", max-age=31536000, immutable", nil
	case CacheRevalidate:
		return scope + ", max-age=0, must-revalidate", nil
	case CacheNoStore:
		return "no-store", nil
	}
	if strings.ContainsAny(cache, "=,") {
		v := strings.TrimSpace(cache)
		if !headerValueOK(v) {
			return "", newErr(CodeInvalidInput, "cache: the header has characters a header cannot carry")
		}
		return v, nil
	}
	d, err := parseDuration(cache, "cache")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s, max-age=%d", scope, int64(d/time.Second)), nil
}

// headerValueOK is printable ASCII and tabs: what a header can carry and storage hands back unchanged.
func headerValueOK(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 0x20 && c != '\t') || c > 0x7e {
			return false
		}
	}
	return true
}

// sniffBytes is how many leading bytes a type check looks at. The browser sends this many at
// phase 'begin' and the server clamps what it decodes to the same number.
const sniffBytes = 4100
