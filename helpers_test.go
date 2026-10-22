package blob

import (
	"encoding/base64"
	"errors"
	"regexp"
)

func errorsAs(err error, target any) bool { return errors.As(err, target) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func regexpMatch(re, s string) bool { return regexp.MustCompile(re).MatchString(s) }
