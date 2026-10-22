package blob

import (
	"os"
	"runtime"
	"strings"
)

func telemetryDisabled(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v != "" && v != "false" && v != "0" && v != "no" && v != "off"
}

// telemetryHeaders go only on calls to the Upstash agent (credentials and signing), never on object
// requests, which are the hot path. UPSTASH_DISABLE_TELEMETRY opts out; "false" or "0" does not,
// since an env var that says false and means true is a trap.
func telemetryHeaders(enabled bool) map[string]string {
	if !enabled || telemetryDisabled(os.Getenv("UPSTASH_DISABLE_TELEMETRY")) {
		return nil
	}
	out := map[string]string{
		"Upstash-Telemetry-Sdk":     "upstash-blob-go@" + Version,
		"Upstash-Telemetry-Runtime": "go@" + strings.TrimPrefix(runtime.Version(), "go"),
	}
	switch {
	case os.Getenv("VERCEL") != "":
		out["Upstash-Telemetry-Platform"] = "vercel"
	case os.Getenv("AWS_REGION") != "":
		out["Upstash-Telemetry-Platform"] = "aws"
	}
	return out
}
