package blob

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// A browser upload PUTs straight to storage, so a bucket whose CORS list leaves out the page's
// origin fails in the browser alone: the route answers 200 and the only trace is a console error in
// a tab nobody is watching. The token cannot read the bucket's CORS rules, but storage answers a
// preflight for anybody, so the handler sends the preflight the browser is about to send, against
// the url it just signed, and logs a warning when storage refuses it.
//
// Diagnostic only: never awaited by the request, never an error, and once per origin per process.

// Origins remembered as probed. Bounded, since the Origin header is the client's to choose.
const maxProbed = 64

var originRE = regexp.MustCompile(`(?i)^https?://[^/]+$`)

type corsProbe struct {
	client *http.Client
	logger *slog.Logger
	mu     sync.Mutex
	probed map[string]bool
}

func newCorsProbe(client *http.Client, logger *slog.Logger) *corsProbe {
	return &corsProbe{client: client, logger: logger, probed: map[string]bool{}}
}

func (p *corsProbe) check(r *http.Request, url string, headers map[string]string) {
	origin := r.Header.Get("Origin")
	if origin == "" || !originRE.MatchString(origin) {
		return
	}
	p.mu.Lock()
	if p.probed[origin] {
		p.mu.Unlock()
		return
	}
	// Forgetting is the cheap way to stay bounded: a forgotten origin is only probed once more.
	if len(p.probed) >= maxProbed {
		p.probed = map[string]bool{}
	}
	p.probed[origin] = true
	p.mu.Unlock()
	go func() {
		allowed, answered := p.preflight(origin, url, headers)
		if !answered {
			// Storage that could not be asked is asked again on the next upload from this origin.
			p.mu.Lock()
			delete(p.probed, origin)
			p.mu.Unlock()
			return
		}
		if !allowed {
			p.logger.Warn(corsWarning(origin))
		}
	}()
}

func corsWarning(origin string) string {
	return "[upstash-blob] storage refused the CORS preflight from " + origin + ", so a browser upload from that origin will be blocked before any bytes are sent. If " + origin + " is your app, add it to the bucket's CORS origins in the Upstash Console, under the bucket's CORS settings."
}

func (p *corsProbe) preflight(origin, url string, headers map[string]string) (allowed, answered bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, url, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "PUT")
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	if len(names) > 0 {
		req.Header.Set("Access-Control-Request-Headers", strings.Join(names, ","))
	}
	res, err := p.client.Do(req)
	if err != nil {
		return false, false
	}
	drain(res)
	// A 5xx or a rate limit is storage not answering the question, not a refusal.
	if res.StatusCode >= 500 || res.StatusCode == 429 {
		return false, false
	}
	got := res.Header.Get("Access-Control-Allow-Origin")
	return ok(res) && (got == "*" || got == origin), true
}
