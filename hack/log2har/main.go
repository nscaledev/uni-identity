// log2har converts a uni-identity integration test verbose log into a HAR file.
//
// Usage:
//
//	go run ./hack/log2har test/runs/dev-20260413-125205.log > test/runs/dev-20260413-125205.har
//
// The resulting .har file can be opened in:
//   - Chrome DevTools → Network tab → Import HAR
//   - https://har.tech  (browser viewer)
//   - Insomnia / Postman (File → Import)
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ── HAR types ────────────────────────────────────────────────────────────────

type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Timings         HARTimings  `json:"timings"`
	Comment         string      `json:"comment,omitempty"`
}

type HARRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []HARHeader  `json:"headers"`
	QueryString []HARParam   `json:"queryString"`
	PostData    *HARPostData `json:"postData,omitempty"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int          `json:"bodySize"`
}

type HARResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// ── Parsing ───────────────────────────────────────────────────────────────────

// Matches:  [GET /path] status=200 duration=125.228209ms traceparent=00-...-01
var reStatus = regexp.MustCompile(`^\s+\[([A-Z]+) ([^\]]+)\] status=(\d+) duration=([\d.]+)ms(?:\s+traceparent=([\w-]+))?`)

// Matches:  [GET /path] UNEXPECTED STATUS expected=NNN got=NNN body=... traceID=... spanID=...
var reUnexpected = regexp.MustCompile(`^\s+\[([A-Z]+) ([^\]]+)\] UNEXPECTED STATUS expected=\d+ got=(\d+) body=(.+?) traceID=(\w+)`)

// Matches:  [GET /path] request body: ...
var reReqBody = regexp.MustCompile(`^\s+\[([A-Z]+) ([^\]]+)\] request body: (.+)$`)

// Matches:  [GET /path] response body: ...
var reRespBody = regexp.MustCompile(`^\s+\[([A-Z]+) ([^\]]+)\] response body: (.+)$`)

// Matches timestamp lines like:  > Enter [It] ... @ 04/13/26 12:52:12.652
var reTimestamp = regexp.MustCompile(`@ (\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)`)

// Matches test name:  > Enter [It] should return ... @ ...
var reItName = regexp.MustCompile(`> Enter \[It\] (.+?) @`)

// pending holds an HTTP call being assembled across multiple log lines.
type pending struct {
	method       string
	path         string
	status       int
	duration     float64
	traceID      string
	reqBody      string
	respBody     string
	timestamp    time.Time
	testName     string
}

func (p *pending) key() string { return p.method + " " + p.path }

func (p *pending) toEntry(baseURL string) HAREntry {
	rawURL := baseURL + p.path
	parsed, _ := url.Parse(rawURL)

	// query string params
	var qs []HARParam
	for k, vs := range parsed.Query() {
		for _, v := range vs {
			qs = append(qs, HARParam{Name: k, Value: v})
		}
	}

	req := HARRequest{
		Method:      p.method,
		URL:         rawURL,
		HTTPVersion: "HTTP/1.1",
		Headers:     []HARHeader{{Name: "Content-Type", Value: "application/json"}},
		QueryString: qs,
		HeadersSize: -1,
		BodySize:    len(p.reqBody),
	}
	if p.reqBody != "" {
		req.PostData = &HARPostData{
			MimeType: "application/json",
			Text:     p.reqBody,
		}
	}

	mimeType := "application/json"
	if strings.HasPrefix(strings.TrimSpace(p.respBody), "<") {
		mimeType = "text/html"
	}

	resp := HARResponse{
		Status:      p.status,
		StatusText:  statusText(p.status),
		HTTPVersion: "HTTP/1.1",
		Headers:     []HARHeader{{Name: "Content-Type", Value: mimeType}},
		Content: HARContent{
			Size:     len(p.respBody),
			MimeType: mimeType,
			Text:     p.respBody,
		},
		RedirectURL: "",
		HeadersSize: -1,
		BodySize:    len(p.respBody),
	}

	ts := p.timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	comment := p.testName
	if p.traceID != "" {
		if comment != "" {
			comment += " | "
		}
		comment += "traceID=" + p.traceID
	}

	return HAREntry{
		StartedDateTime: ts.Format(time.RFC3339Nano),
		Time:            p.duration,
		Request:         req,
		Response:        resp,
		Timings:         HARTimings{Send: 0, Wait: p.duration, Receive: 0},
		Comment:         comment,
	}
}

func statusText(code int) string {
	texts := map[int]string{
		200: "OK", 201: "Created", 204: "No Content",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
		404: "Not Found", 409: "Conflict", 422: "Unprocessable Entity",
		500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	if t, ok := texts[code]; ok {
		return t
	}
	return strconv.Itoa(code)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: log2har <logfile> [base-url]")
		fmt.Fprintln(os.Stderr, "  base-url defaults to https://identity.nks-dev.glo1.nscale.com")
		os.Exit(1)
	}

	logFile := os.Args[1]
	baseURL := "https://identity.nks-dev.glo1.nscale.com"
	if len(os.Args) >= 3 {
		baseURL = strings.TrimRight(os.Args[2], "/")
	}

	f, err := os.Open(logFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error opening file:", err)
		os.Exit(1)
	}
	defer f.Close()

	var entries []HAREntry
	var cur *pending
	var currentTest string
	var currentTime time.Time

	flush := func() {
		if cur != nil && cur.status != 0 {
			entries = append(entries, cur.toEntry(baseURL))
		}
		cur = nil
	}

	scanner := bufio.NewScanner(f)
	// Increase buffer for long response body lines.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Track test name from "Enter [It]" lines.
		if m := reItName.FindStringSubmatch(line); m != nil {
			currentTest = strings.TrimSpace(m[1])
		}

		// Track timestamp from any "@ MM/DD/YY HH:MM:SS" lines.
		if m := reTimestamp.FindStringSubmatch(line); m != nil {
			if t, err := time.Parse("01/02/06 15:04:05.000", m[1]); err == nil {
				currentTime = t.UTC()
			}
		}

		// Request body line — start a new pending entry.
		if m := reReqBody.FindStringSubmatch(line); m != nil {
			flush()
			cur = &pending{
				method:    m[1],
				path:      m[2],
				reqBody:   m[3],
				timestamp: currentTime,
				testName:  currentTest,
			}
			continue
		}

		// Status line — either attach to existing pending or start one.
		if m := reStatus.FindStringSubmatch(line); m != nil {
			method, path, statusStr, durStr := m[1], m[2], m[3], m[4]
			traceID := ""
			if len(m) > 5 {
				traceID = m[5]
			}
			status, _ := strconv.Atoi(statusStr)
			dur, _ := strconv.ParseFloat(durStr, 64)

			if cur != nil && cur.method == method && cur.path == path {
				// Continuing existing entry (had a request body).
				cur.status = status
				cur.duration = dur
				cur.traceID = traceID
			} else {
				flush()
				cur = &pending{
					method:    method,
					path:      path,
					status:    status,
					duration:  dur,
					traceID:   traceID,
					timestamp: currentTime,
					testName:  currentTest,
				}
			}
			continue
		}

		// Unexpected status line (no separate response body line follows).
		if m := reUnexpected.FindStringSubmatch(line); m != nil {
			flush()
			status, _ := strconv.Atoi(m[3])
			cur = &pending{
				method:    m[1],
				path:      m[2],
				status:    status,
				respBody:  m[4],
				traceID:   m[5],
				timestamp: currentTime,
				testName:  currentTest,
			}
			flush()
			continue
		}

		// Response body line — attach to current entry and flush.
		if m := reRespBody.FindStringSubmatch(line); m != nil {
			if cur != nil && cur.method == m[1] && cur.path == m[2] {
				cur.respBody = m[3]
			}
			flush()
			continue
		}
	}

	flush()

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		os.Exit(1)
	}

	har := HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{Name: "uni-identity-log2har", Version: "1.0"},
			Entries: entries,
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(har); err != nil {
		fmt.Fprintln(os.Stderr, "json encode error:", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "wrote %d HAR entries from %s\n", len(entries), logFile)
}
