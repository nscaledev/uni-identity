/*
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultNetworkLogDir           = "test-artifacts/network"
	maxNetworkLogFilenameBaseRunes = 160
)

var (
	networkCapture                = newNetworkCaptureRecorder()
	unsafeNetworkLogNameRegexp    = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	bearerTokenNetworkLogRegexp   = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
	jsonSecretNetworkLogKeyRegexp = regexp.MustCompile(`(?i)("(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token|secret|password|client[_-]?secret|private[_-]?key)"\s*:\s*")[^"]*(")`)
)

type networkCaptureRecorder struct {
	enabled bool
	dir     string
	pid     int

	mu       sync.Mutex
	sequence int
	testName string
	file     *os.File
}

type networkLogEntry struct {
	Timestamp string `json:"timestamp"`
	Test      string `json:"test"`
	Message   string `json:"message"`
}

func newNetworkCaptureRecorder() *networkCaptureRecorder {
	dir := strings.TrimSpace(os.Getenv("NETWORK_LOG_DIR"))
	if dir == "" {
		dir = defaultNetworkLogDir
	}

	return &networkCaptureRecorder{
		enabled: parseBoolEnv(os.Getenv("CAPTURE_NETWORK_LOGS")),
		dir:     dir,
		pid:     os.Getpid(),
	}
}

func parseBoolEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}

// NetworkCaptureEnabled reports whether API request/response capture is enabled.
func NetworkCaptureEnabled() bool {
	return networkCapture.enabled
}

// StartNetworkCapture opens a per-spec network log file.
func StartNetworkCapture(testName string) {
	networkCapture.start(testName)
}

// StopNetworkCapture closes the current per-spec network log file.
func StopNetworkCapture() {
	networkCapture.stop()
}

func (r *networkCaptureRecorder) start(testName string) {
	if !r.enabled {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.closeLocked()

	if err := os.MkdirAll(r.dir, 0o750); err != nil {
		return
	}

	r.sequence++
	filename := fmt.Sprintf("%d-%03d-%s.jsonl", r.pid, r.sequence, sanitizeNetworkLogName(testName))
	file, err := os.Create(filepath.Join(r.dir, filename))
	if err != nil {
		return
	}

	r.testName = testName
	r.file = file
	r.writeLocked("network capture started")
}

func (r *networkCaptureRecorder) stop() {
	if !r.enabled {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.writeLocked("network capture stopped")
	r.closeLocked()
}

func (r *networkCaptureRecorder) printf(format string, args ...interface{}) {
	if !r.enabled {
		return
	}

	message := redactNetworkLogMessage(strings.TrimRight(fmt.Sprintf(format, args...), "\n"))

	r.mu.Lock()
	defer r.mu.Unlock()

	r.writeLocked(message)
}

func (r *networkCaptureRecorder) writeLocked(message string) {
	if r.file == nil {
		return
	}

	entry := networkLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Test:      r.testName,
		Message:   message,
	}

	_ = json.NewEncoder(r.file).Encode(entry)
}

func (r *networkCaptureRecorder) closeLocked() {
	if r.file == nil {
		return
	}

	_ = r.file.Close()
	r.file = nil
	r.testName = ""
}

func sanitizeNetworkLogName(name string) string {
	sanitized := unsafeNetworkLogNameRegexp.ReplaceAllString(name, "-")
	sanitized = strings.Trim(sanitized, "-")

	if sanitized == "" {
		return "unnamed-spec"
	}

	runes := []rune(sanitized)
	if len(runes) > maxNetworkLogFilenameBaseRunes {
		sanitized = string(runes[:maxNetworkLogFilenameBaseRunes])
	}

	return sanitized
}

func redactNetworkLogMessage(message string) string {
	message = bearerTokenNetworkLogRegexp.ReplaceAllString(message, "${1}<redacted>")
	message = jsonSecretNetworkLogKeyRegexp.ReplaceAllString(message, "${1}<redacted>${2}")

	return message
}
