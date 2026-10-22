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

package audit

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Sink consumes audit records.
//
// Emit MUST NOT report failure and MUST NOT block indefinitely: audit delivery
// never fails an API request.  An implementation reports its own errors, and
// the caller recovers panics.  See the README's delivery section.
type Sink interface {
	Emit(ctx context.Context, record *Record)
}

// logSink writes the record to the structured log.  It is always present, as
// the stdout audit line is mandated by the platform specification, and it is
// also the fallback record when a remote sink cannot deliver.
type logSink struct{}

func (logSink) Emit(ctx context.Context, record *Record) {
	log.FromContext(ctx).Info("audit", record.logValues()...)
}

// logValues flattens the record into the key/value pairs of the stdout audit
// line.  The keys are the mandated field names, which are a minimum rather
// than a maximum; see the README's actor and client section.
//
// Every field of the record MUST appear here.  The two destinations describe
// the same event, and a field that reaches a collector but not the log, or the
// reverse, is a discrepancy nobody notices until they are compared during an
// investigation.  TestLogLineCarriesEveryRecordField enforces it.
func (r *Record) logValues() []any {
	values := []any{
		"timestamp", r.Timestamp,
		"component", r.Component,
		"actor", r.Actor,
		"operation", r.Operation,
		"scope", r.Scope,
		"resource", r.Resource,
		"result", r.Result,
	}

	// Omitted rather than logged as empty, matching the wire format.
	if r.Client != nil {
		values = append(values, "client", r.Client)
	}

	if r.Source != nil {
		values = append(values, "source", r.Source)
	}

	if len(r.Grants) > 0 {
		values = append(values, "grants", r.Grants)
	}

	return values
}

// emit hands the record to one sink, containing any panic.  A sink is often
// talking to something remote, and a bug there must not take out the API
// request it is describing, nor stop the remaining sinks.
func emit(ctx context.Context, sink Sink, record *Record) {
	defer func() {
		if r := recover(); r != nil {
			log.FromContext(ctx).Info("audit sink panicked", "panic", r)
		}
	}()

	sink.Emit(ctx, record)
}
