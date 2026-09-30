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

package controller

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// cerbos compile exit codes (cerbos@v0.53.0 cmd/cerbos/compile: 3 on
// compilation failure, 4 on policy test failure).  Anything else non-zero is
// an unclassified gate failure; every non-zero outcome refuses publication.
const (
	exitCodeCompileFailure = 3
	exitCodeTestFailure    = 4
)

var (
	// ErrCompileFailed is returned when the candidate store fails to
	// compile (cerbos compile exit code 3).
	ErrCompileFailed = errors.New("policy store failed to compile")

	// ErrTestsFailed is returned when the candidate store compiles but its
	// policy tests fail (cerbos compile exit code 4).  The generated store
	// carries no tests today, but the gate deliberately does not pass
	// --skip-tests so any future test files are enforced.
	ErrTestsFailed = errors.New("policy store tests failed")

	// ErrGateFailed is returned for any other gate failure (binary
	// missing, killed, unclassified exit code).  Fail closed: an
	// inconclusive gate refuses publication just like a failing one.
	ErrGateFailed = errors.New("compile gate failed")
)

// CompileGate validates a candidate policy store directory before it may be
// published.  A nil error is the only outcome that permits publication.
type CompileGate interface {
	Compile(ctx context.Context, dir string) error
}

// ExecGate implements CompileGate by exec'ing the vendored cerbos binary
// (`cerbos compile <dir>`).  The controller image is distroless so the
// binary is exec'd directly, never through a shell.
type ExecGate struct {
	binary string
}

var _ CompileGate = &ExecGate{}

// NewExecGate returns a gate exec'ing the given cerbos binary.
func NewExecGate(binary string) *ExecGate {
	return &ExecGate{binary: binary}
}

// Compile runs `cerbos compile` on the directory, classifying compile
// failures (exit 3) and test failures (exit 4) into distinct sentinels with
// the tool output attached.
func (g *ExecGate) Compile(ctx context.Context, dir string) error {
	//nolint:gosec // exec'ing the compiler is the gate's purpose: the binary path is operator configuration (--cerbos-binary) and the directory is controller-created scratch.
	out, err := exec.CommandContext(ctx, g.binary, "compile", dir).CombinedOutput()
	if err == nil {
		return nil
	}

	exitError := &exec.ExitError{}
	if errors.As(err, &exitError) {
		switch exitError.ExitCode() {
		case exitCodeCompileFailure:
			return fmt.Errorf("%w: %s", ErrCompileFailed, out)
		case exitCodeTestFailure:
			return fmt.Errorf("%w: %s", ErrTestsFailed, out)
		}
	}

	return fmt.Errorf("%w: %w: %s", ErrGateFailed, err, out)
}
