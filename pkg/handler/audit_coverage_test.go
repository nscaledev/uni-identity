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

package handler_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// unauditedMutations are the handlers that deliberately state no operation,
// with the reason they cannot.  Adding to this list MUST be a decision, which
// is the point of listing them rather than letting a handler fall through.
//
//nolint:gochecknoglobals
var unauditedMutations = map[string]string{
	"PostOauth2V2Authorization": "no organization, project or resource, and runs before authentication",
	"PostOauth2V2Login":         "no organization, project or resource, and runs before authentication",
	"PostOauth2V2Token":         "no organization, project or resource, and runs before authentication",
	"PostOauth2V2Userinfo":      "no organization, project or resource, and runs before authentication",
}

// A mutating handler that does not state its operation produces no audit
// record.  The middleware reports the gap rather than dropping it silently, but
// the event itself is still lost, so this is checked here where it can be
// fixed.
//
// This guards a real regression: three allocation mutations were described in
// review as reads and left on the older gates, so creating, updating and
// deleting a quota reservation recorded nothing at all.  Counting by eye is
// what missed them.
func TestEveryMutatingHandlerStatesItsOperation(t *testing.T) {
	t.Parallel()

	missing, reads := auditTargets(t)

	require.Empty(t, missing,
		"these mutating handlers state no primary target, so they produce no audit record; "+
			"migrate them or add them to unauditedMutations with a reason")

	// The converse, which is how a list read became the only GET in the service
	// reported as an operation: a read sharing a helper with a mutation must not
	// inherit the mutation's target.
	require.Empty(t, reads,
		"these read handlers state a primary target, so a read will be reported as an operation")
}

// auditTargets parses this package and reports mutating handlers with no
// primary target, and read handlers that wrongly have one.
func auditTargets(t *testing.T) ([]string, []string) {
	t.Helper()

	fset := token.NewFileSet()

	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	require.NoError(t, err)

	var missing, reads []string

	for name, pkg := range pkgs {
		if strings.HasSuffix(name, "_test") {
			continue
		}

		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				function, ok := decl.(*ast.FuncDecl)
				if !ok || !isHandlerMethod(function) {
					continue
				}

				switch classify(function) {
				case readWithTarget:
					reads = append(reads, function.Name.Name)
				case mutationWithoutTarget:
					missing = append(missing, function.Name.Name)
				case correct:
				}
			}
		}
	}

	return missing, reads
}

// verdict is what the guard makes of one handler.
type verdict int

const (
	correct verdict = iota
	readWithTarget
	mutationWithoutTarget
)

// classify decides whether a handler states what it should.
func classify(function *ast.FuncDecl) verdict {
	name := function.Name.Name
	states := callsPrimary(function)

	if strings.HasPrefix(name, "Get") {
		if states {
			return readWithTarget
		}

		return correct
	}

	if states {
		return correct
	}

	if _, known := unauditedMutations[name]; known {
		return correct
	}

	return mutationWithoutTarget
}

// isHandlerMethod reports whether the declaration is a generated API handler,
// which is a method on *Handler named for its HTTP method.
func isHandlerMethod(function *ast.FuncDecl) bool {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return false
	}

	star, ok := function.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}

	ident, ok := star.X.(*ast.Ident)
	if !ok || ident.Name != "Handler" {
		return false
	}

	for _, verb := range []string{"Get", "Post", "Put", "Delete", "Patch"} {
		if strings.HasPrefix(function.Name.Name, verb) {
			return true
		}
	}

	return false
}

// callsPrimary reports whether the handler builds a primary target, directly or
// through a helper it passes one to.
func callsPrimary(function *ast.FuncDecl) bool {
	found := false

	ast.Inspect(function, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "primary" {
			found = true
		}

		return !found
	})

	return found
}
