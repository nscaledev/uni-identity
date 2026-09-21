/-
  Main.lean — the `gen-vectors` executable.

  Run via `lake exe gen-vectors` (see `make regenerate-vectors`). It prints the
  conformance-vector JSON to stdout, but ONLY after checking that the model
  reproduces every hand-written case's asserted outcome. If the model and a
  human-asserted expectation disagree, it writes the offending case names to
  stderr and exits non-zero — so a divergence can never silently produce a
  passing vector file.
-/

import UniRbac.Vectors

open UniRbac

def main : IO Unit := do
  match handwrittenMismatches with
  | [] => IO.print (documentJson allScenarios)
  | ms =>
    IO.eprintln s!"model disagrees with hand-written humanExpect for: {ms}"
    throw (IO.userError "hand-written vector mismatch")
