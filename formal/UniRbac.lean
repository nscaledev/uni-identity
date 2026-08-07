/-
  UniRbac.lean — library root.

  This is the top module of the `unirbac` Lean library. Lean builds a library by
  starting from the root module (this file, which matches the library name) and
  following its `import` lines. As the formalization grows, each new module is
  added to the `import` list below so that `lake build` type-checks everything.

  The library is a machine-checked model of the pure, security-critical core of
  UNI RBAC (`pkg/rbac`). It is a proof artifact only — it lives outside the Go
  module on purpose, so the Go build and CI never see it.

  Right now this is just the scaffold: the model itself lands in later commits.
-/
