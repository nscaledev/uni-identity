Unikorn Identity Helm chart developer notes.

Linting:
- Ensure dependencies are present: `helm dependency build charts/identity`
- Run the linter: `helm lint charts/identity`

Rendering manifests:
- Render with defaults: `helm template identity charts/identity > $TMPDIR/identity-render.yaml`
- Inspect output 
- Delete the file once you are fine with the results `rm $TMPDIR/identity-render.yaml`
