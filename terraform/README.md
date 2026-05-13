# Auth0 API Provisioning

This Terraform configuration provisions Auth0 resource servers (APIs) used by
identity token exchange.

It now uses reusable modules and supports provisioning:

- one primary API audience (required)
- optional integration fixtures (minting app, optional wrong-audience API,
  optional active/inactive users)

## Inputs

Required:

- `primary_audience_identifier`

Optional:

- `primary_audience_name` (default: `unikorn_identity_server`)
- `primary_token_lifetime` (default: `900`)
- `enable_integration_fixtures` (default: `false`)
- `integration_wrong_audience_identifier` (default: empty)
- `integration_wrong_audience_name` (default: `unikorn_identity_integration_wrong_server`)
- `integration_wrong_token_lifetime` (default: `900`)
- `integration_fixtures_*` options for app/user fixture customization

If user creation fails with a DB connection/client enablement error, set
`integration_fixtures_database_connection_enabled_client_ids` to include the
Auth0 client ID used by Terraform provider authentication.

## Example (`dev.tfvars`)

```hcl
primary_audience_identifier           = "https://identity.nks-dev.glo1.nscale.com"
integration_wrong_audience_identifier = "https://identity-integration-wrong-audience.nks-dev.glo1.nscale.com"
enable_integration_fixtures           = true
```

If `enable_integration_fixtures` is `false`, integration fixture resources are
not created.

## Usage

Per-environment configuration lives in `envs/<env>/`:

```text
envs/
  dev/
    backend.hcl                  # S3 bucket/key/endpoint for dev state
    terraform.tfvars.example     # template; copy to terraform.tfvars
  integration/
    backend.hcl
    terraform.tfvars.example
```

`*.tfvars` files are gitignored (they may contain secrets); the `.example`
templates and `backend.hcl` files are committed.

First-time setup for a given environment:

```bash
cp envs/dev/terraform.tfvars.example envs/dev/terraform.tfvars
# edit envs/dev/terraform.tfvars and fill in real values
export AWS_ACCESS_KEY_ID=<state-bucket-access-key>
export AWS_SECRET_ACCESS_KEY=<state-bucket-secret-key>
terraform init -backend-config=envs/dev/backend.hcl
terraform plan  -var-file=envs/dev/terraform.tfvars
terraform apply -var-file=envs/dev/terraform.tfvars
```

To switch between environments (re-binds the backend):

```bash
terraform init -reconfigure -backend-config=envs/integration/backend.hcl
terraform plan  -var-file=envs/integration/terraform.tfvars
```

### Remote state (S3-compatible backend)

State is stored on Nscale-hosted S3-compatible object storage. The endpoint,
region, and S3-compatibility flags live in the `backend "s3"` block in
`main.tf` (they're the same across every environment). Per-environment values
are only `bucket` and `key`, which come from `envs/<env>/backend.hcl`:

```hcl
bucket = "uni-identity-tfstate-dev"
key    = "identity/auth0/terraform.tfstate"
```

Credentials must come from your shell (`AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY`) or a secrets manager — never commit them to
`backend.hcl`. The same env-var names work for any S3-compatible provider.
To migrate from local state to a remote backend, pass `-migrate-state` to
`terraform init`.

To point at a different S3-compatible provider (e.g. AWS S3, MinIO,
Cloudflare R2), change `endpoints.s3` in `main.tf` — and, if it's a real
AWS region, drop `skip_region_validation`. The per-env `backend.hcl` files
don't need to change.

## Notes

- All APIs include the `identity:token:exchange` scope.
- The wrong-audience API is used to mint tokens whose `aud` does not match the
  primary audience, exercising the wrong-audience rejection path.
- The expired-token fixture is seeded manually via `hack/auth0/` — mint a
  token against the primary audience once and let it expire in your env file.

## Integration Fixture Outputs

When `enable_integration_fixtures = true`, these root outputs are available:

- `integration_wrong_audience_identifier`
- `integration_fixtures_client_id`
- `integration_fixtures_client_secret` (sensitive)
