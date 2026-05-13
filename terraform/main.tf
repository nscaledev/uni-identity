terraform {
  required_version = ">= 1.5.0"

  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = ">= 1.0.0"
    }
  }

  # Remote state on Nscale-hosted S3-compatible object storage.
  #
  # The endpoint, region, and S3-compatibility flags are baked in here because
  # they're shared across every environment. Only `bucket` and `key` vary per
  # environment — those come from `envs/<env>/backend.hcl` via
  # `terraform init -backend-config=...`. Credentials come from the standard
  # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars. See terraform/README.md.
  #
  # To point at a different S3-compatible provider, change `endpoints.s3`
  # below (and, if it's a real AWS region, drop `skip_region_validation`).
  backend "s3" {
    endpoints = { s3 = "https://s3.glo1.nscale.com" }
    region    = "us-east-1" # Required by Terraform; not used for routing (endpoints.s3 overrides it). skip_region_validation = true lets us pass any string.

    use_path_style              = true
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
  }
}

module "primary_resource_server" {
  source = "./modules/auth0_resource_server"

  name           = var.primary_audience_name
  identifier     = var.primary_audience_identifier
  token_lifetime = var.primary_token_lifetime
}

module "integration_fixtures" {
  count  = var.enable_integration_fixtures ? 1 : 0
  source = "./modules/auth0_integration_fixtures"

  primary_audience_identifier           = module.primary_resource_server.identifier
  create_wrong_audience_resource_server = var.integration_wrong_audience_identifier != ""
  wrong_audience_identifier             = var.integration_wrong_audience_identifier
  wrong_audience_name                   = var.integration_wrong_audience_name
  wrong_token_lifetime                  = var.integration_wrong_token_lifetime

  client_name                            = var.integration_fixtures_client_name
  database_connection_name               = var.integration_fixtures_database_connection_name
  database_connection_enabled_client_ids = var.integration_fixtures_database_connection_enabled_client_ids
  audience_scopes                        = var.integration_fixtures_audience_scopes
  client_grant_types                     = var.integration_fixtures_client_grant_types

  create_active_user     = var.integration_fixtures_create_active_user
  active_user_email      = var.integration_fixtures_active_user_email
  active_user_password   = var.integration_fixtures_active_user_password
  create_inactive_user   = var.integration_fixtures_create_inactive_user
  inactive_user_email    = var.integration_fixtures_inactive_user_email
  inactive_user_password = var.integration_fixtures_inactive_user_password
}
