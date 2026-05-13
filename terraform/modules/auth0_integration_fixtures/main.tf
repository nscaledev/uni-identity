terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = ">= 1.0.0"
    }
  }
}

module "wrong_audience_resource_server" {
  count  = var.create_wrong_audience_resource_server ? 1 : 0
  source = "../auth0_resource_server"

  name           = var.wrong_audience_name
  identifier     = var.wrong_audience_identifier
  token_lifetime = var.wrong_token_lifetime
}

locals {
  effective_wrong_audience_identifier = var.create_wrong_audience_resource_server ? module.wrong_audience_resource_server[0].identifier : var.wrong_audience_identifier
}

data "auth0_connection" "database" {
  name = var.database_connection_name
}

resource "auth0_client" "integration_mint_client" {
  name            = var.client_name
  app_type        = "regular_web"
  is_first_party  = true
  oidc_conformant = true
  grant_types     = var.client_grant_types
}

resource "auth0_client_credentials" "integration_mint_client" {
  client_id             = auth0_client.integration_mint_client.client_id
  authentication_method = "client_secret_post"
}

resource "auth0_connection_client" "integration_mint_client" {
  connection_id = data.auth0_connection.database.id
  client_id     = auth0_client.integration_mint_client.client_id
}

resource "auth0_connection_client" "database_connection_enabled_clients" {
  for_each = toset(var.database_connection_enabled_client_ids)

  connection_id = data.auth0_connection.database.id
  client_id     = each.value
}

resource "auth0_client_grant" "primary_audience" {
  client_id = auth0_client.integration_mint_client.client_id
  audience  = var.primary_audience_identifier
  scopes    = var.audience_scopes
}

resource "auth0_client_grant" "wrong_audience" {
  count = local.effective_wrong_audience_identifier == "" ? 0 : 1

  client_id = auth0_client.integration_mint_client.client_id
  audience  = local.effective_wrong_audience_identifier
  scopes    = var.audience_scopes
}

resource "auth0_user" "active_user" {
  count = var.create_active_user ? 1 : 0

  depends_on = [
    auth0_connection_client.integration_mint_client,
    auth0_connection_client.database_connection_enabled_clients,
  ]

  connection_name = data.auth0_connection.database.name
  email           = var.active_user_email
  password        = var.active_user_password
  verify_email    = false
  email_verified  = true
}

resource "auth0_user" "inactive_user" {
  count = var.create_inactive_user ? 1 : 0

  depends_on = [
    auth0_connection_client.integration_mint_client,
    auth0_connection_client.database_connection_enabled_clients,
  ]

  connection_name = data.auth0_connection.database.name
  email           = var.inactive_user_email
  password        = var.inactive_user_password
  verify_email    = false
  email_verified  = true
}
