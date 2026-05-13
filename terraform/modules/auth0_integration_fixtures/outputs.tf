output "client_id" {
  description = "Auth0 client ID for integration fixture token minting."
  value       = auth0_client.integration_mint_client.client_id
}

output "client_secret" {
  description = "Auth0 client secret for integration fixture token minting."
  value       = auth0_client_credentials.integration_mint_client.client_secret
  sensitive   = true
}

output "database_connection_name" {
  description = "Auth0 database connection name used by fixture users."
  value       = data.auth0_connection.database.name
}

output "primary_audience_identifier" {
  description = "Primary audience identifier granted to the minting client."
  value       = var.primary_audience_identifier
}

output "wrong_audience_identifier" {
  description = "Wrong-audience identifier granted to the minting client."
  value       = local.effective_wrong_audience_identifier
}

output "wrong_audience_resource_server_created" {
  description = "Whether this module created the wrong-audience resource server."
  value       = var.create_wrong_audience_resource_server
}

output "active_user_email" {
  description = "Active fixture user email for successful Auth0 exchange tests."
  value       = var.active_user_email
}

output "active_user_password" {
  description = "Active fixture user password for successful Auth0 exchange tests."
  value       = var.active_user_password
  sensitive   = true
}

output "inactive_user_email" {
  description = "Inactive fixture user email for denied Auth0 exchange tests."
  value       = var.inactive_user_email
}

output "inactive_user_password" {
  description = "Inactive fixture user password for denied Auth0 exchange tests."
  value       = var.inactive_user_password
  sensitive   = true
}
