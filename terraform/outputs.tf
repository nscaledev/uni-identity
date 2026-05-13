output "primary_resource_server_identifier" {
  description = "Audience identifier of the primary Auth0 API."
  value       = module.primary_resource_server.identifier
}

output "integration_wrong_audience_identifier" {
  description = "Audience identifier of the optional Auth0 API used by the wrong-audience fixture."
  value       = var.enable_integration_fixtures && module.integration_fixtures[0].wrong_audience_identifier != "" ? module.integration_fixtures[0].wrong_audience_identifier : null
}

output "integration_fixtures_client_id" {
  description = "Client ID for integration-test Auth0 token minting app."
  value       = var.enable_integration_fixtures ? module.integration_fixtures[0].client_id : null
}

output "integration_fixtures_client_secret" {
  description = "Client secret for integration-test Auth0 token minting app."
  value       = var.enable_integration_fixtures ? module.integration_fixtures[0].client_secret : null
  sensitive   = true
}
