output "id" {
  description = "Auth0 resource server ID."
  value       = auth0_resource_server.this.id
}

output "name" {
  description = "Auth0 resource server display name."
  value       = auth0_resource_server.this.name
}

output "identifier" {
  description = "Auth0 resource server audience identifier."
  value       = auth0_resource_server.this.identifier
}
