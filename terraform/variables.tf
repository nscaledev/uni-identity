variable "primary_audience_identifier" {
  description = "Audience identifier for the primary Auth0 API used by identity."
  type        = string
}

variable "primary_audience_name" {
  description = "Display name of the primary Auth0 API."
  type        = string
  default     = "unikorn_identity_server"
}

variable "primary_token_lifetime" {
  description = "Access token lifetime (seconds) for the primary Auth0 API."
  type        = number
  default     = 900
}

variable "integration_wrong_audience_identifier" {
  description = "Optional audience identifier for the Auth0 API used by the wrong-audience fixture."
  type        = string
  default     = ""
}

variable "integration_wrong_audience_name" {
  description = "Display name of the Auth0 API used by the wrong-audience fixture."
  type        = string
  default     = "unikorn_identity_integration_wrong_server"
}

variable "integration_wrong_token_lifetime" {
  description = "Access token lifetime (seconds) for the Auth0 API used by the wrong-audience fixture."
  type        = number
  default     = 900
}

variable "enable_integration_fixtures" {
  description = "Enable provisioning of Auth0 integration-test minting fixtures."
  type        = bool
  default     = false
}

variable "integration_fixtures_client_name" {
  description = "Display name for the integration-test token minting Auth0 application."
  type        = string
  default     = "unikorn_identity_integration_token_mint"
}

variable "integration_fixtures_database_connection_name" {
  description = "Auth0 database connection for fixture users and password-realm grant."
  type        = string
  default     = "Username-Password-Authentication"
}

variable "integration_fixtures_database_connection_enabled_client_ids" {
  description = "Additional Auth0 client IDs to enable on the DB connection (for example the Terraform management client ID)."
  type        = list(string)
  default     = []
}

variable "integration_fixtures_audience_scopes" {
  description = "Scopes granted to the minting client for fixture audiences."
  type        = list(string)
  default     = ["identity:token:exchange"]
}

variable "integration_fixtures_client_grant_types" {
  description = "Grant types enabled on the integration-test token minting Auth0 application."
  type        = list(string)
  default = [
    "client_credentials",
    "password",
    "http://auth0.com/oauth/grant-type/password-realm",
  ]
}

variable "integration_fixtures_create_active_user" {
  description = "Create the active fixture user for successful Auth0 exchange tests."
  type        = bool
  default     = false
}

variable "integration_fixtures_active_user_email" {
  description = "Email address for active fixture user."
  type        = string
  default     = "integration-test-auth0-active@nscale.com"
}

variable "integration_fixtures_active_user_password" {
  description = "Password for active fixture user."
  type        = string
  default     = ""
  sensitive   = true
}

variable "integration_fixtures_create_inactive_user" {
  description = "Create the inactive fixture user for denied Auth0 exchange tests."
  type        = bool
  default     = false
}

variable "integration_fixtures_inactive_user_email" {
  description = "Email address for inactive fixture user."
  type        = string
  default     = "integration-test-auth0-inactive@nscale.com"
}

variable "integration_fixtures_inactive_user_password" {
  description = "Password for inactive fixture user."
  type        = string
  default     = ""
  sensitive   = true
}
