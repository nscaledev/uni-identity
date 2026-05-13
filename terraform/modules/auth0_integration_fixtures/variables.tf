variable "client_name" {
  description = "Display name for the Auth0 application used to mint integration fixture tokens."
  type        = string
}

variable "database_connection_name" {
  description = "Auth0 database connection name used for password/password-realm grant token minting."
  type        = string
}

variable "database_connection_enabled_client_ids" {
  description = "Additional Auth0 client IDs to enable on the DB connection (for example the Terraform management client ID)."
  type        = list(string)
}

variable "primary_audience_identifier" {
  description = "Primary audience identifier for identity token exchange."
  type        = string
}

variable "wrong_audience_identifier" {
  description = "Audience identifier for the Auth0 API used by the wrong-audience fixture."
  type        = string

  validation {
    condition     = var.create_wrong_audience_resource_server == false || var.wrong_audience_identifier != ""
    error_message = "wrong_audience_identifier must be set when create_wrong_audience_resource_server is true."
  }
}

variable "create_wrong_audience_resource_server" {
  description = "Create the wrong-audience resource server inside this module."
  type        = bool
}

variable "wrong_audience_name" {
  description = "Display name of the wrong-audience resource server."
  type        = string
}

variable "wrong_token_lifetime" {
  description = "Access token lifetime (seconds) for the wrong-audience resource server."
  type        = number
}

variable "audience_scopes" {
  description = "Scopes granted to the minting client for each configured audience."
  type        = list(string)
}

variable "client_grant_types" {
  description = "Grant types enabled on the token-minting Auth0 application."
  type        = list(string)
}

variable "create_active_user" {
  description = "Create the active fixture user used for successful exchange tests."
  type        = bool
}

variable "active_user_email" {
  description = "Email for active fixture user."
  type        = string
}

variable "active_user_password" {
  description = "Password for active fixture user."
  type        = string
  sensitive   = true

  validation {
    condition     = var.create_active_user == false || var.active_user_password != ""
    error_message = "active_user_password must be set when create_active_user is true."
  }
}

variable "create_inactive_user" {
  description = "Create the inactive fixture user used for denied exchange tests."
  type        = bool
}

variable "inactive_user_email" {
  description = "Email for inactive fixture user."
  type        = string
}

variable "inactive_user_password" {
  description = "Password for inactive fixture user."
  type        = string
  sensitive   = true

  validation {
    condition     = var.create_inactive_user == false || var.inactive_user_password != ""
    error_message = "inactive_user_password must be set when create_inactive_user is true."
  }
}
