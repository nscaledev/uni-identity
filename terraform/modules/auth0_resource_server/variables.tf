variable "name" {
  description = "Display name of the Auth0 resource server (API)."
  type        = string
}

variable "identifier" {
  description = "Audience identifier of the Auth0 resource server (API)."
  type        = string
}

variable "token_lifetime" {
  description = "Access token lifetime in seconds."
  type        = number
}
