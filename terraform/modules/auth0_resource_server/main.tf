terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = ">= 1.0.0"
    }
  }
}

resource "auth0_resource_server" "this" {
  name        = var.name
  identifier  = var.identifier
  signing_alg = "RS256"

  token_dialect        = "rfc9068_profile"
  token_lifetime       = var.token_lifetime
  enforce_policies     = true
  allow_offline_access = false
}

resource "auth0_resource_server_scopes" "this" {
  resource_server_identifier = auth0_resource_server.this.identifier

  scopes {
    name        = "identity:token:exchange"
    description = "Exchange source tokens for passport tokens."
  }
}
