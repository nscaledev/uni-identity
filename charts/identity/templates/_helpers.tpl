{{/*
Create the container images
*/}}
{{- define "unikorn.defaultTag" -}}
v{{ .Chart.Version }}
{{- end }}

{{- define "unikorn.image" -}}
{{- .Values.server.image | default (printf "%s/unikorn-identity:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.organizationControllerImage" -}}
{{- .Values.organizationController.image | default (printf "%s/unikorn-organization-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.oauth2clientControllerImage" -}}
{{- .Values.oauth2clientController.image | default (printf "%s/unikorn-oauth2client-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.projectControllerImage" -}}
{{- .Values.projectController.image | default (printf "%s/unikorn-project-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.roleControllerImage" -}}
{{- .Values.roleController.image | default (printf "%s/unikorn-role-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{/*
OTLP resource identity. The exported metrics use platform-generic names, so a
stored series is attributed to this service by the resource's service.name
(stored as the job label), not by the metric name. service.instance.id (stored
as the instance label) keeps per-process series apart: the workloads share one
service.name, so without it their unlabelled runtime series would collide.
*/}}
{{- define "unikorn.identity.otelEnv" -}}
env:
- name: OTEL_SERVICE_NAME
  value: unikorn-identity
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: OTEL_RESOURCE_ATTRIBUTES
  value: service.instance.id=$(POD_NAME)
{{- end }}

{{/*
Role aggregation.  The built-in roles aggregation.builtinRoles switches, and
the chain roles among them that are also sources.  Fixed here, not taken from
values, so a values change cannot widen the chain.
*/}}
{{- define "unikorn.identity.builtinRoles" -}}
{{- list "administrator" "auditor" "user" "reader" | toJson }}
{{- end }}

{{- define "unikorn.identity.chainRoles" -}}
{{- list "auditor" "user" "reader" | toJson }}
{{- end }}

{{/*
The fixed shape of each built-in role with aggregation.builtinRoles on: the
aggregating roles it feeds (its aggregateTo) and its flattenToOrganization.
The render guards and the admission policy both pin the built-in roles to it.
*/}}
{{- define "unikorn.identity.chainShape" -}}
{{- dict
  "administrator" (dict "to" (list) "flatten" true)
  "auditor" (dict "to" (list "administrator") "flatten" true)
  "user" (dict "to" (list "administrator") "flatten" false)
  "reader" (dict "to" (list "auditor" "user") "flatten" false)
  | toJson }}
{{- end }}

{{/*
unikorn.identity.checkLabelKey fails the render unless .key is a valid
Kubernetes label key: an optional DNS subdomain prefix (at most 253
characters) and "/", then a name of at most 63 characters.  A key is written
into the Role manifest, so an invalid one could inject YAML.
*/}}
{{- define "unikorn.identity.checkLabelKey" -}}
{{- $parts := splitList "/" .key }}
{{- $name := last $parts }}
{{- $ok := and (le (len $parts) 2) (regexMatch "^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$" $name) }}
{{- if eq (len $parts) 2 }}
{{- $prefix := first $parts }}
{{- $ok = and $ok (le (len $prefix) 253) (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $prefix) }}
{{- end }}
{{- if not $ok }}
{{- fail (printf "role %q: %q is not a valid label key" .role .key) }}
{{- end }}
{{- end }}

{{/*
unikorn.identity.labelled is "true" if a role in values carries an
aggregate-to-* label, by aggregateTo or by labels.
*/}}
{{- define "unikorn.identity.labelled" -}}
{{- $labelled := not (empty .aggregateTo) }}
{{- range $key, $_ := .labels }}
{{- if hasPrefix "identity.unikorn-cloud.org/aggregate-to-" $key }}
{{- $labelled = true }}
{{- end }}
{{- end }}
{{- $labelled }}
{{- end }}

{{/*
Scope names only platform roles hold.  A labelled role may hold none of them.
Tenant roles are the built-in base roles and the unprotected roles that are
not built-in roles (those count through their base roles).  A scope is
platform-only if:
- this chart's roles (.Values.roles) grant it globally and no unlabelled
  tenant role in .Values.roles grants it in an organization or project block.
  A labelled role does not count here, so it cannot take a chart platform
  scope (such as region:servers) off the list by holding it itself, and no
  additionalRoles role counts either, so a decoy role can't take it off;
- or only additionalRoles grant it globally and no tenant role, labelled or
  not, grants it in an organization or project block.  A service's labelled
  role does count here: it is how the service's own tenant scopes (held
  globally by its platform role, such as radar-global-operator) reach org
  admins.
*/}}
{{- define "unikorn.identity.platformOnlyScopes" -}}
{{- $chartRoles := default (dict) .Values.roles }}
{{- $roles := merge (dict) $chartRoles (default (dict) .Values.additionalRoles) }}
{{- $builtins := include "unikorn.identity.builtinRoles" . | fromJsonArray }}
{{- $bases := list }}
{{- range $builtins }}
{{- $bases = append $bases (printf "%s-base" .) }}
{{- end }}
{{- $chartGlobal := dict }}
{{- $global := dict }}
{{- $tenant := dict }}
{{- $chartTenantScopes := dict }}
{{- range $name, $spec := $roles }}
{{- $scopes := default (dict) $spec.scopes }}
{{- range $scope, $ops := default (dict) $scopes.global }}
{{- $_ := set $global $scope true }}
{{- if hasKey $chartRoles $name }}
{{- $_ := set $chartGlobal $scope true }}
{{- end }}
{{- end }}
{{- if or (has $name $bases) (and (not $spec.protected) (not (has $name $builtins))) }}
{{- $chartTenant := and (hasKey $chartRoles $name) (ne (include "unikorn.identity.labelled" $spec) "true") }}
{{- range $scope, $ops := merge (dict) (default (dict) $scopes.organization) (default (dict) $scopes.project) }}
{{- $_ := set $tenant $scope true }}
{{- if $chartTenant }}
{{- $_ := set $chartTenantScopes $scope true }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- $out := list }}
{{- range $scope, $_ := $global }}
{{- if hasKey $chartGlobal $scope }}
{{- if not (hasKey $chartTenantScopes $scope) }}
{{- $out = append $out $scope }}
{{- end }}
{{- else if not (hasKey $tenant $scope) }}
{{- $out = append $out $scope }}
{{- end }}
{{- end }}
{{- toJson $out }}
{{- end }}
