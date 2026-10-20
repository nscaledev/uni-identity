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
Built-in and chain roles, fixed here so a values change cannot widen the chain.
*/}}
{{- define "unikorn.identity.builtinRoles" -}}
{{- list "administrator" "auditor" "user" "reader" | toJson }}
{{- end }}

{{- define "unikorn.identity.chainRoles" -}}
{{- list "auditor" "user" "reader" | toJson }}
{{- end }}

{{/*
The fixed shape of each built-in role with aggregation.builtinRoles on, pinned by the render and the policy.
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
unikorn.identity.checkLabelKey fails unless .key is a valid label key, as it is written into the manifest.
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
"true" if a role in values carries an aggregate-to-* label.
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
Scopes only platform roles hold; a labelled role may hold none of them.
A labelled or additionalRoles role cannot take a chart platform scope off the list.
A service labelled role counts only for scopes that additionalRoles alone hold globally.
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
