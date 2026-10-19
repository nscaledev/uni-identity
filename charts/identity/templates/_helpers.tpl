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
Scope names only platform roles hold: in some role's global block and in no
tenant role's organization or project block.  Tenant roles are unprotected
roles and the built-in base roles.  A labelled role may hold none of them.
*/}}
{{- define "unikorn.identity.platformOnlyScopes" -}}
{{- $roles := merge (dict) (default (dict) .Values.roles) (default (dict) .Values.additionalRoles) }}
{{- $bases := list }}
{{- range (include "unikorn.identity.builtinRoles" . | fromJsonArray) }}
{{- $bases = append $bases (printf "%s-base" .) }}
{{- end }}
{{- $global := dict }}
{{- $tenant := dict }}
{{- range $name, $spec := $roles }}
{{- $scopes := default (dict) $spec.scopes }}
{{- range $scope, $ops := default (dict) $scopes.global }}
{{- $_ := set $global $scope true }}
{{- end }}
{{- if or (not $spec.protected) (has $name $bases) }}
{{- range $scope, $ops := merge (dict) (default (dict) $scopes.organization) (default (dict) $scopes.project) }}
{{- $_ := set $tenant $scope true }}
{{- end }}
{{- end }}
{{- end }}
{{- $out := list }}
{{- range $scope, $_ := $global }}
{{- if not (hasKey $tenant $scope) }}
{{- $out = append $out $scope }}
{{- end }}
{{- end }}
{{- toJson $out }}
{{- end }}
