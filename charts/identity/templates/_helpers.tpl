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

{{- define "unikorn.policyControllerImage" -}}
{{- .Values.policyController.image | default (printf "%s/unikorn-policy-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{/*
Global role and group role binding args (--global-role-binding /
--global-group-role-binding), including validation and the
render-time wildcard guard. Single source of truth for both the
identity and enclave-authorization deployments: identity/deployment.yaml
has no enable flag, so a duplicated copy there always evaluates first
and any drift in a second copy would never be exercised by a render.
Indentation is baked in at the args: list level (8 spaces) used by
both callers, so this is included verbatim, with no nindent: the body
is unchanged from its original inline form, byte for byte.
*/}}
{{- define "unikorn.globalRoleBindingArgs" -}}
        {{- range $i, $b := .Values.globalRoleBindings }}
          {{- if not (trim (default "" $b.issuer)) }}
            {{- fail (printf "globalRoleBindings[%d]: issuer is required" $i) }}
          {{- end }}
          {{- if regexMatch "\\s" $b.issuer }}
            {{- fail (printf "globalRoleBindings[%d]: issuer must not contain whitespace" $i) }}
          {{- end }}
          {{- /*
          Right-anchored parsing means a "::" in either field silently shifts
          the boundary, undetectably once the flag is built. Reject it here,
          while the intended split is still known.
          */}}
          {{- if contains "::" $b.issuer }}
            {{- fail (printf "globalRoleBindings[%d]: issuer must not contain \"::\"" $i) }}
          {{- end }}
          {{- if and (hasKey $b "subject") (hasKey $b "subjects") }}
            {{- fail (printf "globalRoleBindings[%d]: subject and subjects are mutually exclusive" $i) }}
          {{- end }}
          {{- $subjects := list }}
          {{- if hasKey $b "subject" }}
            {{- $subjects = list $b.subject }}
          {{- else }}
            {{- $subjects = default (list) $b.subjects }}
          {{- end }}
          {{- if not $subjects }}
            {{- fail (printf "globalRoleBindings[%d]: exactly one of subject or non-empty subjects required" $i) }}
          {{- end }}
          {{- /*
          Trim before validating and emitting, so a padded " * " cannot slip
          past the wildcard guards and then match as a wildcard server-side.
          */}}
          {{- $trimmedSubjects := list }}
          {{- range $si, $subject := $subjects }}
            {{- $trimmed := trim (default "" $subject) }}
            {{- if not $trimmed }}
              {{- fail (printf "globalRoleBindings[%d].subjects[%d]: empty or whitespace-only subject" $i $si) }}
            {{- end }}
            {{- if contains "::" $trimmed }}
              {{- fail (printf "globalRoleBindings[%d].subjects[%d]: subject must not contain \"::\"" $i $si) }}
            {{- end }}
            {{- if and (ne $trimmed "*") (regexMatch "[A-Z]" $trimmed) }}
              {{- fail (printf "globalRoleBindings[%d].subjects[%d]: subject must be its canonical lower-case form" $i $si) }}
            {{- end }}
            {{- if and (eq $b.issuer "uni") (eq $trimmed "*") }}
              {{- fail (printf "globalRoleBindings[%d]: wildcard subject not allowed on the UNI sentinel issuer" $i) }}
            {{- end }}
            {{- $trimmedSubjects = append $trimmedSubjects $trimmed }}
          {{- end }}
          {{- if not $b.roles }}
            {{- fail (printf "globalRoleBindings[%d]: roles must be non-empty" $i) }}
          {{- end }}
          {{- $allRoles := merge (dict) (default (dict) $.Values.roles) (default (dict) $.Values.additionalRoles) }}
          {{- $roles := list }}
          {{- range $b.roles }}
            {{- if not (hasKey $allRoles .) }}
              {{- fail (printf "globalRoleBindings[%d]: unknown role %q" $i .) }}
            {{- end }}
            {{- $roles = append $roles (include "resource.id" .) }}
          {{- end }}
          {{- /*
          Render-time guard: a wildcard binding's roles must declare no
          non-read global operation. Complementary to the runtime clamp in
          accumulateGlobalReadPermissions (pkg/rbac/bindings.go); full
          rationale in pkg/rbac/README.md#global-role-bindings.
          */}}
          {{- if has "*" $trimmedSubjects }}
            {{- range $b.roles }}
              {{- $roleName := . }}
              {{- $role := index $allRoles $roleName }}
              {{- $roleScopes := default (dict) $role.scopes }}
              {{- $globalScopes := default (dict) $roleScopes.global }}
              {{- range $scopeName, $ops := $globalScopes }}
                {{- range $ops }}
                  {{- if ne . "read" }}
                    {{- fail (printf "globalRoleBindings[%d]: wildcard binding role %q grants non-read global operation %q on scope %q" $i $roleName . $scopeName) }}
                  {{- end }}
                {{- end }}
              {{- end }}
            {{- end }}
          {{- end }}
          {{- range $subject := $trimmedSubjects }}
        - {{ printf "--global-role-binding=%s::%s::%s" $b.issuer $subject (join "," $roles) | quote }}
          {{- end }}
        {{- end }}
{{- end }}

{{- define "unikorn.globalGroupRoleBindingArgs" -}}
        {{- range $i, $b := .Values.globalGroupRoleBindings }}
          {{- if not (trim (default "" $b.issuer)) }}
            {{- fail (printf "globalGroupRoleBindings[%d]: issuer is required" $i) }}
          {{- end }}
          {{- if regexMatch "\\s" $b.issuer }}
            {{- fail (printf "globalGroupRoleBindings[%d]: issuer must not contain whitespace" $i) }}
          {{- end }}
          {{- if contains "::" $b.issuer }}
            {{- fail (printf "globalGroupRoleBindings[%d]: issuer must not contain \"::\"" $i) }}
          {{- end }}
          {{- if eq $b.issuer "uni" }}
            {{- fail (printf "globalGroupRoleBindings[%d]: the uni sentinel issuer cannot carry groups" $i) }}
          {{- end }}
          {{- $group := trim (default "" $b.group) }}
          {{- if not $group }}
            {{- fail (printf "globalGroupRoleBindings[%d]: group is required" $i) }}
          {{- end }}
          {{- if eq $group "*" }}
            {{- fail (printf "globalGroupRoleBindings[%d]: wildcard group not allowed; use a wildcard subject binding" $i) }}
          {{- end }}
          {{- if contains "::" $group }}
            {{- fail (printf "globalGroupRoleBindings[%d]: group must not contain \"::\"" $i) }}
          {{- end }}
          {{- if regexMatch "[\t\n\r]" $group }}
            {{- fail (printf "globalGroupRoleBindings[%d]: group must not contain control whitespace" $i) }}
          {{- end }}
          {{- if not $b.roles }}
            {{- fail (printf "globalGroupRoleBindings[%d]: roles must be non-empty" $i) }}
          {{- end }}
          {{- $allRoles := merge (dict) (default (dict) $.Values.roles) (default (dict) $.Values.additionalRoles) }}
          {{- $roles := list }}
          {{- range $b.roles }}
            {{- if not (hasKey $allRoles .) }}
              {{- fail (printf "globalGroupRoleBindings[%d]: unknown role %q" $i .) }}
            {{- end }}
            {{- $roles = append $roles (include "resource.id" .) }}
          {{- end }}
          {{- /*
          Render-time guard: a group binding must not carry write on the
          credential and trust scopes. A write there mints credentials or
          edits issuer trust. That converts a settings grant into an
          identity grant. Other write scopes stay allowed, unlike the
          wildcard guard above. No runtime read clamp applies.
          */}}
          {{- $credentialScopes := list "identity:users" "identity:groups" "identity:roles" "identity:serviceaccounts" "identity:oauth2providers" }}
          {{- range $b.roles }}
            {{- $roleName := . }}
            {{- $role := index $allRoles $roleName }}
            {{- $roleScopes := default (dict) $role.scopes }}
            {{- $globalScopes := default (dict) $roleScopes.global }}
            {{- range $scopeName, $ops := $globalScopes }}
              {{- if has $scopeName $credentialScopes }}
                {{- range $ops }}
                  {{- if ne . "read" }}
                    {{- fail (printf "globalGroupRoleBindings[%d]: role %q grants non-read operation %q on credential scope %q" $i $roleName . $scopeName) }}
                  {{- end }}
                {{- end }}
              {{- end }}
            {{- end }}
          {{- end }}
        - {{ printf "--global-group-role-binding=%s::%s::%s" $b.issuer $group (join "," $roles) | quote }}
        {{- end }}
{{- end }}
