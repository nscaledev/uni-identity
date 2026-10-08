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
