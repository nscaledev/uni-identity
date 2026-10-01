{{- define "identity-observability.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "identity-observability.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "identity-observability.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "identity-observability.grafanaNamespace" -}}
{{- .Values.grafana.dashboards.namespace | default .Release.Namespace -}}
{{- end }}

{{- define "identity-observability.labels" -}}
app.kubernetes.io/name: {{ include "identity-observability.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}
