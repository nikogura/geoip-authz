{{- define "geoip-authz.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "geoip-authz.fullname" -}}
{{- default .Chart.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "geoip-authz.labels" -}}
app.kubernetes.io/name: {{ include "geoip-authz.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "geoip-authz.selectorLabels" -}}
app.kubernetes.io/name: {{ include "geoip-authz.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Name of the secret carrying MaxMind creds, if any. */}}
{{- define "geoip-authz.secretName" -}}
{{- if .Values.maxmind.existingSecret -}}
{{- .Values.maxmind.existingSecret -}}
{{- else -}}
{{- include "geoip-authz.fullname" . -}}
{{- end -}}
{{- end -}}

{{/* True when MaxMind creds should be wired (inline or existing secret). */}}
{{- define "geoip-authz.useSecret" -}}
{{- if or .Values.maxmind.existingSecret .Values.maxmind.accountId .Values.maxmind.licenseKey -}}true{{- end -}}
{{- end -}}
