{{/* Chart name */}}
{{- define "pahlevan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name */}}
{{- define "pahlevan.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "pahlevan.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "pahlevan.labels" -}}
helm.sh/chart: {{ include "pahlevan.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: pahlevan
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/* Image reference */}}
{{- define "pahlevan.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/* Service account names */}}
{{- define "pahlevan.agentServiceAccountName" -}}
{{- default (printf "%s-agent" (include "pahlevan.fullname" .)) .Values.serviceAccount.agentName }}
{{- end }}
{{- define "pahlevan.operatorServiceAccountName" -}}
{{- default (printf "%s-operator" (include "pahlevan.fullname" .)) .Values.serviceAccount.operatorName }}
{{- end }}
