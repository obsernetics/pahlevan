{{/*
Expand the name of the chart.
*/}}
{{- define "pahlevan-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "pahlevan-operator.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "pahlevan-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "pahlevan-operator.labels" -}}
helm.sh/chart: {{ include "pahlevan-operator.chart" . }}
{{ include "pahlevan-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: security-operator
app.kubernetes.io/part-of: pahlevan
{{- end }}

{{/*
Selector labels
*/}}
{{- define "pahlevan-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pahlevan-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "pahlevan-operator.serviceAccountName" -}}
{{- if .Values.operator.serviceAccount.create }}
{{- default (include "pahlevan-operator.fullname" .) .Values.operator.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.operator.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the namespace to use
*/}}
{{- define "pahlevan-operator.namespace" -}}
{{- if .Values.namespace.create }}
{{- default .Release.Namespace .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Create webhook service name
*/}}
{{- define "pahlevan-operator.webhookServiceName" -}}
{{- printf "%s-webhook" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
Create metrics service name
*/}}
{{- define "pahlevan-operator.metricsServiceName" -}}
{{- printf "%s-metrics" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
Create webhook certificate secret name
*/}}
{{- define "pahlevan-operator.webhookCertSecretName" -}}
{{- printf "%s-webhook-certs" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
Create CA bundle for webhooks
*/}}
{{- define "pahlevan-operator.caBundle" -}}
{{- if .Values.webhooks.certificate.ca }}
{{- .Values.webhooks.certificate.ca | b64enc }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Webhook configuration name
*/}}
{{- define "pahlevan-operator.validatingWebhookName" -}}
{{- printf "%s-validating-webhook" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{- define "pahlevan-operator.mutatingWebhookName" -}}
{{- printf "%s-mutating-webhook" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
Create image pull secret name
*/}}
{{- define "pahlevan-operator.imagePullSecretName" -}}
{{- printf "%s-image-pull-secret" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
ServiceMonitor name
*/}}
{{- define "pahlevan-operator.serviceMonitorName" -}}
{{- printf "%s-metrics" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
PrometheusRule name
*/}}
{{- define "pahlevan-operator.prometheusRuleName" -}}
{{- printf "%s-rules" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
NetworkPolicy name
*/}}
{{- define "pahlevan-operator.networkPolicyName" -}}
{{- printf "%s-network-policy" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
PodDisruptionBudget name
*/}}
{{- define "pahlevan-operator.podDisruptionBudgetName" -}}
{{- printf "%s-pdb" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "pahlevan-operator.configMapName" -}}
{{- printf "%s-config" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
RBAC names
*/}}
{{- define "pahlevan-operator.clusterRoleName" -}}
{{- printf "%s-manager-role" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{- define "pahlevan-operator.clusterRoleBindingName" -}}
{{- printf "%s-manager-rolebinding" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{- define "pahlevan-operator.roleName" -}}
{{- printf "%s-leader-election-role" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{- define "pahlevan-operator.roleBindingName" -}}
{{- printf "%s-leader-election-rolebinding" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
Default policy names
*/}}
{{- define "pahlevan-operator.defaultPolicyName" -}}
{{- printf "%s-default-policy" (include "pahlevan-operator.fullname" .) }}
{{- end }}

{{/*
Create common annotations
*/}}
{{- define "pahlevan-operator.commonAnnotations" -}}
meta.helm.sh/release-name: {{ .Release.Name }}
meta.helm.sh/release-namespace: {{ .Release.Namespace }}
{{- if .Values.global.commonAnnotations }}
{{- toYaml .Values.global.commonAnnotations }}
{{- end }}
{{- end }}

{{/*
Create pod annotations
*/}}
{{- define "pahlevan-operator.podAnnotations" -}}
{{- if .Values.operator.podAnnotations }}
{{- toYaml .Values.operator.podAnnotations }}
{{- end }}
{{- include "pahlevan-operator.commonAnnotations" . }}
{{- end }}

{{/*
Validate eBPF configuration
*/}}
{{- define "pahlevan-operator.validateEBPF" -}}
{{- /* eBPF uses specific capabilities (BPF, NET_ADMIN, SYS_RESOURCE, IPC_LOCK) instead of privileged mode */ -}}
{{- end }}

{{/*
Validate webhook configuration
*/}}
{{- define "pahlevan-operator.validateWebhooks" -}}
{{- if and .Values.webhooks.enabled (not .Values.webhooks.certificate.autoGenerate) (not .Values.webhooks.certificate.cert) }}
{{- fail "Webhooks are enabled but no certificate configuration provided. Set webhooks.certificate.autoGenerate=true or provide custom certificates" }}
{{- end }}
{{- end }}

{{/*
Validate resources
*/}}
{{- define "pahlevan-operator.validateResources" -}}
{{- if .Values.operator.resources.requests }}
{{- if and .Values.operator.resources.limits.cpu .Values.operator.resources.requests.cpu }}
{{- $limitCPU := .Values.operator.resources.limits.cpu | toString }}
{{- $requestCPU := .Values.operator.resources.requests.cpu | toString }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Generate certificates for webhooks
*/}}
{{- define "pahlevan-operator.webhookCerts" -}}
{{- if .Values.webhooks.certificate.autoGenerate }}
{{- $ca := genCA (printf "%s-ca" (include "pahlevan-operator.fullname" .)) 365 }}
{{- $altNames := list }}
{{- $altNames = append $altNames (printf "%s.%s.svc" (include "pahlevan-operator.webhookServiceName" .) (include "pahlevan-operator.namespace" .)) }}
{{- $altNames = append $altNames (printf "%s.%s.svc.cluster.local" (include "pahlevan-operator.webhookServiceName" .) (include "pahlevan-operator.namespace" .)) }}
{{- $cert := genSignedCert (include "pahlevan-operator.fullname" .) nil $altNames 365 $ca }}
tls.crt: {{ $cert.Cert | b64enc }}
tls.key: {{ $cert.Key | b64enc }}
ca.crt: {{ $ca.Cert | b64enc }}
{{- else }}
{{- if .Values.webhooks.certificate.cert }}
tls.crt: {{ .Values.webhooks.certificate.cert | b64enc }}
tls.key: {{ .Values.webhooks.certificate.key | b64enc }}
ca.crt: {{ .Values.webhooks.certificate.ca | b64enc }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common security context - now always uses specific capabilities instead of privileged mode
*/}}
{{- define "pahlevan-operator.securityContext" -}}
{{- toYaml .Values.operator.securityContext }}
{{- end }}

{{/*
Get image with registry
*/}}
{{- define "pahlevan-operator.image" -}}
{{- $registry := .Values.global.imageRegistry | default "" }}
{{- $repository := .Values.image.repository }}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- else }}
{{- printf "%s:%s" $repository $tag }}
{{- end }}
{{- end }}

{{/*
Validate all configurations
*/}}
{{- define "pahlevan-operator.validate" -}}
{{- include "pahlevan-operator.validateEBPF" . }}
{{- include "pahlevan-operator.validateWebhooks" . }}
{{- include "pahlevan-operator.validateResources" . }}
{{- end }}