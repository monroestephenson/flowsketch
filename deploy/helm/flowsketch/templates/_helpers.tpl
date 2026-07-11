{{- define "flowsketch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "flowsketch.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "flowsketch.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "flowsketch.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "flowsketch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "flowsketch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "flowsketch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "flowsketch.agentServiceAccountName" -}}
{{- default (printf "%s-agent" (include "flowsketch.fullname" .)) .Values.serviceAccounts.agent.name -}}
{{- end -}}

{{- define "flowsketch.gatewayServiceAccountName" -}}
{{- default (printf "%s-gateway" (include "flowsketch.fullname" .)) .Values.serviceAccounts.gateway.name -}}
{{- end -}}

{{- define "flowsketch.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
