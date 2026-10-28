{{- define "limitplane.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "limitplane.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "limitplane.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "limitplane.redisSelectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: redis
{{- end -}}

{{- define "limitplane.secretName" -}}
{{- .Values.existingSecret | default (include "limitplane.fullname" .) -}}
{{- end -}}

{{/* Admin plane prefix: "" in demo mode, /_limitplane in proxy mode. */}}
{{- define "limitplane.adminPath" -}}
{{- if .Values.upstream -}}/_limitplane{{- end -}}
{{- end -}}

{{/* Label selector for this release's series in PromQL. */}}
{{- define "limitplane.promSelector" -}}
namespace="{{ .Release.Namespace }}",service="{{ include "limitplane.fullname" . }}"
{{- end -}}
