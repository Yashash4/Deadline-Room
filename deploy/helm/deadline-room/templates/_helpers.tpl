{{/* Common labels for every Deadline Room workload. */}}
{{- define "deadline-room.labels" -}}
app.kubernetes.io/name: deadline-room
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* The image reference for a given role target (service, warden, drafter). */}}
{{- define "deadline-room.image" -}}
{{- printf "%s-%s:%s" .repo .role .tag -}}
{{- end -}}
