{{- define "ntk.fullname" -}}{{ .Release.Name }}-ntk-rag{{- end -}}
{{- define "ntk.labels" -}}
app.kubernetes.io/name: ntk-rag
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "ntk.selector" -}}
app.kubernetes.io/name: ntk-rag
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "ntk.usersSecret" -}}
{{- if .Values.security.existingUsersSecret -}}{{ .Values.security.existingUsersSecret }}{{- else -}}{{ include "ntk.fullname" . }}-users{{- end -}}
{{- end -}}
