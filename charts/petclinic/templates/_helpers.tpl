{{- define "petclinic.image" -}}
{{- $d := required "image.digest is required; tags never authorize deployment" .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $d) -}}{{ fail "invalid immutable digest" }}{{- end -}}
{{- printf "%s@%s" .Values.image.repository $d -}}
{{- end -}}
