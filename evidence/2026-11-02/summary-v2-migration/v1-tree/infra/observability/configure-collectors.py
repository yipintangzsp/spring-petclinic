"""Apply narrow changes to existing collectors; keep original backups for rollback."""
import json,subprocess
from pathlib import Path
root=Path('/opt/petclinic-observability');backup=root/'backup';backup.mkdir(exist_ok=True)
def kube(*args):return json.loads(subprocess.check_output(['kubectl',*args,'-o','json'],text=True))
def apply(obj):subprocess.run(['kubectl','apply','-f','-'],input=json.dumps(obj),text=True,check=True)
cm=kube('get','cm','filebeat-config','-n','default');p=backup/'filebeat-config.json'
if not p.exists():p.write_text(json.dumps(cm))
config=cm['data']['filebeat.yml']
if 'petclinic_' not in config:
 config+='''
processors:
  - decode_json_fields:
      fields: ["message"]
      target: ""
      overwrite_keys: true
      expand_keys: true
      add_error_key: true
      when:
        and:
          - contains:
              log.file.path: "/petclinic_"
          - regexp:
              message: '^[{]'
'''
 cm['data']['filebeat.yml']=config;apply(cm)
if 'from: "traceId"' not in config:
 config+='''
  - rename:
      fields:
        - from: "traceId"
          to: "trace.id"
        - from: "spanId"
          to: "span.id"
      ignore_missing: true
      fail_on_error: false
      when:
        contains:
          log.file.path: "/petclinic_"
'''
 cm['data']['filebeat.yml']=config;apply(cm)
cm=kube('get','cm','otel-collector-config','-n','monitoring');p=backup/'otel-collector-config.json'
if not p.exists():p.write_text(json.dumps(cm))
config=cm['data']['config.yaml']
if 'otlphttp/jaeger' not in config:
 config=config.replace('exporters:\n','exporters:\n  otlphttp/jaeger:\n    endpoint: http://jaeger.monitoring.svc.cluster.local:4318\n',1)
 config=config.replace('    traces:\n      receivers: [otlp]\n      processors: [batch]\n      exporters: [debug]','    traces:\n      receivers: [otlp]\n      processors: [batch]\n      exporters: [otlphttp/jaeger, debug]')
 cm['data']['config.yaml']=config;apply(cm)
print('Collector configuration applied; restart only affected running collectors after validation.')
