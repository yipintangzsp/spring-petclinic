"""Reconcile the existing Filebeat template's lab retention; never delete indices.

Run on the server with kubectl access. Existing backing indices are untouched.
ILM delete age is measured from rollover, so daily rollover retains about 7–8 days.
"""
import json
import subprocess

POLICY = 'petclinic-lab-filebeat-7d'
TEMPLATE = 'filebeat-9.4.4'


def api(path, body=None):
    command = ['kubectl', '-n', 'default', 'exec', '-i',
               'deploy/elasticsearch', '--', 'curl', '-fsS', '--max-time', '30']
    if body is not None:
        command += ['-X', 'PUT', '-H', 'Content-Type:application/json',
                    '--data-binary', '@-']
    command += ['http://127.0.0.1:9200/' + path]
    return json.loads(subprocess.check_output(
        command, input=json.dumps(body) if body is not None else '', text=True))


def main():
    template = api('_index_template/' + TEMPLATE)['index_templates'][0]['index_template']
    api('_ilm/policy/' + POLICY, {'policy': {'phases': {
        'hot': {'actions': {'rollover': {'max_age': '1d', 'max_primary_shard_size': '1gb'}}},
        'delete': {'min_age': '7d', 'actions': {'delete': {}}}}}})
    template['template']['settings']['index'].setdefault('lifecycle', {})['name'] = POLICY
    for key in ('created_date_millis', 'modified_date_millis'):
        template.pop(key, None)
    api('_index_template/' + TEMPLATE, template)
    print(json.dumps({'template': TEMPLATE, 'policy': POLICY, 'existing_indices_deleted': False}))


if __name__ == '__main__':
    main()
