"""Execute provisioned dashboard queries against real Prometheus and Loki APIs."""
import importlib.util
import json
import sys
from pathlib import Path

import yaml

spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('audit-production.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
resource = yaml.safe_load(Path(sys.argv[1]).read_text())
dashboard = json.loads(next(iter(resource['data'].values())))
result = []
for panel in dashboard['panels']:
    for target in panel.get('targets', []):
        expr = target['expr'].replace('$__rate_interval', '5m')
        if panel['datasource']['type'] == 'loki':
            response = audit.query('http://10.43.7.197:3100', '/loki/api/v1/query_range',
                                   {'query': expr, 'since': '1h', 'limit': '5'})
        else:
            response = audit.query('http://10.43.111.46:9090', '/api/v1/query', {'query': expr})
        assert response['status'] == 'success', panel['title']
        count = len(response['data']['result'])
        # Error logs may legitimately be empty. Metric series must exist.
        if panel['datasource']['type'] == 'prometheus':
            assert count > 0, panel['title']
        result.append({'panel': panel['title'], 'query': expr, 'status': response['status'],
                       'series': count})
Path(sys.argv[2]).write_text(json.dumps(result, indent=2))
print('PASS:', len(result), 'real dashboard queries; UID:', dashboard['uid'])
