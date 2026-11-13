"""Read the existing annual chart through Superset's authenticated API handler."""
import json
import sys

from superset import appbuilder, db
from superset.app import create_app
app = create_app()
from superset.models.dashboard import Dashboard
from superset.connectors.sqla.models import SqlaTable
from sqlalchemy.orm.attributes import set_committed_value
with app.app_context():
    admin = appbuilder.sm.find_user(username='admin')
    dashboard = db.session.query(Dashboard).filter_by(slug='petclinic-analytics-20261011').one()
    charts = [chart for chart in dashboard.slices if chart.viz_type == 'big_number_total']
    if admin is None or len(charts) != 1:
        raise RuntimeError('Existing admin or unique annual chart is missing')
    chart = charts[0]
    target_run = sys.argv[1] if len(sys.argv) > 1 else None
    if target_run:
        if len(target_run) > 200:
            raise ValueError('Invalid bounded verification run ID')
        # The verification process uses the existing chart and datasource with
        # an explicit staged batch. This changes only its in-memory ORM value:
        # it does not mark the dataset dirty or persist a dashboard modification.
        dataset = chart.datasource
        staged_sql = ("SELECT stat_date,visits FROM clinic.petclinic_analytics.daily_visits "
                      "WHERE run_id='" + target_run.replace("'", "''") + "'")
        query_builder = SqlaTable.get_sqla_query

        def staged_query(table, *args, **kwargs):
            if table.id != dataset.id:
                return query_builder(table, *args, **kwargs)
            original_sql = table.sql
            set_committed_value(table, 'sql', staged_sql)
            try:
                if table in db.session.dirty:
                    raise RuntimeError('Verification must not update the stored datasource')
                return query_builder(table, *args, **kwargs)
            finally:
                set_committed_value(table, 'sql', original_sql)

        # Requests use their own scoped ORM session. Limit the substitution to
        # SQL construction in this verification process, then restore it.
        SqlaTable.get_sqla_query = staged_query
    form = json.loads(chart.params)
    payload = {
        'datasource': {'id': chart.datasource_id, 'type': 'table'},
        'force': True, 'result_format': 'json', 'result_type': 'full',
        'form_data': {**form, 'slice_id': chart.id},
        'queries': [{'columns': [], 'metrics': [form['metric']], 'row_limit': 1,
                     'time_range': 'No filter', 'is_timeseries': False,
                     'extras': {'where': '', 'having': ''}}],
    }
    with app.test_client() as client:
        with client.session_transaction() as session:
            session['_user_id'] = str(admin.get_id())
            session['_fresh'] = True
        csrf = client.get('/api/v1/security/csrf_token/')
        if csrf.status_code != 200:
            raise RuntimeError(f'Superset CSRF endpoint returned {csrf.status_code}')
        response = client.post('/api/v1/chart/data', json=payload,
                               headers={'X-CSRFToken': csrf.get_json()['result']})
        body = response.get_json()
        if response.status_code != 200:
            raise RuntimeError(f'Superset chart returned {response.status_code}: {body}')
        queries = body.get('result', [])
        if len(queries) != 1 or queries[0].get('error') or queries[0].get('status') != 'success':
            raise RuntimeError(f'Superset chart query failed: {body}')
        if target_run and target_run.replace("'", "''") not in queries[0].get('query', ''):
            raise RuntimeError('Superset did not query the specified staged batch')
        rows = queries[0].get('data', [])
        if len(rows) != 1:
            raise RuntimeError('Superset annual chart returned no unique aggregate')
        total = int(rows[0][form['metric']])
        print('RESULT:' + json.dumps({'chart_id': chart.id, 'http_status': response.status_code,
                                     'run_id': target_run, 'annual_visits': total, 'response': body}))
    db.session.rollback()
