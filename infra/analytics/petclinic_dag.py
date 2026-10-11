"""Manual-only, single-run Petclinic analysis on the installed Airflow 3 SDK."""
import datetime as dt
from airflow.sdk import dag, task, get_current_context, Param

from clinic_task import extract, quality, publish


@dag(dag_id='petclinic_insights', schedule=None, catchup=False,
     start_date=dt.datetime(2026, 10, 11, tzinfo=dt.timezone.utc), max_active_runs=1,
     max_active_tasks=1, dagrun_timeout=dt.timedelta(minutes=5),
     default_args={'retries': 1, 'retry_delay': dt.timedelta(seconds=15),
                   'execution_timeout': dt.timedelta(seconds=90)},
     params={'from': Param('2026-01-01', type='string', format='date'),
             'to': Param('2026-12-31', type='string', format='date')},
     tags=['petclinic', 'manual', 'bounded'])
def insights():
    @task
    def bounded_read():
        params = get_current_context()['params']
        return extract(params['from'], params['to'])

    @task
    def data_quality(batch):
        return quality(batch)

    @task
    def incremental_publish(batch):
        return publish(batch, get_current_context()['run_id'])

    incremental_publish(data_quality(bounded_read()))


insights()
