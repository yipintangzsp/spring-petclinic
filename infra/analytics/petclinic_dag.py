"""Manual-only, single-run Petclinic analysis on the installed Airflow 3 SDK."""
import datetime as dt
import time
from airflow.sdk import dag, task, get_current_context, Param

from clinic_task import extract, quality, publish


@dag(dag_id='petclinic_insights', schedule=None, catchup=False,
     start_date=dt.datetime(2026, 10, 11, tzinfo=dt.timezone.utc), max_active_runs=1,
     max_active_tasks=1, dagrun_timeout=dt.timedelta(minutes=5),
     default_args={'retries': 1, 'retry_delay': dt.timedelta(seconds=15),
                   'execution_timeout': dt.timedelta(seconds=90)},
     params={'from': Param('2026-01-01', type='string', format='date'),
             'to': Param('2026-12-31', type='string', format='date'),
             'verify_retry': Param('none', enum=['none', 'retry', 'timeout'])},
     tags=['petclinic', 'manual', 'bounded'])
def insights():
    @task(show_return_value_in_logs=False)
    def bounded_read():
        context = get_current_context()
        params = context['params']
        # Manual acceptance probes run before any result writes. The second
        # attempt executes the normal bounded read after the scheduler retry.
        if context['ti'].try_number == 1:
            if params['verify_retry'] == 'retry':
                raise RuntimeError('Controlled first-attempt retry probe')
            if params['verify_retry'] == 'timeout':
                time.sleep(95)
        return extract(params['from'], params['to'])

    @task(show_return_value_in_logs=False)
    def data_quality(batch):
        return quality(batch)

    @task(show_return_value_in_logs=False)
    def incremental_publish(batch):
        return publish(batch, get_current_context()['run_id'])

    incremental_publish(data_quality(bounded_read()))


insights()
