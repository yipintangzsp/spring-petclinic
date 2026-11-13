"""Serial, bounded Petclinic Spark/Flink business analysis."""
import datetime as dt
import os

import pendulum
from airflow.providers.cncf.kubernetes.sensors.spark_kubernetes import SparkKubernetesSensor
from airflow.sdk import Param, dag, get_current_context, task

from clinic_task import (acquire_guard, check_resources, complete_execution, create_snapshot, publish_orchestrated,
                         release_guard, run_flink_bounded, submit_spark, validate_snapshot,
                         verify_spark, verify_trino_and_superset)


class GuardedSparkSensor(SparkKubernetesSensor):
    def poke(self, context):
        check_resources()
        return super().poke(context)


@dag(dag_id='petclinic_insights', schedule=os.environ.get('PETCLINIC_ANALYTICS_SCHEDULE') or None, catchup=False,
     start_date=pendulum.datetime(2026, 10, 12, tz='Asia/Shanghai'), max_active_runs=1,
     max_active_tasks=1, dagrun_timeout=dt.timedelta(minutes=60),
     default_args={'retries': 1, 'retry_delay': dt.timedelta(seconds=20),
                   'execution_timeout': dt.timedelta(minutes=12)},
     params={'from': Param('2026-01-01', type='string', format='date'),
             'to': Param('2026-12-31', type='string', format='date'),
             'verify_retry': Param('none', enum=['none', 'retry', 'fail'])},
     tags=['petclinic', 'spark', 'flink', 'bounded', 'business'])
def insights():
    @task(show_return_value_in_logs=False)
    def acquire():
        context = get_current_context()
        return acquire_guard(context['params']['from'], context['params']['to'], context['run_id'])

    @task(show_return_value_in_logs=False)
    def snapshot(guard):
        return create_snapshot(guard)

    @task(show_return_value_in_logs=False)
    def validate(value):
        context = get_current_context()
        return validate_snapshot(value, context['params']['from'], context['params']['to'],
                                 False, context['ti'].try_number)

    @task(show_return_value_in_logs=False)
    def spark_submit(value):
        context = get_current_context()
        return submit_spark(value, context['params']['from'], context['params']['to'])

    @task(show_return_value_in_logs=False)
    def spark_result(value, baseline, application):
        return verify_spark(value, baseline, application)

    @task(show_return_value_in_logs=False)
    def flink(value, baseline, spark):
        del spark
        context = get_current_context()
        return run_flink_bounded(value, baseline, context['params']['verify_retry'], context['ti'].try_number)

    @task(show_return_value_in_logs=False)
    def publish(value, flink_result):
        del flink_result
        context = get_current_context()
        return publish_orchestrated(value, context['params']['from'], context['params']['to'], context['run_id'])

    @task(show_return_value_in_logs=False)
    def verify(value, baseline, published):
        del published
        return verify_trino_and_superset(value, baseline)

    @task(show_return_value_in_logs=False)
    def complete(value, verification, released):
        del verification
        if not released.get('released'):
            raise RuntimeError('Compute cleanup did not complete; keep results pending')
        return complete_execution(value)

    # Compute exit (up to two minutes), Sonar startup (ten), and API/exit margin.
    @task(trigger_rule='all_done', retries=0, execution_timeout=dt.timedelta(minutes=15),
          show_return_value_in_logs=False)
    def cleanup():
        context = get_current_context()
        guard = context['ti'].xcom_pull(task_ids='acquire')
        value = context['ti'].xcom_pull(task_ids='snapshot')
        verified = context['ti'].xcom_pull(task_ids='verify')
        failed = not verified
        error = 'Upstream verification did not complete; inspect task attempts in Airflow' if failed else None
        if guard is None:
            return {'released': False, 'reason': 'admission did not acquire the shared Lease'}
        return release_guard(guard, value, failed, error)

    @task(trigger_rule='one_failed', retries=0)
    def failure_status():
        context = get_current_context()
        value = context['ti'].xcom_pull(task_ids='snapshot')
        if value:
            from clinic_task import _execution
            _execution(value['batch_id'], 'failed', 'failed', error='A task failed; inspect task attempts and cleanup status')
        # An all_done cleanup leaf must not turn a failed business run green.
        raise RuntimeError('Analysis failed; cleanup ran independently. Inspect the failed task and its logs.')

    guard = acquire()
    value = snapshot(guard)
    baseline = validate(value)
    application = spark_submit(value)
    baseline >> application
    spark_wait = GuardedSparkSensor(
        task_id='wait_for_spark', application_name=application, namespace='default',
        kubernetes_conn_id='kubernetes_default', attach_log=False, poke_interval=10,
        timeout=720, mode='reschedule')
    application >> spark_wait
    spark = spark_result(value, baseline, application)
    spark_wait >> spark
    flink_result = flink(value, baseline, spark)
    published = publish(value, flink_result)
    verification = verify(value, baseline, published)
    released = cleanup()
    guard >> released
    verification >> released
    done = complete(value, verification, released)
    failed = failure_status()
    for upstream in (guard, value, baseline, application, spark_wait, spark,
                     flink_result, published, verification, done, released):
        upstream >> failed


insights()
