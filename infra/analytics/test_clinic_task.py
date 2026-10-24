import unittest
import hashlib
import ast
import copy
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import subprocess
from unittest.mock import MagicMock, patch
from clinic_task import parse_spark_result, cpu_request_milli, pod_cpu_request_milli, restore_build_services, finite_input, publish_orchestrated, quality, release_guard, validate_snapshot, window


class QualityChecks(unittest.TestCase):
    def test_disk_budget_keeps_eviction_margin_and_task_allowance(self):
        from clinic_task import disk_required_mib
        self.assertEqual(disk_required_mib(250 * 1024), 45.5 * 1024)
        for missing in (None, 0, -1):
            with self.assertRaises(ValueError):
                disk_required_mib(missing)

    def test_spark_submits_both_roles_with_admitted_cpu_requests(self):
        import clinic_task
        custom = MagicMock()
        with patch.object(clinic_task, '_kube', return_value=(None, None, custom, None)), \
             patch.object(clinic_task, '_execution'):
            clinic_task.submit_spark({'execution_id': 'budget-check', 'batch_id': 'bounded',
                                     'config_map': 'snapshot'}, '2026-01-01', '2026-12-31')
        body = custom.create_namespaced_custom_object.call_args.args[-1]
        total = sum(cpu_request_milli(body['spec'][role]['coreRequest']) for role in ('driver', 'executor'))
        self.assertEqual(total, 2 * clinic_task.SPARK_ROLE_CPU_MILLI)
        self.assertEqual(total + clinic_task.COMPUTE_CPU_RESERVE_MILLI, 1750)
        for role in ('driver', 'executor'):
            self.assertEqual(body['spec'][role]['cores'], 1)
            self.assertEqual(body['spec'][role]['coreLimit'], '1000m')

    def test_finite_remote_input_handles_a_real_batch_above_linux_single_argument_limit(self):
        body = ('{"snapshot_id":"bounded","visit_id":1234,"visit_date":"2026-10-11"}\n' * 2300)
        command = finite_input(['cat'], body)
        self.assertLess(max(len(argument.encode()) for argument in command), 128 * 1024)
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(result.stdout, body)

    def test_cpu_units_round_up_for_safe_scheduler_accounting(self):
        for value, expected in [('1', 1000), ('0.125', 125), ('100m', 100),
                                ('100000u', 100), ('100000001n', 101)]:
            self.assertEqual(cpu_request_milli(value), expected)

    def test_cpu_budget_includes_native_sidecars_init_peak_and_overhead(self):
        pod = {'spec': {'containers': [{'resources': {'requests': {'cpu': '100m'}}}],
                       'initContainers': [
                           {'restartPolicy': 'Always', 'resources': {'requests': {'cpu': '20m'}}},
                           {'resources': {'requests': {'cpu': '200m'}}}],
                       'overhead': {'cpu': '5m'}}}
        self.assertEqual(pod_cpu_request_milli(pod), 225)

    def test_sonar_foreign_owner_cannot_be_restored_or_scaled(self):
        core, apps, custom, coordination = [MagicMock() for _ in range(4)]
        lease = coordination.read_namespaced_lease.return_value
        lease.metadata.uid = 'lease'; lease.spec.holder_identity = 'ours'
        lease.metadata.annotations = {'petclinic.devops.local/paused-sonar': '{"uid":"sonar","replicas":1}'}
        item = apps.read_namespaced_stateful_set.return_value
        item.metadata.uid = 'sonar'
        item.metadata.annotations = {'petclinic.devops.local/analysis-holder': 'someone-else'}
        with patch('clinic_task._kube', return_value=(core, apps, custom, coordination)):
            with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
                restore_build_services({'lease_uid': 'lease', 'holder': 'ours'})
        apps.patch_namespaced_stateful_set.assert_not_called()

    def test_spark_json_frame_accepts_a_following_unseparated_log_record(self):
        text = 'INFO start\nCLINIC_RESULT:{"event":"petclinic_spark_success","jobIds":[0,1],"inputRows":3}26/10/16 INFO shutdown\n'
        self.assertEqual(parse_spark_result(text)['inputRows'], 3)

    def test_spark_duplicate_business_frames_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            parse_spark_result('CLINIC_RESULT:{}\nCLINIC_RESULT:{}')

    def test_spark_truncated_frame_cannot_be_accepted(self):
        with self.assertRaises(ValueError):
            parse_spark_result('CLINIC_RESULT:{"event":"petclinic_spark_success","jobIds":[0,')

    def batch(self):
        return {'window_start': '2026-01-01', 'window_end': '2026-12-31', 'watermark': 0,
                'counts': {'pets': 1}, 'visits': [{'id': 1, 'date': '2026-10-11',
                'pet_id': 1, 'pet_exists': True}], 'types': [{'name': 'dog', 'pets': 1}], 'missing_type': 0}

    def test_valid_boundary(self):
        self.assertEqual(quality(self.batch())['visits'][0]['id'], 1)

    def test_missing_foreign_key(self):
        b = self.batch(); b['visits'][0]['pet_exists'] = False
        with self.assertRaises(ValueError): quality(b)

    def test_duplicate_input(self):
        b = self.batch(); b['visits'] *= 2
        with self.assertRaises(ValueError): quality(b)

    def test_invalid_window(self):
        with self.assertRaises(ValueError): window('2026-10-12', '2026-10-11')
        with self.assertRaises(ValueError): window('2025-01-01', '2026-12-31')

    def test_non_reconciling_dimensions(self):
        b = self.batch(); b['counts']['pets'] = 2
        with self.assertRaises(ValueError): quality(b)

    def test_late_or_corrected_visit_below_watermark_is_valid(self):
        b = self.batch(); b['watermark'] = 1001195
        self.assertEqual(quality(b)['visits'][0]['id'], 1)

    def test_nonpositive_or_noninteger_visit_id_is_rejected(self):
        for invalid in (0, -1, True, '1'):
            b = self.batch(); b['visits'][0]['id'] = invalid
            with self.assertRaises(ValueError): quality(b)

    def test_changed_source_cannot_publish(self):
        batch = self.batch()
        batch['source_sha256'] = 'changed'
        with patch('clinic_task.extract', return_value=batch), patch('clinic_task.publish') as writer:
            with self.assertRaisesRegex(ValueError, 'Source changed'):
                publish_orchestrated({'sha256': 'captured'}, '2026-01-01', '2026-12-31', 'run')
            writer.assert_not_called()

    def test_changed_dimensions_cannot_reuse_an_unchanged_visit_snapshot(self):
        batch = self.batch()
        batch.update(source_sha256='unchanged', source_metadata_sha256='new-pet-dimensions')
        with patch('clinic_task.extract', return_value=batch), patch('clinic_task.publish') as writer:
            with self.assertRaisesRegex(ValueError, 'Source changed'):
                publish_orchestrated({'sha256': 'unchanged', 'source_metadata_sha256': 'captured'},
                                     '2026-01-01', '2026-12-31', 'run')
            writer.assert_not_called()

    def test_foreign_lease_prevents_cleanup(self):
        core, apps, custom, coordination = [MagicMock() for _ in range(4)]
        lease = coordination.read_namespaced_lease.return_value
        lease.metadata.uid = 'foreign-uid'
        lease.spec.holder_identity = 'another-run'
        with patch('clinic_task._kube', return_value=(core, apps, custom, coordination)):
            with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
                release_guard({'lease_uid': 'our-uid', 'holder': 'our-run'}, {'batch_id': 'batch'})
        apps.patch_namespaced_deployment_scale.assert_not_called()
        custom.delete_namespaced_custom_object.assert_not_called()
        coordination.delete_namespaced_lease.assert_not_called()

    def test_mysql_type_mismatch_cannot_pass_an_equal_total(self):
        text = 'visit_id,visit_date,pet_id,pet_type\n1,2026-10-11,1,dog\n'
        snapshot = {'input_rows': 1, 'unique_visit_ids': 1, 'config_map': 'owned',
                    'batch_id': 'bounded', 'sha256': hashlib.sha256(text.encode()).hexdigest()}
        core = MagicMock()
        core.read_namespaced_config_map.return_value.data = {'visits.csv': text}
        with patch('clinic_task._kube', return_value=(core, None, None, None)), \
                patch('clinic_task._exec', return_value='counts\t1\t1\t1\ntype\tcat\t1\n'), \
                patch('clinic_task._execution') as status:
            with self.assertRaisesRegex(ValueError, 'MySQL baseline mismatch'):
                validate_snapshot(snapshot, '2026-01-01', '2026-12-31')
            status.assert_not_called()


class SonarRestorationChecks(unittest.TestCase):
    def setUp(self):
        self.clock = 0
        self.ready_at = 270
        self.foreign_owner_at = None
        self.foreign_uid_at = None
        self.generation_at = 0
        self.replicas = 0
        self.owner = 'ours'
        self.guard = {'lease_uid': 'lease', 'holder': 'ours', 'owned_quiet': True}
        self.original = {'uid': 'sonar', 'replicas': 1}
        self.core, self.apps, self.custom, self.coordination = [MagicMock() for _ in range(4)]
        self.lease = {'metadata': {'uid': 'lease', 'annotations': {
            'petclinic.devops.local/paused-sonar': json.dumps(self.original)}},
            'spec': {'holderIdentity': 'ours'}}
        self.coordination.read_namespaced_lease.return_value = SimpleNamespace(
            metadata=SimpleNamespace(uid='lease', annotations=self.lease['metadata']['annotations']),
            spec=SimpleNamespace(holder_identity='ours'))
        self.core.list_namespaced_config_map.return_value.items = []
        self.apps.read_namespaced_stateful_set.side_effect = self.read_item
        self.apps.patch_namespaced_stateful_set.side_effect = self.patch_item
        self.monotonic = patch('clinic_task.time.monotonic', side_effect=lambda: self.clock)
        self.sleep = patch('clinic_task.time.sleep', side_effect=self.advance)
        self.monotonic.start()
        self.sleep.start()
        self.addCleanup(self.monotonic.stop)
        self.addCleanup(self.sleep.stop)

    def advance(self, seconds):
        self.clock += seconds

    def state(self):
        owner = 'foreign' if self.foreign_owner_at is not None and self.clock >= self.foreign_owner_at else self.owner
        uid = 'foreign-uid' if self.foreign_uid_at is not None and self.clock >= self.foreign_uid_at else 'sonar'
        return {'metadata': {'uid': uid, 'generation': 2,
                             'annotations': {'petclinic.devops.local/analysis-holder': owner}},
                'spec': {'replicas': self.replicas},
                'status': {'readyReplicas': int(self.clock >= self.ready_at),
                           'observedGeneration': 2 if self.clock >= self.generation_at else 1}}

    def read_item(self, *args, **kwargs):
        state = self.state()
        return SimpleNamespace(metadata=SimpleNamespace(**state['metadata']),
                               spec=SimpleNamespace(**state['spec']),
                               status=SimpleNamespace(ready_replicas=state['status']['readyReplicas'],
                                                      observed_generation=state['status']['observedGeneration']))

    def patch_item(self, *args):
        for operation in args[-1]:
            if operation['op'] == 'replace' and operation['path'] == '/spec/replicas':
                self.replicas = operation['value']
            if operation['op'] == 'remove':
                self.owner = None

    def kube(self, command):
        if command[2] == 'get':
            return copy.deepcopy(self.state())
        if command[2] == 'patch':
            self.patch_item(json.loads(command[-1]))
            return {}
        raise AssertionError(command)

    def release(self, jenkins):
        # These tests need the exception type only; no Kubernetes client or network is used.
        class ApiException(Exception):
            pass
        modules = {'kubernetes': MagicMock(), 'kubernetes.client': MagicMock(),
                   'kubernetes.client.exceptions': SimpleNamespace(ApiException=ApiException)}
        with patch('clinic_task._kube', return_value=(self.core, self.apps, self.custom, self.coordination)), \
                patch('clinic_task._jenkins', jenkins), patch.dict(sys.modules, modules):
            return release_guard(self.guard)

    def test_slow_sonar_startup_releases_guards_only_after_ready(self):
        def resumed(*args):
            self.assertGreater(self.clock, 200)
            self.assertGreaterEqual(self.clock, self.ready_at)
        jenkins = MagicMock(side_effect=resumed)
        result = self.release(jenkins)
        self.assertTrue(result['released'])
        self.assertEqual(result['sonar_restore']['elapsed_seconds'], 270)
        self.assertEqual(result['sonar_restore']['last_state']['ready_replicas'], 1)
        self.assertIsNone(self.owner)
        jenkins.assert_called_once_with('/cancelQuietDown', 'POST')
        self.coordination.delete_namespaced_lease.assert_called_once()

    def test_never_ready_sonar_preserves_lease_and_jenkins_pause(self):
        self.ready_at = float('inf')
        jenkins = MagicMock()
        with self.assertRaisesRegex(RuntimeError, 'readiness not restored.*elapsed_seconds=600.*last_state='):
            self.release(jenkins)
        self.assertEqual(self.clock, 600)
        self.assertEqual(self.owner, 'ours')
        jenkins.assert_not_called()
        self.coordination.delete_namespaced_lease.assert_not_called()

    def test_owner_change_while_waiting_preserves_guards(self):
        self.foreign_owner_at = 6
        jenkins = MagicMock()
        with self.assertRaisesRegex(RuntimeError, 'ownership changed while restoring'):
            self.release(jenkins)
        self.assertEqual(self.clock, 6)
        self.assertEqual(self.owner, 'ours')
        jenkins.assert_not_called()
        self.coordination.delete_namespaced_lease.assert_not_called()

    def test_uid_change_while_waiting_preserves_guards(self):
        self.foreign_uid_at = 6
        jenkins = MagicMock()
        with self.assertRaisesRegex(RuntimeError, 'UID changed while restoring'):
            self.release(jenkins)
        jenkins.assert_not_called()
        self.coordination.delete_namespaced_lease.assert_not_called()

    def test_stale_ready_status_waits_for_observed_generation(self):
        self.ready_at = 0
        self.generation_at = 270
        result = self.release(MagicMock())
        self.assertEqual(result['sonar_restore']['elapsed_seconds'], 270)
        self.assertEqual(result['sonar_restore']['last_state']['observed_generation'], 2)

    def test_abort_restoration_records_slow_startup_evidence(self):
        from run_airflow import restore_owned_sonar
        with tempfile.TemporaryDirectory() as directory, patch('run_airflow.kube', side_effect=self.kube):
            evidence = Path(directory)
            restore_owned_sonar(self.lease, evidence)
            result = json.loads((evidence / 'abort-sonar-restored.json').read_text())
        self.assertTrue(result['ready'])
        self.assertEqual(result['restoration']['elapsed_seconds'], 270)
        self.assertEqual(result['restoration']['last_state']['ready_replicas'], 1)
        self.assertIsNone(self.owner)

    def test_abort_timeout_cannot_clear_owner_or_claim_restoration(self):
        from run_airflow import restore_owned_sonar
        self.ready_at = float('inf')
        with tempfile.TemporaryDirectory() as directory, patch('run_airflow.kube', side_effect=self.kube):
            evidence = Path(directory)
            with self.assertRaisesRegex(RuntimeError, 'readiness not restored'):
                restore_owned_sonar(self.lease, evidence)
            self.assertFalse((evidence / 'abort-sonar-restored.json').exists())
        self.assertEqual(self.clock, 600)
        self.assertEqual(self.owner, 'ours')

    def test_abort_owner_change_cannot_clear_owner_or_claim_restoration(self):
        from run_airflow import restore_owned_sonar
        self.foreign_owner_at = 6
        with tempfile.TemporaryDirectory() as directory, patch('run_airflow.kube', side_effect=self.kube):
            evidence = Path(directory)
            with self.assertRaisesRegex(RuntimeError, 'ownership changed while restoring'):
                restore_owned_sonar(self.lease, evidence)
            self.assertFalse((evidence / 'abort-sonar-restored.json').exists())
        self.assertEqual(self.clock, 6)
        self.assertEqual(self.owner, 'ours')

    def test_deadlines_cover_serial_compute_retry_cleanup_and_worker_margin(self):
        root = Path(__file__).parent
        dag = ast.parse((root / 'petclinic_dag.py').read_text())
        cleanup = next(node for node in ast.walk(dag) if isinstance(node, ast.FunctionDef) and node.name == 'cleanup')
        decorator = cleanup.decorator_list[0]
        timeout = next(value.value for value in decorator.keywords if value.arg == 'execution_timeout')
        cleanup_seconds = next(value.value.value for value in timeout.keywords if value.arg == 'minutes') * 60
        config = json.loads((root / 'airflow' / 'config.json').read_text())
        template = json.loads(config['data']['pod_template_file.yaml'])
        self.assertGreaterEqual(template['spec']['activeDeadlineSeconds'], cleanup_seconds + 180,
                                'Worker lifetime must cover cleanup plus startup and shutdown margin')

        definition = next(node for node in dag.body if isinstance(node, ast.FunctionDef) and node.name == 'insights')
        options = {value.arg: value.value for value in definition.decorator_list[0].keywords}
        dag_seconds = next(value.value.value for value in options['dagrun_timeout'].keywords
                           if value.arg == 'minutes') * 60
        defaults = {key.value: value for key, value in zip(options['default_args'].keys,
                                                          options['default_args'].values)}
        attempts = defaults['retries'].value + 1
        task_seconds = next(value.value.value for value in defaults['execution_timeout'].keywords
                            if value.arg == 'minutes') * 60
        spark_wait = next(node for node in ast.walk(definition) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Name) and node.func.id == 'GuardedSparkSensor')
        spark_seconds = next(value.value.value for value in spark_wait.keywords if value.arg == 'timeout')
        self.assertGreaterEqual(dag_seconds, spark_seconds + attempts * task_seconds + cleanup_seconds + 9 * 60,
                                'DAG must cover Spark, both Flink attempts, cleanup and nine minutes overhead')
        controller = ast.parse((root / 'run_airflow.py').read_text())
        wait_run = next(node for node in controller.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'wait_run')
        deadline = next(node.value for node in wait_run.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'deadline' for target in node.targets))
        self.assertGreaterEqual(deadline.right.value, dag_seconds + 5 * 60,
                                'Acceptance controller must outlive the DAG by five minutes')


class AirflowSerialStartup(unittest.TestCase):
    def test_scheduler_starts_only_after_api_and_processor_readiness(self):
        import run_airflow as controller
        events = []
        record = MagicMock()
        def switch(count, revision, active):
            events.append(('switch', tuple(active), count, revision))
        def ready(callback, names, deadline):
            self.assertIs(callback, record)
            self.assertEqual(deadline, 700)
            events.append(('ready', tuple(names)))
            callback()
        with patch.object(controller, 'switch', side_effect=switch), \
             patch.object(controller, 'wait_ready', side_effect=ready), \
             patch.object(controller.time, 'monotonic', return_value=100):
            controller.start_core_serially('released-source', record)
        expected = [('airflow-statsd', 'airflow-api-server'),
                    ('airflow-statsd', 'airflow-api-server', 'airflow-dag-processor'),
                    ('airflow-statsd', 'airflow-api-server', 'airflow-dag-processor', 'airflow-scheduler')]
        self.assertEqual([e[1] for e in events[::2]], expected)
        self.assertEqual([e[1] for e in events[1::2]], expected)
        self.assertTrue(all(e[2:] == (1, 'released-source') for e in events[::2]))
        self.assertEqual(record.call_count, 3)

    def test_failed_phase_cannot_enable_the_next_component(self):
        import run_airflow as controller
        with patch.object(controller, 'switch') as switch, \
             patch.object(controller, 'wait_ready', side_effect=RuntimeError('Safety stop')), \
             patch.object(controller.time, 'monotonic', return_value=100):
            with self.assertRaisesRegex(RuntimeError, 'Safety stop'):
                controller.start_core_serially('released-source', MagicMock())
        self.assertEqual(switch.call_count, 1)
        self.assertNotIn('airflow-scheduler', switch.call_args.kwargs['active'])

    def test_startup_phases_share_deadline_without_starting_late_components(self):
        import run_airflow as controller
        with patch.object(controller, 'switch') as switch, \
             patch.object(controller, 'wait_ready'), \
             patch.object(controller.time, 'monotonic', side_effect=[100, 100, 701]):
            with self.assertRaisesRegex(TimeoutError, 'deadline exceeded'):
                controller.start_core_serially('released-source', MagicMock())
        self.assertEqual(switch.call_count, 1)

    def test_staging_never_enables_triggerer_or_adds_replicas(self):
        from run_airflow import replicas
        result = {v['name']: v['count'] for v in replicas(1, ['airflow-api-server', 'airflow-statsd'])}
        self.assertEqual(result['airflow-api-server'], 1)
        self.assertEqual(result['airflow-statsd'], 1)
        self.assertEqual(result['airflow-scheduler'], 0)
        self.assertEqual(result['airflow-dag-processor'], 0)
        self.assertEqual(result['airflow-triggerer'], 0)
        self.assertTrue(all(v['count'] == 0 for v in replicas(0)))
        with self.assertRaises(ValueError):
            replicas(2)
        with self.assertRaises(ValueError):
            replicas(1, ['airflow-triggerer'])

    def test_expired_readiness_deadline_does_not_poll_or_hide_failure(self):
        import run_airflow as controller
        record = MagicMock()
        with patch.object(controller, 'kube') as kube, \
             patch.object(controller.time, 'monotonic', return_value=10):
            with self.assertRaisesRegex(RuntimeError, 'bounded startup deadline'):
                controller.wait_ready(record, names=['airflow-api-server'], deadline=9)
        kube.assert_not_called()
        record.assert_not_called()

    def test_old_ready_count_cannot_pass_before_desired_generation_is_observed(self):
        import run_airflow as controller
        original = {'metadata': {'generation': 4}, 'spec': {'replicas': 0},
                    'status': {'readyReplicas': 1, 'observedGeneration': 4}}
        stale = copy.deepcopy(original)
        stale['spec']['replicas'] = 1
        stale['status']['observedGeneration'] = 3
        current = copy.deepcopy(stale)
        current['status']['observedGeneration'] = 4
        record = MagicMock()
        with patch.object(controller, 'kube', side_effect=[original, stale, current]) as kube, \
             patch.object(controller.time, 'monotonic', return_value=100), \
             patch.object(controller.time, 'sleep') as sleep:
            controller.wait_ready(record, names=['airflow-api-server'], deadline=700)
        self.assertEqual(kube.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(record.call_count, 3)


if __name__ == '__main__':
    unittest.main()
