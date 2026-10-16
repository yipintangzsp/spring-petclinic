import unittest
import hashlib
import subprocess
from unittest.mock import MagicMock, patch
from clinic_task import parse_spark_result, cpu_request_milli, pod_cpu_request_milli, restore_build_services, finite_input, publish_orchestrated, quality, release_guard, validate_snapshot, window


class QualityChecks(unittest.TestCase):
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

    def test_watermark(self):
        b = self.batch(); b['watermark'] = 1
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


if __name__ == '__main__':
    unittest.main()
