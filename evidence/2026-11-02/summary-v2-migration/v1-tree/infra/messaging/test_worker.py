import datetime
import io
from contextlib import redirect_stdout
import json
import unittest
from unittest.mock import Mock
import worker


class ProtocolTests(unittest.TestCase):
    def test_business_logs_preserve_the_existing_ecs_service_object_mapping(self):
        output=io.StringIO()
        with redirect_stdout(output):worker.log('success',event_id='visit-42',attempt=1)
        event=json.loads(output.getvalue())
        self.assertEqual(event['service'],{'name':'clinic-message-worker'})
        self.assertEqual(event['event_id'],'visit-42')
        self.assertEqual(event['action'],'success')
        self.assertIsNotNone(datetime.datetime.fromisoformat(event['at']).tzinfo)

    def test_inclusive_window_is_bounded_and_reversed_rejected(self):
        self.assertEqual(worker.parse_window({'from':'2026-01-01','to':'2026-12-31'}),
                         (datetime.date(2026,1,1),datetime.date(2026,12,31)))
        for start,end in [('2026-02-01','2026-01-01'),('2025-01-01','2026-12-31')]:
            with self.assertRaises(ValueError):worker.parse_window({'from':start,'to':end})

    def test_retry_stops_after_three_attempts(self):
        self.assertEqual(worker.next_state(1),('retrying',5))
        self.assertEqual(worker.next_state(2),('retrying',10))
        self.assertEqual(worker.next_state(3),('failed',0))
        self.assertEqual(worker.next_state(100),('failed',0))

    def test_envelope_identity_schema_and_size_checked_before_any_database_use(self):
        valid={'schema_version':1,'event_id':'visit-1','kind':'visit_followup','delivery_version':1,'payload':{}}
        self.assertEqual(worker.decode_envelope(json.dumps(valid).encode(),'visit-1'),valid)
        for bad in [None, [], {**valid,'delivery_version':True}, {**valid,'delivery_version':0}, {**valid,'schema_version':2},{**valid,'event_id':'spoofed'},
                    {**valid,'kind':'shell_command'},{**valid,'delivery_version':'1'}]:
            with self.assertRaises(ValueError):worker.decode_envelope(json.dumps(bad).encode(),'visit-1')
        with self.assertRaises(ValueError):worker.decode_envelope(b'x'*8193,'visit-1')

    def test_invalid_message_is_dead_lettered_without_database_write(self):
        db=Mock();channel=Mock();method=Mock(delivery_tag=42);properties=Mock(message_id='visit-1')
        worker.consume(db,channel,method,properties,b'{}')
        db.cursor.assert_not_called();channel.basic_nack.assert_called_once_with(42,requeue=False)
        channel.basic_ack.assert_not_called()


if __name__=='__main__':unittest.main()
