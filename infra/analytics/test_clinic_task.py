import unittest
from clinic_task import quality, window


class QualityChecks(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
