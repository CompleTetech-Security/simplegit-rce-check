"""Run provenance survives every format and interrupted/empty reports offline."""
import contextlib
import csv
from datetime import datetime, timezone
import io
import json
import unittest
from unittest import mock

import simplegit_rce_check as c


class ReportProvenanceTests(unittest.TestCase):
    instant = datetime(2026, 10, 25, 20, 55, 49, tzinfo=timezone.utc)

    def test_one_injected_clock_instant_across_cli_formats_and_rows(self):
        timestamp = self.instant.isoformat()
        for fmt in ('csv', 'json', 'html'):
            with self.subTest(format=fmt), mock.patch.object(c, 'datetime') as clock:
                clock.now.return_value = self.instant
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    code = c.main(['--version', '4.0.0', '--version', '3.35.9', '--format', fmt])
                self.assertEqual(0, code)
                clock.now.assert_called_once_with(timezone.utc)
                text = output.getvalue()
                if fmt == 'csv':
                    rows = list(csv.DictReader(io.StringIO(text)))
                    self.assertEqual(2, len(rows))
                    for row in rows:
                        self.assertEqual((c.TOOL_NAME, c.TOOL_VERSION, timestamp),
                                         (row['tool'], row['tool_version'], row['generated_at']))
                        self.assertEqual('not_tested', row['exploitability'])
                        self.assertEqual(c.RULES_DATE, row['rules_as_of'])
                elif fmt == 'json':
                    report = json.loads(text)
                    self.assertEqual((c.TOOL_NAME, c.TOOL_VERSION, timestamp),
                                     (report['tool'], report['tool_version'], report['generated_at']))
                else:
                    self.assertIn(timestamp, text)
                    self.assertIn(c.TOOL_NAME + ' ' + c.TOOL_VERSION, text)

    def test_empty_complete_and_interrupted_summaries_retain_provenance(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                output = io.StringIO()
                c.write_report(output, [], complete=complete, generated_at=self.instant.isoformat())
                rows = list(csv.DictReader(io.StringIO(output.getvalue())))
                self.assertEqual(1, len(rows))
                row = rows[0]
                self.assertEqual('summary', row['record_type'])
                self.assertEqual(str(complete).lower(), row['report_complete'])
                self.assertEqual(c.TOOL_NAME, row['tool'])
                self.assertEqual(c.TOOL_VERSION, row['tool_version'])
                self.assertEqual(self.instant.isoformat(), row['generated_at'])
                self.assertEqual('', row['status'])

    def test_cli_interruption_before_and_after_first_result_keeps_run_time(self):
        original = c.assess_entry
        for count in (0, 1):
            with self.subTest(completed=count), mock.patch.object(c, 'datetime') as clock:
                clock.now.return_value = self.instant
                calls = 0
                def assess(*args, **kwargs):
                    nonlocal calls
                    if calls == count:
                        raise KeyboardInterrupt
                    calls += 1
                    return original(*args, **kwargs)
                with mock.patch.object(c, 'assess_entry', side_effect=assess), \
                     contextlib.redirect_stdout(io.StringIO()) as output, \
                     contextlib.redirect_stderr(io.StringIO()):
                    code = c.main(['--version', '4.0.0', '--version', '4.0.0'])
                self.assertEqual(130, code)
                clock.now.assert_called_once_with(timezone.utc)
                rows = list(csv.DictReader(io.StringIO(output.getvalue())))
                self.assertEqual(1, len(rows))
                self.assertEqual('result' if count else 'summary', rows[0]['record_type'])
                self.assertEqual('false', rows[0]['report_complete'])
                self.assertEqual(self.instant.isoformat(), rows[0]['generated_at'])

    def test_row_metadata_cannot_replace_report_provenance(self):
        row = c.assess_entry('=synthetic', 'inventory', '4.0.0')
        row.update(tool='=forged', tool_version='=forged', generated_at='=forged')
        output = io.StringIO()
        c.write_report(output, [row], generated_at=self.instant.isoformat())
        result = next(csv.DictReader(io.StringIO(output.getvalue())))
        self.assertEqual(c.TOOL_NAME, result['tool'])
        self.assertEqual(c.TOOL_VERSION, result['tool_version'])
        self.assertEqual(self.instant.isoformat(), result['generated_at'])
        self.assertEqual("'=synthetic", result['input_label'])


if __name__ == '__main__':
    unittest.main()
