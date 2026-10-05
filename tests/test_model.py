"""Frozen full reports, bounds, native no-hook admission and real CLI delivery."""
import ast
import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import unittest
from decimal import getcontext
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cli
import model

CASES = json.loads((ROOT / 'tests/oracles.json').read_text(encoding='ascii'))
BASE = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'


def sample(vectors=None):
    return {'schema_version': 1, 'profile': 'cvss31-base-v1',
            'vectors': [BASE] if vectors is None else vectors}


def admission():
    return {'schema_version': 1, 'profile': 'cvss31-base-v1', 'status': 'invalid',
            'reasons': [{'code': 'admission', 'pointer': ''}], 'results': []}


class Contract(unittest.TestCase):
    def test_frozen_reports(self):
        for case in CASES:
            with self.subTest(case=case['name']):
                self.assertEqual(model.interpret(case['input']), case['expected'])

    def test_frozen_raw_and_serialized_reports(self):
        for case in CASES:
            with self.subTest(case=case['name']):
                raw = json.dumps(case['input']).encode('utf-8')
                report = model.interpret(model.decode(raw))
                self.assertEqual(json.loads(model.serialize(report)), case['expected'])

    def test_freeze_hashes(self):
        receipt = json.loads((ROOT / 'research/oracle-freeze.json').read_text())
        self.assertEqual(receipt['cases'], 57)
        for entry in receipt['files']:
            raw = (ROOT / entry['path']).read_bytes()
            self.assertEqual(len(raw), entry['bytes'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry['sha256'])

    def test_input_preservation_and_detached_reports(self):
        data = sample([BASE, BASE + '/E:X'])
        before = copy.deepcopy(data)
        report = model.interpret(data)
        self.assertEqual(data, before)
        self.assertEqual(report['status'], 'unsupported')
        self.assertEqual(report['results'], [])
        good = sample()
        report = model.interpret(good)
        report['results'][0]['metric_values']['AV'] = 'P'
        report['results'][0]['input_metric_order'].clear()
        self.assertEqual(good, sample())
        self.assertEqual(model.interpret(good), CASES[1]['expected'])

    def test_optional_namespace_and_values(self):
        optional = {'E': 'XHFPU', 'RL': 'XUWTO', 'RC': 'XCRU',
                    'CR': 'XHML', 'IR': 'XHML', 'AR': 'XHML',
                    'MAV': 'XNALP', 'MAC': 'XLH', 'MPR': 'XNLH',
                    'MUI': 'XNR', 'MS': 'XUC', 'MC': 'XNLH', 'MI': 'XNLH', 'MA': 'XNLH'}
        for key, values in optional.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    data = sample([BASE + '/' + key + ':' + value])
                    before = copy.deepcopy(data)
                    report = model.interpret(data)
                    self.assertEqual(report['status'], 'unsupported')
                    self.assertEqual(report['reasons'], [{'code': 'optional_metric', 'pointer': '/vectors/0'}])
                    self.assertEqual(report['results'], [])
                    self.assertEqual(data, before)
            self.assertEqual(model.interpret(sample([BASE + '/' + key + ':Q']))['status'], 'invalid')

    def test_unsupported_priority_and_invalid_dominance(self):
        data = {**sample(['CVSS:4.0/text']), 'extra': None}
        data['schema_version'] = 2
        data['profile'] = 'future'
        report = model.interpret(data)
        self.assertEqual(report['reasons'], [{'code': 'unknown_field', 'pointer': '/extra'}])
        data['vectors'].append(BASE + '/ZZ:N')
        report = model.interpret(data)
        self.assertEqual(report['status'], 'invalid')
        self.assertEqual(report['reasons'], [{'code': 'unknown_metric', 'pointer': '/vectors/1'}])
        self.assertEqual(report['results'], [])

    def test_decimal_context_does_not_change_scores(self):
        ctx = getcontext()
        saved = ctx.copy()
        try:
            ctx.prec = 2
            for case in CASES[:15]:
                self.assertEqual(model.interpret(case['input']), case['expected'])
        finally:
            import decimal
            decimal.setcontext(saved)

    def test_roundup_boundary_helpers(self):
        for value, expected in [('4', '4.0'), ('4.02', '4.1'), ('4.000001', '4.1'), ('0', '0.0'), ('10', '10.0')]:
            self.assertEqual(model._roundup(Fraction(value)), expected)

    def test_reordering_and_repeat_determinism(self):
        for case in CASES[:15]:
            self.assertEqual(model.interpret(case['input']), model.interpret(case['input']))
        reversed_vector = 'CVSS:3.1/' + '/'.join(reversed(BASE.split('/')[1:]))
        row = model.interpret(sample([reversed_vector]))['results'][0]
        self.assertEqual(row['canonical_base_vector'], BASE)
        self.assertEqual(row['input_vector'], reversed_vector)
        self.assertEqual(row['input_metric_order'], ['A', 'I', 'C', 'S', 'UI', 'PR', 'AC', 'AV'])
        self.assertEqual(row['computed_base_score'], '9.8')


class Admission(unittest.TestCase):
    def test_raw_rejections(self):
        for raw in (b'', b'\xef\xbb\xbf{}', b'\xff', b'{"x":1,"x":2}', b'1.0', b'NaN',
                    b'Infinity', b'12345678901', b'-1234567890', b'"\\ud800"',
                    b'[' * 9 + b'0' + b']' * 9, b'{}x'):
            with self.subTest(raw=raw):
                with self.assertRaises(model.Invalid) as caught:
                    model.decode(raw)
                self.assertEqual(caught.exception.code, 'admission')

    def test_raw_byte_boundary(self):
        raw = json.dumps(sample([])).encode()
        fitted = raw + b' ' * (16384 - len(raw))
        self.assertEqual(model.interpret(model.decode(fitted)), CASES[0]['expected'])
        with self.assertRaises(model.Invalid):
            model.decode(fitted + b' ')

    def test_api_byte_amplification(self):
        data = {**sample([]), 'extra': ['\U0001f600' * 256] * 50}
        self.assertLess(len(json.dumps(data, ensure_ascii=False)), 16384)
        self.assertGreater(len(json.dumps(data, ensure_ascii=False).encode()), 16384)
        self.assertEqual(model.interpret(data), admission())

    def test_string_and_vector_limits(self):
        data = {**sample([]), 'extra': 'a' * 256}
        self.assertEqual(model.interpret(data)['status'], 'unsupported')
        data['extra'] += 'a'
        self.assertEqual(model.interpret(data), admission())
        vector = 'CVSS:4.0/' + 'x' * (256 - len('CVSS:4.0/'))
        self.assertEqual(model.interpret(sample([vector]))['status'], 'unsupported')
        self.assertEqual(model.interpret(sample([vector + 'x'])), admission())
        for value in (BASE + '\x1b', BASE + ' ', BASE + '\n', BASE + '\u00e9'):
            self.assertEqual(model.interpret(sample([value]))['status'], 'invalid')

    def test_integer_and_schema_shape(self):
        for value in (True, False, None, '1', []):
            self.assertEqual(model.interpret({**sample([]), 'schema_version': value})['reasons'],
                             [{'code': 'shape', 'pointer': '/schema_version'}])
        for value in (-1, 2147483648, 1.0, float('nan')):
            self.assertEqual(model.interpret({**sample([]), 'extra': value}), admission())
        self.assertEqual(model.interpret({**sample([]), 'schema_version': 2147483647})['status'], 'unsupported')

    def test_depth_and_node_boundaries(self):
        nested = None
        for _ in range(6):
            nested = [nested]
        self.assertEqual(model.interpret({**sample([]), 'extra': nested})['status'], 'unsupported')
        self.assertEqual(model.interpret({**sample([]), 'extra': [nested]}), admission())
        self.assertEqual(model.interpret({**sample([]), 'extra': [None] * 503})['status'], 'unsupported')
        self.assertEqual(model.interpret({**sample([]), 'extra': [None] * 504}), admission())

    def test_cycles_aliases_and_nonstring_keys(self):
        loop = []
        loop.append(loop)
        self.assertEqual(model.interpret({**sample([]), 'extra': loop}), admission())
        child = ['x']
        self.assertEqual(model.interpret({**sample([]), 'extra': [child, child]})['status'], 'unsupported')
        self.assertEqual(model.interpret({1: 'x'}), admission())

    def test_hostile_metaclass_and_instance_hooks_never_called(self):
        for behavior in ('false', 'true', 'raise'):
            calls = []
            class Meta(type):
                def __eq__(cls, other):
                    calls.append('type-equality')
                    if behavior == 'raise':
                        raise AssertionError('type hook')
                    return behavior == 'true'
                def __hash__(cls):
                    calls.append('type-hash')
                    raise AssertionError('type hook')
            class Hostile(dict, metaclass=Meta):
                def __len__(self):
                    calls.append('length')
                    raise AssertionError('instance hook')
                def items(self):
                    calls.append('items')
                    raise AssertionError('instance hook')
                def __iter__(self):
                    calls.append('iteration')
                    raise AssertionError('instance hook')
                def __eq__(self, other):
                    calls.append('equality')
                    raise AssertionError('instance hook')
            obj = Hostile()
            for value in (obj, {**sample([]), 'extra': obj}, {**sample([]), 'schema_version': obj}):
                self.assertEqual(model.interpret(value), admission())
            self.assertEqual(calls, [])

    def test_other_subclasses_and_key_hooks(self):
        calls = []
        class Key(str):
            def __hash__(self):
                calls.append('hash')
                return str.__hash__(self)
            def __eq__(self, other):
                calls.append('equality')
                raise AssertionError('key hook')
        data = {Key('synthetic'): None}
        calls.clear()
        self.assertEqual(model.interpret(data), admission())
        self.assertEqual(calls, [])
        for kind, seed in ((str, 'x'), (int, 1), (list, []), (bytes, b'{}')):
            subclass = type('NativeSubclass', (kind,), {})
            value = subclass(seed)
            self.assertEqual(model.interpret(value), admission())
            if kind is bytes:
                with self.assertRaises(model.Invalid):
                    model.decode(value)

    def test_brackets_inside_strings_do_not_raise_depth(self):
        raw = json.dumps({**sample([]), 'extra': '[{' * 80}).encode()
        self.assertEqual(model.interpret(model.decode(raw))['status'], 'unsupported')

    def test_maximum_report_and_output_cap_seam(self):
        report = model.interpret(sample([BASE] * 16))
        payload = model.serialize(report)
        self.assertTrue(payload.isascii())
        self.assertTrue(payload.endswith(b'\n'))
        self.assertLess(len(payload), 65536)
        with patch.object(model, 'MAX_OUTPUT', len(payload)):
            self.assertEqual(model.serialize(report), payload)
        with patch.object(model, 'MAX_OUTPUT', len(payload) - 1):
            with self.assertRaises(ValueError):
                model.serialize(report)
            self.assertEqual(cli.main([], io.BytesIO(json.dumps(sample([BASE] * 16)).encode()),
                                      io.BytesIO(), io.StringIO()), 3)

    def test_import_and_forbidden_capability_seams(self):
        for path, expected in ((ROOT / 'model.py', {'json', 're', 'fractions'}),
                               (ROOT / 'cli.py', {'sys', 'model'})):
            tree = ast.parse(path.read_text())
            imports = {name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names}
            imports.update(node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
            self.assertEqual(imports, expected)
        def denied(*_args, **_kwargs):
            raise AssertionError('forbidden external capability')
        with patch('builtins.open', denied), patch.object(socket, 'socket', denied), \
                patch.object(subprocess, 'Popen', denied), patch.object(os, 'system', denied), \
                patch.object(os, 'getenv', denied):
            for case in CASES:
                output = io.BytesIO()
                code = cli.main([], io.BytesIO(json.dumps(case['input']).encode()), output, io.StringIO())
                self.assertEqual(code, 0 if case['expected']['status'] == 'interpreted' else 2)
                self.assertEqual(json.loads(output.getvalue()), case['expected'])


class Delivery(unittest.TestCase):
    def invoke(self, output, args=None, errors=None):
        return cli.main([] if args is None else args, io.BytesIO(json.dumps(sample()).encode()),
                        output, io.StringIO() if errors is None else errors)

    def test_help_and_misuse(self):
        output = io.BytesIO()
        self.assertEqual(self.invoke(output, ['--help']), 0)
        self.assertEqual(output.getvalue(), cli.HELP)
        output = io.BytesIO()
        errors = io.StringIO()
        self.assertEqual(self.invoke(output, ['file'], errors), 2)
        self.assertEqual(output.getvalue(), b'')
        self.assertEqual(errors.getvalue(), 'Usage: python cli.py < synthetic.json\n')

    def test_short_none_bool_output_writes(self):
        for returned in (1, None, True):
            class Short(io.BytesIO):
                def write(self, payload):
                    super().write(payload[:1])
                    return returned
            for args in ([], ['--help']):
                self.assertEqual(self.invoke(Short(), args), 3)

    def test_output_flush_and_write_errors(self):
        class Flush(io.BytesIO):
            def flush(self):
                raise OSError('synthetic')
        class Broken(io.BytesIO):
            def write(self, payload):
                raise BrokenPipeError('synthetic')
        for output in (Flush(), Broken()):
            for args in ([], ['--help']):
                self.assertEqual(self.invoke(output, args), 3)

    def test_read_and_closed_stream_errors(self):
        class Broken(io.BytesIO):
            def read(self, size):
                raise OSError('synthetic')
        self.assertEqual(cli.main([], Broken(), io.BytesIO(), io.StringIO()), 3)
        closed = io.BytesIO()
        closed.close()
        self.assertEqual(self.invoke(closed), 3)

    def test_diagnostic_short_none_bool_writes(self):
        for returned in (1, None, True):
            class Short(io.StringIO):
                def write(self, text):
                    super().write(text[:1])
                    return returned
            errors = Short()
            self.assertEqual(self.invoke(io.BytesIO(), ['bad'], errors), 3)
            self.assertEqual(errors.getvalue(), 'U')

    def test_diagnostic_flush_write_and_both_failure(self):
        class Flush(io.StringIO):
            def flush(self):
                raise OSError('synthetic')
        class Broken(io.StringIO):
            def write(self, text):
                raise BrokenPipeError('synthetic')
        out = io.BytesIO()
        out.close()
        for errors in (Flush(), Broken()):
            self.assertEqual(self.invoke(io.BytesIO(), ['bad'], errors), 3)
            self.assertEqual(self.invoke(out, [], errors), 3)
            self.assertFalse(cli.diagnostic(errors, 'fixed\n'))

    def test_actual_all_frozen_cli_reports_normal_and_optimized(self):
        for flags in ([], ['-O']):
            for case in CASES:
                with self.subTest(flags=flags, case=case['name']):
                    result = subprocess.run([sys.executable, *flags, str(ROOT / 'cli.py')],
                                            input=json.dumps(case['input']).encode(),
                                            capture_output=True, timeout=10, check=False)
                    self.assertEqual(result.returncode, 0 if case['expected']['status'] == 'interpreted' else 2)
                    self.assertEqual(result.stderr, b'')
                    self.assertTrue(result.stdout.isascii())
                    self.assertEqual(json.loads(result.stdout), case['expected'])

    def test_actual_help_misuse_normal_and_optimized(self):
        for flags in ([], ['-O']):
            for args, expected in ((['--help'], 0), (['bad'], 2)):
                result = subprocess.run([sys.executable, *flags, str(ROOT / 'cli.py'), *args],
                                        capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(result.stdout, cli.HELP if expected == 0 else b'')
                if expected == 0:
                    self.assertEqual(result.stderr, b'')
                else:
                    self.assertIn(result.stderr, (b'Usage: python cli.py < synthetic.json\n',
                                                  b'Usage: python cli.py < synthetic.json\r\n'))

    def test_actual_closed_sinks_barrier_normal_and_optimized(self):
        # Close parent read ends BEFORE releasing stdin barrier; avoids races.
        wrapper = ('import runpy,sys; sys.stdin.buffer.read(1); '
                   'path=sys.argv[1]; sys.path.insert(0,sys.argv[2]); '
                   'sys.argv=[path]+sys.argv[3:]; runpy.run_path(path,run_name="__main__")')
        scenarios = [(['bad'], False, True, 3), (['bad'], True, True, 3),
                     (['--help'], True, True, 3), ([], True, True, 3),
                     ([], False, True, 0), (['--help'], True, False, 3),
                     ([], True, False, 3)]
        for flags in ([], ['-O']):
            for args, close_out, close_err, expected in scenarios:
                with self.subTest(flags=flags, args=args, close_out=close_out, close_err=close_err):
                    child = subprocess.Popen([sys.executable, *flags, '-c', wrapper,
                                              str(ROOT / 'cli.py'), str(ROOT), *args],
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
                    if close_out:
                        child.stdout.close()
                        child.stdout = None
                    if close_err:
                        child.stderr.close()
                        child.stderr = None
                    try:
                        out, err = child.communicate(input=b'!' + (json.dumps(sample()).encode() if not args else b''), timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.communicate(timeout=10)
                        raise
                    self.assertEqual(child.returncode, expected)
                    if expected == 0:
                        self.assertEqual(json.loads(out), CASES[1]['expected'])
                    elif not close_out:
                        self.assertEqual(out, b'')
                    if not close_err:
                        self.assertTrue(err)


if __name__ == '__main__':
    unittest.main()
