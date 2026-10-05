"""Bounded supplied CVSS 3.1 Base declarations; no real-world assessment.

Public interpret() accepts exact native JSON trees. decode() additionally
enforces byte/token limits. Inputs are never modified. See CONTRACT.md.
"""
import json
import re
from fractions import Fraction

MAX_INPUT = 16384
MAX_OUTPUT = 65536
PROFILE = 'cvss31-base-v1'
BASE = ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')
VALUES = {
    'AV': 'NALP', 'AC': 'LH', 'PR': 'NLH', 'UI': 'NR', 'S': 'UC',
    'C': 'HLN', 'I': 'HLN', 'A': 'HLN', 'E': 'XHFPU', 'RL': 'XUWTO',
    'RC': 'XCRU', 'CR': 'XHML', 'IR': 'XHML', 'AR': 'XHML',
    'MAV': 'XNALP', 'MAC': 'XLH', 'MPR': 'XNLH', 'MUI': 'XNR',
    'MS': 'XUC', 'MC': 'XNLH', 'MI': 'XNLH', 'MA': 'XNLH'}
PREFIX = re.compile(r'CVSS:([0-9]{1,2}\.[0-9]{1,2})/(.+)\Z')
WEIGHTS = {
    'AV': dict(zip('NALP', map(Fraction, ('.85', '.62', '.55', '.20')))),
    'AC': {'L': Fraction('.77'), 'H': Fraction('.44')},
    'UI': {'N': Fraction('.85'), 'R': Fraction('.62')},
    'CIA': {'H': Fraction('.56'), 'L': Fraction('.22'), 'N': Fraction(0)},
    'PR_U': {'N': Fraction('.85'), 'L': Fraction('.62'), 'H': Fraction('.27')},
    'PR_C': {'N': Fraction('.85'), 'L': Fraction('.68'), 'H': Fraction('.50')}}


class Invalid(ValueError):
    """Fixed reason and input pointer; no input excerpts or dynamic diagnostic."""

    def __init__(self, code, pointer=''):
        super().__init__(code)
        self.code = code
        self.pointer = pointer


def failure(code, pointer='', status='invalid'):
    return {'schema_version': 1, 'profile': PROFILE, 'status': status,
            'reasons': [{'code': code, 'pointer': pointer}], 'results': []}


def _admit(value):
    """Identity checks precede all operations on caller-supplied objects."""
    active = set()
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if depth > 8 or nodes > 512:
            raise Invalid('admission')
        kind = type(item)
        if kind is str:
            if len(item) > 256 or any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise Invalid('admission')
        elif kind is int:
            if not 0 <= item <= 2147483647:
                raise Invalid('admission')
        elif item is None or kind is bool:
            return
        elif kind is list or kind is dict:
            identity = id(item)
            if identity in active:
                raise Invalid('admission')
            active.add(identity)
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise Invalid('admission')
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
            active.remove(identity)
        else:
            raise Invalid('admission')

    visit(value, 1)
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(encoded) > MAX_INPUT:
        raise Invalid('admission')


def decode(raw):
    """Strict UTF-8 JSON admission; bounded nesting before JSON recursion."""
    if type(raw) is not bytes or len(raw) > MAX_INPUT or raw.startswith(b'\xef\xbb\xbf'):
        raise Invalid('admission')
    try:
        text = raw.decode('utf-8')
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '[{':
                depth += 1
                if depth > 8:
                    raise Invalid('admission')
            elif char in ']}':
                depth -= 1

        def integer(token):
            if len(token) > 10:
                raise Invalid('admission')
            return int(token)

        def forbidden(_token):
            raise Invalid('admission')

        def pairs(entries):
            result = {}
            for key, child in entries:
                if key in result:
                    raise Invalid('admission')
                result[key] = child
            return result

        value = json.loads(text, parse_int=integer, parse_float=forbidden,
                           parse_constant=forbidden, object_pairs_hook=pairs)
        _admit(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Invalid('admission') from error


def _vector(text, pointer):
    if type(text) is not str:
        raise Invalid('shape', pointer)
    if not text or any(ord(c) < 33 or ord(c) > 126 for c in text):
        raise Invalid('vector_syntax', pointer)
    match = PREFIX.fullmatch(text)
    if match is None:
        raise Invalid('vector_syntax', pointer)
    if match[1] != '3.1':
        return None, ('version', pointer)
    metrics = {}
    for token in match[2].split('/'):
        parts = token.split(':')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise Invalid('vector_syntax', pointer)
        name, value = parts
        if name not in VALUES:
            raise Invalid('unknown_metric', pointer)
        if name in metrics:
            raise Invalid('duplicate_metric', pointer)
        if len(value) != 1 or value not in VALUES[name]:
            raise Invalid('metric_value', pointer)
        metrics[name] = value
    for name in BASE:
        if name not in metrics:
            raise Invalid('missing_metric', pointer)
    if any(name not in BASE for name in metrics):
        return metrics, ('optional_metric', pointer)
    return metrics, None


def _base_value(metrics):
    """Internal fixed-weight exact rational value BEFORE upward rounding."""
    iss = 1 - ((1 - WEIGHTS['CIA'][metrics['C']]) *
               (1 - WEIGHTS['CIA'][metrics['I']]) *
               (1 - WEIGHTS['CIA'][metrics['A']]))
    changed = metrics['S'] == 'C'
    impact = (Fraction('7.52') * (iss - Fraction('.029')) -
              Fraction('3.25') * (iss - Fraction('.02')) ** 15
              if changed else Fraction('6.42') * iss)
    if impact <= 0:
        return Fraction(0)
    pr = WEIGHTS['PR_C' if changed else 'PR_U'][metrics['PR']]
    exploitability = (Fraction('8.22') * WEIGHTS['AV'][metrics['AV']] *
                      WEIGHTS['AC'][metrics['AC']] * pr * WEIGHTS['UI'][metrics['UI']])
    total = impact + exploitability
    if changed:
        total *= Fraction('1.08')
    return min(total, Fraction(10))


def _roundup(value):
    tenths = (10 * value.numerator + value.denominator - 1) // value.denominator
    return f'{tenths // 10}.{tenths % 10}'


def interpret(value):
    """Return a complete bounded-profile report; invalid dominates unsupported."""
    try:
        _admit(value)
        if type(value) is not dict:
            raise Invalid('shape')
        for key, kind in (('schema_version', int), ('profile', str), ('vectors', list)):
            if key not in value or type(value[key]) is not kind:
                raise Invalid('shape', '/' + key)
        if len(value['vectors']) > 16:
            raise Invalid('admission')
        unsupported = []
        for key in value:
            if key not in ('schema_version', 'profile', 'vectors'):
                unsupported.append(('unknown_field', '/' + key.replace('~', '~0').replace('/', '~1')))
        if value['schema_version'] != 1:
            unsupported.append(('schema_version', '/schema_version'))
        if value['profile'] != PROFILE:
            unsupported.append(('profile', '/profile'))
        parsed = []
        for index, vector in enumerate(value['vectors']):
            metrics, reason = _vector(vector, '/vectors/' + str(index))
            parsed.append(metrics)
            if reason is not None:
                unsupported.append(reason)
        if unsupported:
            code, pointer = unsupported[0]
            return failure(code, pointer, 'unsupported')
        results = []
        for index, metrics in enumerate(parsed):
            results.append({
                'index': index, 'input_vector': value['vectors'][index],
                'input_metric_order': list(metrics),
                'canonical_base_vector': 'CVSS:3.1/' + '/'.join(k + ':' + metrics[k] for k in BASE),
                'metric_values': {k: metrics[k] for k in BASE},
                'computed_base_score': _roundup(_base_value(metrics)),
                'score_basis': 'supplied_base_metrics_only',
                'unassessed': ['metric_accuracy', 'temporal', 'environmental',
                               'real_world_severity', 'risk']})
        return {'schema_version': 1, 'profile': PROFILE, 'status': 'interpreted',
                'reasons': [], 'results': results}
    except Invalid as error:
        return failure(error.code, error.pointer)


def serialize(report):
    """Serialize model-produced reports completely before any delivery."""
    payload = (json.dumps(report, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(payload) > MAX_OUTPUT:
        raise ValueError('output limit')
    return payload
