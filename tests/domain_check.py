"""Independent Decimal formulas/enumeration, not an expected-score corpus.

Compares exact mathematical ceiling, Appendix A and production across the
finite 2592 Base combinations. A mismatch must stop acceptance. No candidate
implementation imported; literal constants from FIRST section 7.
"""
import hashlib
import itertools
import json
import sys
from decimal import Decimal as D, ROUND_CEILING, ROUND_HALF_UP, localcontext
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import model


def check():
    comparisons = []
    mismatches = []
    zero_count = 0
    with localcontext() as ctx:
        ctx.prec = 100
        for values in itertools.product('NALP', 'LH', 'NLH', 'NR', 'UC', 'HLN', 'HLN', 'HLN'):
            av, ac, pr, ui, scope, c, i, a = values
            cia = {'H': D('.56'), 'L': D('.22'), 'N': D(0)}
            iss = D(1) - (D(1) - cia[c]) * (D(1) - cia[i]) * (D(1) - cia[a])
            impact = (D('6.42') * iss if scope == 'U' else
                      D('7.52') * (iss - D('.029')) - D('3.25') * (iss - D('.02')) ** 15)
            pr_weight = ({'N': D('.85'), 'L': D('.62'), 'H': D('.27')} if scope == 'U'
                         else {'N': D('.85'), 'L': D('.68'), 'H': D('.50')})[pr]
            exploit = (D('8.22') * {'N': D('.85'), 'A': D('.62'), 'L': D('.55'), 'P': D('.20')}[av] *
                       {'L': D('.77'), 'H': D('.44')}[ac] * pr_weight *
                       {'N': D('.85'), 'R': D('.62')}[ui])
            if impact <= 0:
                raw = D(0)
                zero_count += 1
            else:
                raw = min(D(10), (impact + exploit) * (D('1.08') if scope == 'C' else D(1)))
            ceiling = int((raw * 10).to_integral_value(rounding=ROUND_CEILING))
            stabilized = int((raw * 100000).to_integral_value(rounding=ROUND_HALF_UP))
            appendix = (stabilized // 10000 if stabilized % 10000 == 0
                        else stabilized // 10000 + 1)
            vector = 'CVSS:3.1/' + '/'.join(k + ':' + v for k, v in zip(model.BASE, values, strict=True))
            report = model.interpret({'schema_version': 1, 'profile': 'cvss31-base-v1', 'vectors': [vector]})
            expected = f'{ceiling // 10}.{ceiling % 10}'
            actual = report['results'][0]['computed_base_score'] if report['status'] == 'interpreted' else None
            comparisons.append([vector, expected, appendix])
            metrics = dict(zip(model.BASE, values, strict=True))
            exact_agrees = model._base_value(metrics) == Fraction(raw)
            if ceiling != appendix or actual != expected or not exact_agrees:
                mismatches.append({'vector': vector, 'mathematical': expected,
                                   'appendix_tenths': appendix, 'actual': actual,
                                   'exact_unrounded_agreement': exact_agrees})
    return {'combinations': len(comparisons), 'zero_impact': zero_count,
            'mismatches': mismatches, 'comparison_sha256': hashlib.sha256(
                json.dumps(comparisons, separators=(',', ':')).encode('ascii')).hexdigest(),
            'claim': 'finite comparison, not independent published-score corpus'}


if __name__ == '__main__':
    receipt = check()
    print(json.dumps(receipt, indent=2))
    raise SystemExit(1 if receipt['mismatches'] else 0)
