"""Repeatable local verification into one NEW project-local evidence directory.

Usage: python verify.py --output .private/check-NEW
Runs only this original project using the current installed Python and Bandit.
No installs, network, real targets or altered production sources. Mutation
copies are preserved; original hashes must match before/after. Requires the
frozen fixtures and installed Bandit. See VERIFICATION.md for limits.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
MUTATIONS = (
    ('overwrite-duplicate', "if name in metrics:\n            raise Invalid('duplicate_metric', pointer)",
     "if False:\n            raise Invalid('duplicate_metric', pointer)"),
    ('erase-scope-pr', "pr = WEIGHTS['PR_C' if changed else 'PR_U'][metrics['PR']]",
     "pr = WEIGHTS['PR_U'][metrics['PR']]"),
    ('nearest-rounding', 'tenths = (10 * value.numerator + value.denominator - 1) // value.denominator',
     'tenths = (20 * value.numerator + value.denominator) // (2 * value.denominator)'),
    ('bypass-zero-impact', 'if impact <= 0:', 'if False:'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(output, label, arguments, cwd=ROOT):
    result = subprocess.run([sys.executable, *arguments], cwd=cwd,
                            capture_output=True, timeout=90, check=False)
    (output / (label + '.stdout')).write_bytes(result.stdout)
    (output / (label + '.stderr')).write_bytes(result.stderr)
    return {'command': [sys.executable, *arguments], 'cwd': str(cwd),
            'exit': result.returncode,
            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    if not output.is_relative_to(ROOT / '.private') or output == ROOT / '.private':
        parser.error('output must be a NEW directory beneath this project .private')
    output.mkdir(parents=True, exist_ok=False)
    originals = ['model.py', 'cli.py', 'verify.py', 'CONTRACT.md', 'tests/test_model.py',
                 'tests/domain_check.py', 'tests/mutation_probe.py', 'tests/oracles.json',
                 'research/oracle-provenance.json', 'research/oracle-freeze.json']
    before = {name: digest(ROOT / name) for name in originals}
    receipt = {'python': sys.version, 'before': before, 'runs': {}, 'mutations': {}}
    entry, process = execute(output, 'rounding-domain', ['tests/domain_check.py'])
    receipt['runs']['rounding-domain'] = entry
    receipt['rounding_gate'] = json.loads(process.stdout)
    if process.returncode != 0 or receipt['rounding_gate']['mismatches']:
        receipt['status'] = 'rounding_design_gate'
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        return 1
    for label, arguments in (
            ('normal', ['-m', 'unittest', 'discover', '-s', 'tests', '-v']),
            ('optimized', ['-O', '-m', 'unittest', 'discover', '-s', 'tests', '-v']),
            ('bandit-application', ['-m', 'bandit', '-f', 'json', 'model.py', 'cli.py']),
            ('bandit-harness', ['-m', 'bandit', '-f', 'json', '-r', 'tests', 'verify.py', 'research/freeze_oracles.py'])):
        entry, process = execute(output, label, arguments)
        receipt['runs'][label] = entry
        if label.startswith('bandit'):
            parsed = json.loads(process.stdout)
            receipt['runs'][label]['issues'] = len(parsed['results'])
            receipt['runs'][label]['errors'] = len(parsed['errors'])
            receipt['runs'][label]['severity'] = {
                level: sum(issue['issue_severity'] == level for issue in parsed['results'])
                for level in ('LOW', 'MEDIUM', 'HIGH')}
    for name, old, new in MUTATIONS:
        mutant = output / name
        mutant.mkdir()
        for relative in originals:
            target = mutant / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        path = mutant / 'model.py'
        source = path.read_text(encoding='utf-8')
        if source.count(old) != 1:
            raise ValueError('mutation seam must occur exactly once')
        path.write_text(source.replace(old, new), encoding='utf-8')
        entry, process = execute(output, name, ['tests/mutation_probe.py'], mutant)
        outcome = json.loads(process.stdout)
        receipt['mutations'][name] = {**entry, **outcome, 'mutant_sha256': digest(path),
                                      'killed': process.returncode == 1 and outcome['failures'] > 0
                                      and outcome['errors'] == 0 and outcome['assertion_only']}
    after = {name: digest(ROOT / name) for name in originals}
    receipt['after'] = after
    receipt['original_sources_unchanged'] = before == after
    entry, process = execute(output, 'restored', ['-m', 'unittest', 'discover', '-s', 'tests', '-v'])
    receipt['runs']['restored'] = entry
    receipt['status'] = 'passed' if (
        before == after and all(receipt['runs'][name]['exit'] == 0 for name in
                               ('normal', 'optimized', 'restored', 'bandit-application'))
        and receipt['runs']['bandit-application']['errors'] == 0
        and receipt['runs']['bandit-harness']['errors'] == 0
        and receipt['runs']['bandit-harness']['exit'] in (0, 1)
        and all(item['killed'] for item in receipt['mutations'].values())) else 'failed'
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'output': str(output),
                      'rounding': receipt['rounding_gate'],
                      'mutations': {name: {'failures': item['failures'], 'errors': item['errors'],
                                          'killed': item['killed']} for name, item in receipt['mutations'].items()},
                      'bandit': {name: receipt['runs'][name]['severity'] for name in
                                 ('bandit-application', 'bandit-harness')}}))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
