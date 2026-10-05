"""Stdin/stdout only. No filename, target, artifact or external access."""
import sys
from model import Invalid, MAX_INPUT, decode, failure, interpret, serialize

HELP = (b'Usage: python cli.py < synthetic.json\n'
        b'Offline supplied CVSS 3.1 Base metrics only; no severity or risk assessment.\n')


def deliver(stream, payload):
    written = stream.write(payload)
    if type(written) is not int or written != len(payload):
        raise OSError('short output')
    stream.flush()


def diagnostic(stream, text):
    try:
        deliver(stream, text)
        return True
    except (OSError, ValueError):
        return False


def main(argv=None, source=None, output=None, errors=None):
    """Injectable streams for checks; default is process stdio only."""
    argv = sys.argv[1:] if argv is None else argv
    source = sys.stdin.buffer if source is None else source
    output = sys.stdout.buffer if output is None else output
    errors = sys.stderr if errors is None else errors
    if argv == ['--help']:
        try:
            deliver(output, HELP)
            return 0
        except (OSError, ValueError):
            diagnostic(errors, 'Output delivery failed.\n')
            return 3
    if argv:
        return 2 if diagnostic(errors, 'Usage: python cli.py < synthetic.json\n') else 3
    try:
        raw = source.read(MAX_INPUT + 1)
        try:
            report = interpret(decode(raw))
        except Invalid as error:
            report = failure(error.code, error.pointer)
        deliver(output, serialize(report))
        return 0 if report['status'] == 'interpreted' else 2
    except (OSError, ValueError):
        diagnostic(errors, 'Input or output operation failed.\n')
        return 3


if __name__ == '__main__':
    exit_code = main()
    if exit_code == 3:
        # Avoid a second failed buffer flush changing the intended exit to 120.
        # No replacement file/device or external sink is opened.
        sys.stdout = None
        sys.stderr = None
    raise SystemExit(exit_code)
