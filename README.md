# CVSS Vector Model Lab

A small offline Python model that turns **supplied synthetic CVSS 3.1 Base
metrics** into a conditional numeric score. It preserves every original vector
and metric order, pairs the score with a canonical vector, and states what was
not assessed. CVSS 3.1 is deliberately an archived teaching profile.

A numeric score is easy to mistake for verified severity or risk. This lab
makes supplied declarations and unsupported scope visible. It does not verify
metric accuracy, classify real findings or assign severity labels. Optional
metrics—including explicit `X`—are unsupported, never silently stripped. An
invalid or unsupported batch produces zero score rows.

## Run

No dependencies or installation for the application. Python 3.12+ is intended;
verification used Windows CPython 3.13.7. From this directory in PowerShell:

```powershell
@'
{"schema_version":1,"profile":"cvss31-base-v1","vectors":["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]}
'@ | python .\cli.py
python .\cli.py --help
python -m unittest discover -s tests -v
python -O -m unittest discover -s tests -v
python .\tests\domain_check.py
```

The example yields `computed_base_score: "9.8"`, paired with its supplied vector,
`score_basis: "supplied_base_metrics_only"` and explicit unassessed areas.
[Examples](examples/) include complete inputs/reports, optional-X and late-invalid
refusals. A filename argument is misuse; input comes from stdin.

API: `model.interpret(native_tree)` returns a report; `model.decode(bytes)`
performs strict UTF-8 JSON admission and can raise `model.Invalid`;
`model.serialize(model_report)` returns bounded escaped ASCII JSON plus newline.
Public input trees require exact builtin JSON types. See [CONTRACT](CONTRACT.md).

## Architecture and security model

Stdin → bounded decoder/native admission → complete known validation → profile
gate → fixed-weight rational arithmetic → complete serialization → checked
write/flush. The model imports only json/re/fractions; the adapter adds sys.
Application code has no file/path resolution, network, subprocess, environment
lookup, target execution or external model. Whole known validation precedes
unsupported status, even behind an earlier future-version vector.

Input limits: 16 KiB, depth 8, 512 values plus keys, 256 characters per string,
16 vectors and 10-character integer tokens with values 0..2147483647. Output
<=64 KiB including newline. Duplicate keys/metrics, missing Base metrics,
floats, surrogates, custom objects and cycles are rejected. Exact-type identity
guards precede caller hooks. Limits bound workload, not OS isolation or hard
runtime/memory. Physical output is not transactional; failed stderr cannot
promise visible diagnostics. Exits: 0 interpreted/help; 2 invalid, unsupported
or fully delivered misuse; 3 I/O, serialization or diagnostic delivery failure.

## Verified results and limits

57 complete independent reports frozen before scorer code; 30 tests pass in
normal and optimized Python. Each suite includes 114 real CLI report checks,
four help/misuse checks and 14 barrier-controlled closed-sink scenarios across
normal/-O children. All 2592 Base combinations agree across exact arithmetic,
an independent 100-digit Decimal calculation and Appendix A stabilization;
96 have nonpositive impact. This finite comparison is not a published oracle
corpus or a full conformance certificate.

Four intended semantic mutations are caught by assertion failures (4/2/8/2),
with zero errors; original hashes unchanged and restored suite passes.
Bandit: zero application findings; six reviewed, unsuppressed LOW harness
findings, zero scan errors. [VERIFICATION](VERIFICATION.md) and [REVIEW](REVIEW.md)
describe evidence/limits. Reusable `verify.py --output .private/NEW` needs
already-installed Bandit and a fresh directory; it never installs tools.

No 4.0, Temporal/Environmental calculation, real vulnerability assessment,
production deployment, Linux/other-Python execution or hosted CI was verified.
No repository was created, committed or published. Research candidates were
inspected but not installed/executed. Other labs remain separate.

## Sources, license and learning

Original implementation/synthetic fixtures: [MIT license](LICENSE).
CVSS is owned by FIRST.Org, Inc. and used by permission. Equations, weights and
published numeric controls are attributed to [FIRST 3.1 specification](https://www.first.org/cvss/v3.1/specification-document),
[design guidance](https://www.first.org/cvss/v3.1/use-design) and
[examples](https://www.first.org/cvss/v3.1/examples), consulted October 5, 2026.
Only metric tokens/numeric controls retained, not vulnerability prose. No
upstream implementation or test corpus copied. Source/license limits:
[RESEARCH](RESEARCH.md), [provenance](research/oracle-provenance.json).

AI assistance: Codex helped research, implement, test, review and document this
lab. A local 2B draft was rejected; a selected free worker returned no text.
Raw evidence preserved. Neither supplied accepted code/oracle values. ECC was
a Codex self-review, not independent audit. No additional spending initiated.
[DECISIONS](DECISIONS.md), [LEARNING](LEARNING.md) and [STATE](STATE.md) preserve
choices, learning and authorization.

Optional exercise: predict why adding `/E:X` returns no score rows, then compare
that complete report with the Base-only example.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
