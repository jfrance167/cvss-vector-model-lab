# CVSS Vector Model Lab — proposed plan

October5,2026. **Stages 1–3 APPROVED at 04:49; resumed at 05:03.** Tier3
portfolio workflow applied proportionally to an inert small model. Authority:
coordinator's04:18 SUCCESSORS.md decision under Jake's independently verified
plan/start/successor delegation. Sole writer remains this chat; separate directory.
SARIF is accepted and unchanged. Keyless58 advisories/independent-restore/guest/
manual hostile-use gates remain separate. Research limitations: RESEARCH.md.

## Problem, success and chosen scope

Teach the difference between supplied CVSS metric declarations and a conditional
version-specific numeric result. Recommend **CVSS3.1 Base-only**; archived3.1
is deliberately chosen for a small inspectable formula, not presented as latest.
One original standard-library Python3.12+ offline model/CLI, synthetic vectors
only, preserving original metric order and a separate preferred-order vector.
No qualitative severity bands, real vulnerability classification, metric truth,
environment collection, exploit likelihood, business risk or remediation ranking.
No4.0 computation, Temporal/Environmental scores, free-text extraction, CVE/URL
lookups, vulnerability databases, scanning, source/binary/artifact/file access,
subprocess/network in the application, VM/scanner changes, installs, repository
creation or publication. The product never requires models/workers/accounts.

Success: frozen independent full reports and published metric/score controls
match, exact one-decimal formatting and scope branches are demonstrated, malformed
or unsupported late data yields no projected scores, resource bounds apply to
API and CLI, delivery failures stay controlled in real normal/-O children.
Report always pairs a conditional computed score with its supplied/canonical
vector, identifies the version/profile and leaves assessments unverified.

## Exact proposed input and validation contract

Stdin UTF-8 JSON only; no input filename argument. Envelope exact keys:
schema_version exact int1, profile string `cvss31-base-v1`, vectors array of
0..16 exact strings. Preserve each array occurrence/index; do not deduplicate.
Empty array is interpreted empty supplied metadata, never a vulnerability verdict.
Unknown root fields are unsupported after common/known validation; wrong shapes,
duplicates, floats/nonfinite values/BOM/invalid UTF-8/surrogates/cycles/custom
containers are invalid. Unknown bounded schema/profile values unsupported only
after known shape/vector validation. Scalar bool must not stand in for schema1.

Limits:16KiB raw/API-equivalent UTF-8 input; depth8,512 values plus keys,
256 Unicode characters/string, ten numeric-token characters, integers0..2147483647,
16 vectors, each256 visible-ASCII non-space characters; serialized escaped ASCII
JSON output64KiB including newline. Limits are conjunctive workload constraints,
not OS isolation, hard time/RSS or artifact safety guarantees. Pre-parse nesting
and token bounds; built-in/container limits precede semantic interpretation.

Versioned vector prefix: `CVSS:<1–2 decimal digits>.<1–2 decimal digits>/`
followed by nonempty bounded text. Exact3.1 requires slash-separated name:value
tokens; no whitespace, casing repair, extra/trailing delimiter or percent/Unicode
normalization. Other bounded version prefixes unsupported; only common bounded
text/prefix validation applies, no future-version semantic validity claim.

For3.1 validate the complete known22-metric namespace and values, including
valid optional fields destined for unsupported status, before scoring/feature
gating. Mandatory Base fields exactly once; duplicate same/different values,
unknown name/value and missing Base fields invalid. Metrics may occur in ANY
order. Base values: AV=N/A/L/P; AC=L/H; PR=N/L/H; UI=N/R; S=U/C;
C/I/A=H/L/N. Base X invalid. Known optional values from FIRST Table15:
E=X/H/F/P/U; RL=X/U/W/T/O; RC=X/C/R/U; CR/IR/AR=X/H/M/L;
MAV=X/N/A/L/P; MAC=X/L/H; MPR=X/N/L/H; MUI=X/N/R; MS=X/U/C;
MC/MI/MA=X/N/L/H. ANY present optional metric, even X, is unsupported for this
Base-only profile; never silently strip it, default it or compute an adjusted
score. Optional absence is permitted but does not assess actual circumstances.

Whole batch common and known3.1 validation runs before unsupported gating.
Invalid dominates unsupported; either releases zero results, including if a late
entry fails after an early valid vector or an earlier unsupported version. First
invalid in input order is reported; otherwise first unsupported in input order.
No score projection until all admitted declarations pass the selected profile.
Freeze exact reason codes/pointers in stage1, including vector_syntax,
missing_metric, duplicate_metric, unknown_metric, metric_value, optional_metric,
version/profile/schema_version, shape/admission/unknown_field. Pointers identify
input indices, not raw target text. No real-target identifiers or descriptions.

## Arithmetic and report proposal

Use fractions.Fraction from exact finite decimal constants, never binary floats,
ambient Decimal context or caller-provided weights/formulas. Base coefficients
and tables are fixed from FIRST section7 and inspected reference math:
AV .85/.62/.55/.20; AC .77/.44; UI .85/.62; CIA .56/.22/0;
PR N=.85; unchanged L=.62/H=.27; changed L=.68/H=.50.

ISS =1−(1−C)(1−I)(1−A). Unchanged Impact=6.42×ISS; changed
Impact=7.52×(ISS−.029)−3.25×(ISS−.02)^15. Exploitability=8.22×AV×AC×PR×UI.
If Impact≤0, Base=0. Otherwise cap the sum at10, multiplying by1.08 before
the cap for changed Scope, then **exact rational ceiling to tenths**. Format as
one decimal string0.0..10.0, no JSON float. Exponent/table fixed, never data-
driven. Explain score is conditional on supplied metrics, not verified severity.

The formal mathematical Roundup and FIRST's floating-point repair helper differ
for arbitrary inputs extremely close above a decimal boundary. This model uses
exact arithmetic and does not apply the floating-point stabilization to pretend
its exact value was different. Stage1 must independently document this choice;
stage2 finite2592 Base-domain comparison checks exact ceiling versus AppendixA
nearest-100000/integer-up behavior. If any actual Base score differs, retain the
case and stop for a scoped design review rather than altering expected answers
or claiming reference parity. No full-scoring engine/conformance certificate.

Report exact fields to freeze: schema_version1, profile, status, reasons,
results. Each successful row: index, input_vector, input_metric_order,
canonical_base_vector (AV/AC/PR/UI/S/C/I/A order), metric_values, computed_base_score,
score_basis=`supplied_base_metrics_only`, unassessed fixed list covering metric
accuracy/Temporal/Environmental/real-world severity/risk. Include branch/rounding
labels only if needed to explain learning, never raw expansive arithmetic state.
Unknown/error output: fixed reason code/pointer, results[]. No inferred score
for missing/unknown metrics. No report sorting or equivalence across versions.

CLI exits: interpreted0, invalid/unsupported2, misuse2 ONLY if complete fixed
stderr delivery, input/serialization/output/diagnostic delivery failure3. Help
success0 only on exact write/flush. Check short/None/bool writes and flush errors;
detach failed stdio on operation-failure process exit, with no replacement file.
Failed stderr cannot promise visible diagnostics. Stdout/stderr are not atomic.

## Architecture, alternatives and threat model

Thin stdio adapter → strict bounded decoder → whole-batch profile/vector
validation → pure fixed-weight rational calculation → complete bounded serializer.
Reuse reviewed *concepts* from SARIF bounds/delivery tests; preserve that source
and implement a small standalone module rather than adding a cross-project
runtime dependency. Standard library suffices; no package download needed.
Alternatives: Red Hat library is suitable for broader version/group calculations
but loses optional-X provenance and has LGPL/test/build scope beyond this lab;
FIRST4 browser/reference adds lookup/interpolation/CDN surface. No suitable
candidate directly supplies this frozen narrow API, output/provenance and bounds.

| Threat / misleading outcome | Control / residual limit |
| --- | --- |
| Untrusted text resource growth | byte/depth/node/count/token/serialization guards; workload bounds only |
| Metric overwrite/default guessing | reject duplicates/missing Base; validate optional fields before refusal |
| Mixed versions/formulas or rounding drift | exact3.1 profile, fixed rational constants/branches, independent numeric controls |
| Score mistaken for actual severity | supplied-only basis, paired vector, no severity label or real vulnerability data |
| Early score leaked before late failure | validate batch fully and serialize before writing; physical delivery remains non-atomic |
| Terminal/path/network injection | escaped ASCII JSON, fixed diagnostics, no artifact/I/O resolution or execution |
| Weak tests or shutdown behavior | frozen full reports, independent finite properties, assertion-killed mutations, actual child barriers |

## Stages and definitions of done (proposed)

1. **Contract/provenance and independent oracles before scorer code.** Freeze
   exact schema/status/reasons/rounding policy and ≥24 full expected reports.
   Capture only published vector tokens/numeric controls with source/section/
   date/digest and permission attribution, not vulnerability prose. Controls:
   FIRST design6.1 for N/L/N/R/C/L/L/N and8.6 for N/L/N/N/C/H/N/N;
   FIRST example9.8 for N/L/N/N/U/H/H/H and7.5 for N/L/N/N/U/H/N/N;
   synthetic all-CIA:N→0 both scopes; cap10 and scope-dependent PR paired cases
   justified independently. Add arbitrary reorder, duplicates, each missing Base,
   invalid X/value/name, optional-X/non-X, future prefix, empty batch, malformed
   late entry, repaired pairs. Freeze helper4.00→4.0/4.02→4.1 and close-boundary
   policy examples separately from published Base scores. No worker/candidate
   scorer may generate expectations. Done: reviewed provenance, fixture hashes,
   exact independent expectations and explicit arithmetic choice. Requires approval.
2. **Bounded model and CLI.** Decoder/grammar first, then exact arithmetic and
   reporting/delivery. Done: all full oracles pass, normal/-O and actual-CLI
   checks, API custom/cycle rejection, max-byte/count/report checks, denied file/
   network/subprocess/environment seams and exact import review. Independently
   enumerate2592 Base metric combinations for bounds/no-impact/determinism and
   helper-rounding compatibility, not claiming2592 independent score oracles.
   Paired scope/PR vectors and reordering preserve scores but retain declarations.
   Test short writes/flush/read failures, both closed sinks and misuse in normal/
   optimized barrier-controlled processes. Stop on true arithmetic discrepancy.
3. **Focused review and local portfolio handoff.** Four intended mutations:
   overwrite duplicate metric, erase scope-dependent PR weights, nearest instead
   of upward rounding, bypass zero-impact branch. Each must yield the intended
   assertion difference, not crashes/removed test guards; source hashes restored.
   ECC actual self-review/fixes/affected reruns; installed Bandit with transparent
   application/harness results, no broad suppressions; final receipts/hashes.
   README setup/demo/security/limitations/MIT/FIRST attribution/AI disclosure,
   STATE/DECISIONS/LEARNING and vault milestone. No CI/publication/repo claims.
   Done: actual evidence matches completion record, limitations preserved.

Task checklist: tasks/todo.md; PLAN.md is authoritative because coordinator
requested that path, overriding the planning skill's default tasks/plan.md.
Approval is recorded in the coordinator's SUCCESSORS.md section “Two plan
approvals and SemVer correction acceptance”, under Jake's verified direct
delegation. Stage 1 freezes at least 24 complete independent reports BEFORE
scorer code. Native admission must use exact-type identity before any hooks.
Actual normal/-O failed-sink checks, optional-X preservation, four assertion
mutations and the 2592-combination rounding discrepancy stop gate are mandatory.
No new approval pause within subsequently authorized stages unless scope/risk
changes materially or an app review blocks an action. No successor yet.
