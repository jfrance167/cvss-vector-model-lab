# Frozen cvss31-base-v1 contract

October 5, 2026, stage 1, before scorer implementation. PLAN bounds and FIRST
3.1 section 7 apply. This is a synthetic teaching subset, not full conformance.

Exact root fields: schema_version integer, profile string, vectors list of
strings (0..16). Missing fields/wrong shapes invalid. Root checks run in that
field order, then vector validation in input order. Admission precedes all
semantics. Extra fields, other bounded integer schema versions and other
profiles unsupported only AFTER complete known vector validation. Unsupported
priority: first extra field in insertion order, schema_version, profile, then
first vector with optional metrics or another version. First invalid vector
wins even behind unsupported declarations. No partial results.

Admission: exact builtins only, no subclass/custom hook execution; strings up
to 256 characters without surrogates, integers 0..2147483647, null/bool allowed
as JSON values but not as schema integers. Depth 8 (root value depth 1, keys and
values advance depth), 512 visited values PLUS keys. Reject active cycles;
acyclic repeated containers count each occurrence. Compact unescaped UTF-8 API
JSON <=16384 bytes. Raw UTF-8 <=16384, no BOM, duplicate keys, floats/NaN,
invalid UTF-8 or numeric tokens longer than 10 characters. Pre-parse container
nesting bounded at 8; complete native admission also bounds leaf depth.

Vectors are 1..256 visible ASCII characters (33..126), no repair. Prefix
CVSS:<1–2 ASCII digits>.<1–2 ASCII digits>/ then nonempty text. Only exact
3.1 parses metric tokens, each exactly one colon with nonempty name/value.
Other prefixes unsupported with no later grammar validity claim. For 3.1:
syntax, unknown metric, duplicate metric, invalid value checks in token order,
then missing Base metrics in AV/AC/PR/UI/S/C/I/A order. Full optional namespace
and values are exactly as PLAN. Any optional presence, including X, unsupported.
Inputs are not mutated, defaulted or stripped. Error outputs use pointers to
the original vector and zero results; original declarations remain in supplied
input and saved fixtures, rather than a misleading stripped projection.

Exact report keys: schema_version:1, profile:cvss31-base-v1, status
(interpreted/invalid/unsupported), reasons, results. Error reasons contain only
code and pointer. Codes: admission (pointer empty); shape (missing/wrong field
pointer); vector_syntax, unknown_metric, duplicate_metric, metric_value,
missing_metric, optional_metric, version (all /vectors/i); unknown_field (escaped
root key pointer), schema_version (/schema_version), profile (/profile).
Interpreted reasons empty. Error results empty.

Success rows: index, input_vector, input_metric_order, canonical_base_vector,
metric_values, computed_base_score (one decimal STRING),
score_basis:supplied_base_metrics_only, unassessed:[metric_accuracy,temporal,
environmental,real_world_severity,risk]. Metric values/canonical vector ordered
AV/AC/PR/UI/S/C/I/A. Every occurrence retained; empty input yields empty results.

Fixed exact Fraction arithmetic and mathematical ceiling to tenths as PLAN.
Helper controls: 4 ->4.0, 4.02 ->4.1, 4.000001 ->4.1; Appendix A gives 4.0 for
the last arbitrary boundary control. Compare both on all 2592 actual Base
inputs; any discrepancy stops scoring acceptance, never changes this oracle.

Serialization: compact escaped ASCII JSON plus newline, <=65536 bytes; an
output-cap failure raises ValueError and CLI exits 3. API serialize accepts
model-produced reports; caller-built reports are outside its public contract.
CLI has --help only, otherwise stdin bytes/stdout bytes. Exits 0 interpreted or
fully delivered help; 2 invalid/unsupported or fully delivered misuse diagnostic;
3 read/serialize/write/flush/diagnostic failure. Write count must be exact int
equal to payload length, not bool/None. On failure standalone entrypoint detaches
stdio before interpreter shutdown. Physical output is not transactional.

Four intended assertion mutations: duplicate overwritten; changed-Scope PR
weights replaced by unchanged; nearest rounding; zero-impact branch bypass.
Independent reports and numerical provenance are frozen in tests/oracles.json
and research/oracle-provenance.json with research/oracle-freeze.json hashes.
