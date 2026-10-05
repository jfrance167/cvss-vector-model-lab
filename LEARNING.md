# Learning

- A correct formula does not verify supplied metric judgments, environment,
  real-world severity or business risk.
- Scope changes both impact and PR weights. Synthetic changed-Scope PR:H gives
  an unrounded 9.000964...; upward rounding produces 9.1, not 9.0.
- Not Defined X may be defaultable in a full engine while still being an
  explicit unsupported declaration in this provenance-preserving subset.
- Exact decimals are rationals. A floating-point repair should not silently
  change an exact value; check the finite domain instead of assuming parity.
- `type(x) in (...)` can invoke hostile metaclass equality. Use identity before
  length, iteration, hashing or comparisons on caller objects.
- Full reports detect provenance/order/status changes that score-only tests
  miss. Assertion-killed mutants demonstrate sensitivity, not full correctness.
- Interpreter shutdown may flush failed streams and alter exit status. Actual
  pipes closed before a release barrier test this beyond fake stream seams.
- Compaction briefly resumed an old storage discussion. HANDOFF.md now names
  the current approved CVSS scope to preserve continuation.
