# CVSS vector research

October 5, 2026. Research only under coordinator 04:18 SUCCESSORS.md.
Candidate revisions/blob IDs and retrieval limits: research/source-review.json.
No third-party code was executed, copied into an application or installed.

## Existing work and alternatives

Focused README/source checks: vulnerability-management-lab accepts a supplied
numeric CVSS value and adds contextual risk weights. It has no vector grammar or
version-specific score calculation. Do not import its synthetic vulnerability
records or change its policy. SARIF teaches declarations/provenance, not CVSS.
Keyless intentionally leaves severity unassessed. Relevant vault research/decision
keyword search found only central coordination; no dedicated matching lab. Home/
Codex Integration had already been consulted. This is not an exhaustive inventory.

| Profile | Teaching fit and cost |
| --- | --- |
| CVSS3.1 Base-only | Eight mandatory metrics, reordered inputs permitted, explicit scope-dependent calculation; small rational-arithmetic model |
| CVSS4.0 interpretation/scoring | Eleven Base metrics, fixed order, additional attack requirements and subsequent impacts; lookup/interpolation and default rules enlarge proof/licensing surface |

3.1 is an archived version on FIRST's current site, not the latest standard. Its
selection is a bounded learning choice, not a production-version recommendation.
The comparison is grounded in [FIRST 3.1](https://www.first.org/cvss/v3.1/specification-document)
sections6/7/AppendixA and [FIRST 4.0](https://www.first.org/cvss/v4.0/specification-document)
sections7/8. In each version, calculation depends on supplied assessments and
does not authenticate their correctness or establish business risk.

## Candidate assessment

**[RedHatProductSecurity/cvss](https://github.com/RedHatProductSecurity/cvss)**,
revision2f149099257ae06b98cef252efc440bddafe61e5 (August4,2025, Version3.6
commit). Connected search/tree/file calls inspected cvss3.py/constants3.py,
test_cvss3.py, setup.py/pyproject, workflow, LICENSE and vector generator.
Parser checks prefix, token shape, allowed values, duplicate/mandatory metrics;
calculation uses Decimal and ceiling rounding, scope-specific PR values, and
Base/Temporal/Environmental formulas. clean_vector strips optional X values;
that loses explicit-versus-omitted provenance for this proposed teaching output.
Runtime dependencies on modern Python are empty; build setuptools/wheel and
test jsonschema/tools still have their own supply-chain obligations.

Tests include malformed/duplicate/missing cases, claimed2592 Base3.1 cases and
100000 generated3.1 cases. These are source-observed definitions, not executed
passes or independently authenticated oracle data. One empty-field test appears
to omit assigning its new vector before asserting; do not count its presence as
verified coverage. CI uses checkout@v2 and tox action@main, unlike Jake's immutable
pin baseline. No candidate CI run, Scorecard or advisory audit was performed.
Latest inspected code commit is maintenance evidence, not confirmed ongoing
support. Issue71 clarifies score tuples; closed issue78 records ending Python2
test support; PR72 records corrected4.0 output ordering. Reports are not local
reproductions. License/source/setup identify LGPLv3-or-later: adoption/copying
would require preserving its licensing obligations. Do not copy its test corpus
or implementation into an MIT-only original project.

**[FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator)**,
revisionc5b0d409ae9f57c44264c6ce5f27d89298e1d32a (August19,2024). FIRST's
spec links this reference. Actual cvss_score.js/app.js/index.html/LICENSE and
complete tree inspected: MacroVector lookup, lower-vector distances, interpolation
and final Math.round; UI enforces ordered metrics. Tree has no test/workflow or
package manifest paths, not evidence that upstream tests do not exist elsewhere.
HTML loads Vue/Spectre via CDNs; a browser UI is unnecessary and outside offline
scope. BSD2-Clause notice obligations apply if borrowed. Open
[PR4](https://github.com/FIRSTdotorg/cvss-v4-calculator/pull/4) proposes an upstream
rounding-tie fix and reports changed scores; not executed/reproduced here. The
reference label is not a guarantee every revision matches all current fixes.

## Primary reference and numeric expectations

[FIRST calculator design](https://www.first.org/cvss/v3.1/use-design) publishes
Base6.1 for N/L/N/R/C/L/L/N, and Base8.6 for N/L/N/N/C/H/N/N (optional
metrics in that second demonstration do not change its Base score). The
[FIRST examples](https://www.first.org/cvss/v3.1/examples) provide further metric/
score tables, including9.8 and7.5. Use metric tokens/numbers as published controls,
without copying vulnerability narratives or assessing real vulnerabilities.

Canonical FIRST cvsscalc31.js retrieval failed: web reader rejects JavaScript
content type; direct request hit sandbox DNS denial, then approved transport
reset. A [pinned attributed mirror](https://github.com/DefectDojo/django-DefectDojo/blob/8b12d80ae30904fed44f5a84ff71f28da14bebaf/dojo/static/dojo/js/cvsscalc31.js)
was read (header, Base formulas, roundUp1). It carries FIRST2019/BSD3-Clause
style notice and five-decimal integer stabilization before rounding upward.
Live-origin equivalence is UNVERIFIED; DefectDojo itself was not assessed for
adoption. This lab proposes exact rational arithmetic following mathematical
Roundup, avoiding binary representation errors. It will not advertise universal
reference-engine equivalence; finite domain/helper comparison is a stage gate.

## Recommendation and worker limits

Build a small original stdlib3.1 Base teaching model. Do not fork the broader
libraries/UI, mix4.0 weights or imply production vulnerability assessment.
Published facts/equations and narrowly attributed examples support independent
code; no installed dependency or borrowed scorer is necessary. MIT for original
code after approval; FIRST ownership/permission attribution plus score-and-vector
pairing are required. Borrowed source/test-data licensing would need separate
review before use. No current universal-safety or exhaustive-candidate claim.

Firecrawl status could not retrieve account/credits, so no credit-consuming
requests were made. Connected GitHub worked apart from one metadata failure;
public web supplemented primary docs. Local Ollama draft was rejected for
invented metric/rounding/duplicate semantics. One deliberately selected current
zero-priced OpenRouter public draft returned no text. Raw/failure/readiness
records remain separate in research/; no retry/provider switch/paid fallback.
Codex retained source verification, security judgment and necessary planning.
Laya's tested schemas are unsuitable for standards semantics. PLAN.md is the
concrete proposal; no implementation or test pass is claimed.
