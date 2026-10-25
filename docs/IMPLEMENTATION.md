# Implementation status

Implemented offline package-version evidence checker, with independent source/semantic review and synthetic local verification on 2026-10-24. The exact documented affected interval through 3.36.0 and reviewed 4.x fixed line remain explicit. Hypothetical versions in the gap stay unknown. An empty interrupted CSV retains a summary row.

Local verification: 13 tests, CLI help, documented synthetic inputs, checksum validation and whitespace checks. Hosted CI must pass for the exact final PR head before merge; a local pass is not a hosted result. The advisory metadata now describes the implemented rule and preserves its original disabled research state under research_origin.

No live traffic, application execution, exploit verification or deployed-target assessment is claimed. Reported fixed versions do not attest installed patches; unknown evidence remains unknown.

## Dependency/source extension (2026-10-25)

Adds explicit installed simple-git manifests, bounded npm locks v1/v2/v3 with instance/conflict/link uncertainty, and lexical import-associated clone/mirror candidates. Source evidence never establishes taint, runtime configuration or a patch verdict. Relative locations, argument/config shapes, output parity and protected standalone operation have synthetic tests. Schema 1.1 is documented in README/REFERENCE. Primary advisory bounds are unchanged. Exact-head hosted CI and review remain separate release evidence.
