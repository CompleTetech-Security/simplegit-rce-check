<p align="center">
  <img src="docs/images/banner.png" alt="simplegit-rce-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <a href="https://github.com/CompleTetech-Security/simplegit-rce-check/actions"><img src="https://img.shields.io/github/actions/workflow/status/CompleTetech-Security/simplegit-rce-check/tests.yml?label=tests" alt="Tests"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-1E3A8A" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-none-067647" alt="No runtime dependencies">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

# simplegit-rce-check

Offline evidence checker for **CVE-2026-102826 — simple-git configuration include command injection**.

It compares simple-git version evidence that you supply (CLI values, JSON/CSV inventories, npm lockfiles, installed manifests) with the reviewed advisory rules, and can list lexical source review candidates. It never contacts websites, imports application code, runs Git or a package manager, or executes exploit payloads.

- [Scope and limits](#scope-and-limits)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Synthetic report preview](#synthetic-report-preview)
- [Version rules](#version-rules)
- [Operator observations](#operator-observations)
- [Input modes](#input-modes)
- [Options](#options)
- [Output and exit status](#output-and-exit-status)
- [Bounds and file safety](#bounds-and-file-safety)
- [Sources and references](#sources-and-references)
- [Development, security and license](#development-security-and-license)

## Scope and limits

- **Evidence triage, not a scanner.** The checker covers only CVE-2026-102826 and assesses reported package-version evidence. A public URL cannot reveal an installed package inventory, and no network mode exists.
- **Reported versions are claims.** Obtain each deployed package instance's exact version and provenance. Declarations, lockfiles, manifests and local workstation versions are not deployment evidence.
- **Nothing is exploited or verified in production.** `potentially_affected` is not confirmed exploitability, and `fixed_version_reported` never attests an installed patch or safety. Every result retains `exploitability: not_tested`.
- **Uncertainty stays visible.** Missing, conflicting, malformed, prerelease, qualified, vendor/custom-built and uncovered-future versions are reported as `unknown`. `unknown` is neither a finding nor a clean result.
- **Source inspection is lexical.** It produces review targets only. No taint analysis, reachability test or runtime evaluation is performed.

Operate it only on evidence you are authorized to handle. Reports contain operator data; keep real targets, inventories and reports out of commits.

## Requirements

- Python 3.10 or newer, standard library only; no installation step.
- The single file `simplegit_rce_check.py` can be copied and run alone. It bundles its own bounded input/reporting helpers and source lexer, and needs no companion repository at runtime.

## Quick start

```sh
python simplegit_rce_check.py --version 4.0.0 --format json
python simplegit_rce_check.py --inventory examples/inventory.example.json --format html --output report.html
python simplegit_rce_check.py --csv-list inventory.csv --fail-on-finding
python simplegit_rce_check.py --help
python -m unittest -v
```

`inventory.csv` is your own file (see [JSON and CSV inventories](#json-and-csv-inventories)); the other inputs ship in `examples/`. The default output format is CSV on stdout. `python -m unittest -v` runs the local-only synthetic tests.

## Synthetic report preview

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
  <img src="docs/images/report-light.png" alt="simple-git synthetic report" width="100%">
</picture>

[Open the synthetic example report](docs/example-report.html). Example data only; this is not a live assessment.

## Version rules

The primary advisory and reviewed database were retrieved on 2026-10-24 (`rules_as_of` in every report).

| Example reported version | Result |
| --- | --- |
| 3.35.9 | `potentially_affected` |
| 3.36.0 | `potentially_affected` |
| 3.36.1 | `unknown` |
| 3.99.0 | `unknown` |
| 4.0.0 | `fixed_version_reported` |
| 4.0.1 | `fixed_version_reported` |
| 5.0.0 | `unknown` |

Do not invent affected status for hypothetical versions between 3.36.0 and 4.0.0. include.path and includeIf variants share this advisory.

### Interpreting statuses

| Status | Meaning |
| --- | --- |
| `potentially_affected` | The reported version is in the documented affected interval (up to and including 3.36.0). Application preconditions and exploitability were not established; this is not confirmed exploitability. |
| `fixed_version_reported` | The reported version is 4.0.0 or later within the reviewed `4.x` fixed line. This describes a version claim only; it never attests an installed patch or safety. |
| `unknown` | Anything else: versions outside the affected interval and fixed line (no safety or other-vulnerability conclusion is made), future lines (no patch claim is extrapolated), and missing, conflicting, malformed, prerelease, qualified or custom/vendor builds. |

Each row also carries a more specific `version_status`, such as `in_documented_affected_range`, `at_or_above_fixed_version`, `outside_reviewed_range`, `version_not_disclosed`, `conflicting_versions`, `qualified_version_unverified`, `unrecognized_or_partial_version` or `vendor_build_unverified`. The `build_source` value `unknown` (the default), `upstream` or `official` is compared as an upstream build; any other value, such as a vendor name, keeps the result `unknown` until independent patch evidence exists. Leading `v` prefixes are accepted.

## Operator observations

Three optional observations describe advisory preconditions. They are supplied by the operator, unverified, and never change the package-version result.

| Observation | Meaning |
| --- | --- |
| `attacker_influence_over_clone_mirror_customargs` | attacker influence over clone/mirror customArgs |
| `attacker_controlled_readable_git_configuration_file` | attacker-controlled readable Git configuration file |
| `remote_operation_loads_unsafe_configuration` | remote operation loads unsafe configuration |

Each observation is boolean or null (not reported). Absent observations do not establish mitigation. Optional lexical source inspection is separate from them, and file-pattern findings show review targets, not proven input taint.

## Input modes

At least one input is required. Modes can be combined in one run; every input produces its own rows. Unless noted, each input file must be named explicitly and is only read.

### CLI versions

`--version` (alias `--package-version`) is repeatable. Each value is a separate instance, not evidence reconciliation for a single instance. `--build-source` and the observation flags (the observation key with underscores turned into hyphens, value `true` or `false`) apply to all CLI versions.

```sh
python simplegit_rce_check.py --version 3.36.0 --version 4.0.1 --format json
python simplegit_rce_check.py --version 4.0.0 --build-source "Example Vendor" --attacker-controlled-readable-git-configuration-file true
```

The second command stays `unknown` because the build is vendor-supplied.

### JSON and CSV inventories

- **JSON** (`--inventory`, repeatable): one object or an array of objects. Required: integer `schema_version: 1` and string `package_version`. Optional: `package: "simple-git"`, `label`, `build_source` and the observation keys above. Unknown or duplicate keys, wrong types, non-finite numbers and malformed inputs are rejected.
- **CSV** (`--csv-list`, repeatable): requires a `package_version` column. Optional columns are `label`, `build_source` and the observation keys (`true`, `false` or blank). NUL characters are rejected.

A runnable JSON example is in [`examples/inventory.example.json`](examples/inventory.example.json).

### npm lockfiles and installed manifests

```sh
python simplegit_rce_check.py --npm-lock examples/package-lock.example.json --format json
python simplegit_rce_check.py --installed-package path/to/node_modules/simple-git/package.json --format json
```

- `--npm-lock` reads explicitly named npm lock/shrinkwrap v1/v2/v3 JSON. Nested instances and aliases carrying an explicit package name remain separate. Metadata grammar follows the [official package-lock reference](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/), reviewed 2026-10-25. Lockfile URLs and scripts are not collected.
- Resolved versions are not proof of deployment. Linked packages, missing or qualified versions, conflicting primary/legacy lock records and unsupported coverage keep uncertainty, and conflicting version candidates are retained.
- When no determinable instance is found, the report includes an `unknown` coverage observation, never proof of absence.
- `--installed-package` reads only the name and version of an explicitly selected installed simple-git `package.json`, without running scripts or importing the module. Manifest metadata cannot attest that a serving process loads that package.

### Lexical source candidates

```sh
python simplegit_rce_check.py --source examples/source.example.js --source-root examples --format html
```

`--source` explicitly selects JS/TS files (`.js`, `.cjs`, `.mjs`, `.ts`, `.cts`, `.mts`, `.jsx`, `.tsx`) and requires `--source-root`, which provides relative evidence locations and must contain every selected file. There is no directory traversal and no execution.

- Simple literal CommonJS/ES imports (default/named aliases and namespace `simpleGit`), factory calls, directly assigned client spellings, and clone/mirror argument shapes produce lexical review candidates.
- Factory `config` and actual call arguments are inspected separately; an unrelated same-file `customArgs` or config object cannot establish a flow.
- Argument labels describe literal containers/strings or dynamic expressions, not input trust. Identifiers named `trustedConfig` or `request.body` do not prove trusted input or attacker control.
- Shadowing, reassignment, computed syntax, templates (including interpolation), callbacks, chained methods, execution order and regex/division ambiguity require manual review.
- Source rows always remain `unknown` with `not_tested` exploitability and unfilled operator observations. They never inherit the status of a separately supplied version, manifest or lock instance.
- When no supported candidate is found, the report includes an explicit `unknown` coverage row rather than an absence verdict.
- Source strings and snippets, registry URLs and manifest scripts are not included in reports.

## Options

| Option | Purpose |
| --- | --- |
| `--version VERSION` (`--package-version`) | Assess an explicitly supplied simple-git version; repeatable. |
| `--build-source SOURCE` | Provenance of the `--version` builds (at most 512 characters): `unknown` (default, compared as upstream), `upstream`, `official`, or a vendor name. |
| `--attacker-influence-over-clone-mirror-customargs`<br>`--attacker-controlled-readable-git-configuration-file`<br>`--remote-operation-loads-unsafe-configuration` | Operator observation (`true` or `false`) applied to `--version` inputs. |
| `--inventory FILE` | JSON inventory object or array; repeatable. |
| `--csv-list FILE` | CSV inventory; repeatable. |
| `--npm-lock FILE` | npm package-lock/shrinkwrap JSON, lockfile versions 1, 2 and 3; repeatable. Never invokes npm. |
| `--installed-package FILE` | Installed simple-git `package.json`; repeatable. |
| `--source FILE` | JS/TS file for lexical clone/mirror candidates; repeatable. Requires `--source-root`. |
| `--source-root DIR` | Directory that must contain every `--source` file; evidence paths are relative to it. |
| `--format csv\|json\|html` | Output format; default `csv`. |
| `--output FILE` | Write the report to a new file; default is stdout. |
| `--force` | Explicitly replace an existing output file. |
| `--brand NAME` | Organization name shown in the HTML report (at most 512 characters); default `CompleteTech LLC`. |
| `--fail-on-finding` | Exit 1 when any result is `potentially_affected`. |
| `--tool-version` | Print the tool name and version. |

Run `python simplegit_rce_check.py --help` for the authoritative option text.

## Output and exit status

JSON, formula-neutralized CSV and escaped script-free HTML are rendered from the same assessments.

| Format | Contents |
| --- | --- |
| JSON | One document with `tool`, `tool_version`, `generated_at`, `report_schema_version`, `cve`, `rules_as_of`, `sources`, `complete` and a `results` array. |
| CSV | One `record_type=result` row per asset observation. A zero-result report has a single `record_type=summary` row carrying completeness, schema, rule date, CVE and `not_tested`; it is not an asset finding. Every row carries `tool`, `tool_version` and `generated_at`. |
| HTML | Escaped, script-free report. Candidates and locations appear in escaped evidence notes. |

Report schema 1.1 adds `version_candidates`, `source_path`, `source_line`, `source_operation`, `source_argument_shapes`, `source_factory_options`, `source_config_argument` and `source_coverage` to JSON and CSV. See [docs/REFERENCE.md](docs/REFERENCE.md) for the detailed reference.

`generated_at` is the UTC assessment-run time, captured once and retained after interruption. It is separate from `rules_as_of`, the advisory verification date. Evidence collection time remains unknown unless the operator records it independently; neither date attests deployment or installed patches. Embedding callers can inject `generated_at` into `write_report` for deterministic rendering across formats.

### Exit status

| Code | Meaning |
| --- | --- |
| 0 | Run completed. |
| 1 | At least one result is `potentially_affected`, and `--fail-on-finding` was given. |
| 2 | Argument, input or output error; operational failures are not assessment results. |
| 130 | Interrupted. Completed observations are written with `complete=false` when possible. |

`unknown` does not trigger the finding gate and is not a clean result.

### Interruption and partial results

- An empty interrupted CSV retains its summary row.
- An interruption after a complete report is published preserves that report and exits 130.
- An interruption while writing to stdout can leave a truncated document and never appends a second report.
- If an interrupt leaves file publication indeterminate, the checker exits 130 without retrying. Inspect the output before retrying; the diagnostic does not establish whether publication succeeded.

## Bounds and file safety

- Only regular UTF-8 input files are accepted. Source files must resolve within the selected root.
- Limits: 4 MiB per file, 100 input files and 10,000 results per run, 512 characters per text field.
- npm lock traversal is limited to 64 dependency levels and 10,000 metadata entries. Source inspection is limited to 200,000 tokens per file and 4,096 tokens per inspected argument window.
- Output files are published atomically and are not overwritten without `--force`. Every input and its aliases stay protected from being overwritten, even with `--force`.
- Work from stable copies; file checks are not a filesystem sandbox.
- The checker performs no Git, npm, network, application or sandbox execution.

## Sources and references

Primary advisory sources (retrieved 2026-10-24):

- <https://github.com/steveukx/git-js/security/advisories/GHSA-g4wm-2vf7-vfgr>
- <https://github.com/advisories/GHSA-g4wm-2vf7-vfgr>

Repository documents:

- [docs/REFERENCE.md](docs/REFERENCE.md): detailed reference
- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md): implementation status and verification checklist
- [docs/example-report.html](docs/example-report.html): synthetic example report
- [AGENTS.md](AGENTS.md): repository instructions

Provenance of bundled code: the bounded input and reporting helpers come from the reviewed Node.js checker at commit `74aa57ba5df05c34d17ae67912cd26ec2335201b`, with package-specific range comparison and the mixed-whitespace CSV fix. The source lexer comes from vm2-nesting-check commit `1618874` under the same licensing.

## Development, security and license

Before changing the project, read [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Run `python -m unittest -v`, `python simplegit_rce_check.py --help` and `git diff --check`. Use synthetic evidence only and verify primary sources before changing version ranges. A local test pass is not a hosted CI result.

Report flaws in this project as described in [SECURITY.md](SECURITY.md). The project is licensed under AGPL-3.0 or a separate commercial license from CompleteTech LLC; see [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md). Contribution terms are in [CONTRIBUTING.md](CONTRIBUTING.md#licensing-of-contributions). CompleteTech LLC names, logos and the artwork in `docs/images/` are brand assets and are not covered by the code license; see [BRAND_ASSETS.md](BRAND_ASSETS.md).
