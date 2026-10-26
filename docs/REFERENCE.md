# simplegit-rce-check

Offline evidence checker for **CVE-2026-102826 — simple-git configuration include command injection**. Python 3.10+, standard library only. The executable can be copied alone. It never contacts websites, imports application code, runs a package manager, or executes exploit payloads.

```sh
python simplegit_rce_check.py --version 4.0.0 --format json
python simplegit_rce_check.py --inventory examples/inventory.example.json --format html --output report.html
python simplegit_rce_check.py --csv-list inventory.csv --fail-on-finding
python simplegit_rce_check.py --help
python -m unittest -v
```

## Reviewed rules

Primary advisory and reviewed database retrieved 2026-10-24. A public URL cannot provide installed package inventory. Obtain each deployed package instance's exact version and provenance; declarations and local workstation versions are not deployment evidence.

| Example reported version | Result |
| --- | --- |
| 3.35.9 | `potentially_affected` |
| 3.36.0 | `potentially_affected` |
| 3.36.1 | `unknown` |
| 3.99.0 | `unknown` |
| 4.0.0 | `fixed_version_reported` |
| 4.0.1 | `fixed_version_reported` |
| 5.0.0 | `unknown` |

Do not invent affected status for hypothetical versions between 3.36.0 and 4.0.0. File-pattern findings show review targets, not proven input taint. include.path and includeIf variants share this advisory.

The reviewed fixed line is `4.x`; future lines remain unknown rather than extrapolating a patch claim. Versions outside the exact affected interval remain unknown, including older releases that might have other flaws. Missing, conflicting, malformed, prerelease, qualified, custom/vendor builds remain unknown. `fixed_version_reported` only describes a version claim; it never attests installed patches or safety. `potentially_affected` is not confirmed exploitability. Every row retains `exploitability: not_tested`.

## Preconditions

| Optional operator observation | Meaning |
| --- | --- |
| `attacker_influence_over_clone_mirror_customargs` | attacker influence over clone/mirror customArgs |
| `attacker_controlled_readable_git_configuration_file` | attacker-controlled readable Git configuration file |
| `remote_operation_loads_unsafe_configuration` | remote operation loads unsafe configuration |

Each observation is boolean or null, is unverified, and never changes the package-version result. Optional lexical source inspection is separate. No taint analysis, reachability test or runtime evaluation is performed. Absent observations do not establish mitigation.

## Dependency and source evidence

```sh
python simplegit_rce_check.py --npm-lock examples/package-lock.example.json --format json
python simplegit_rce_check.py --source examples/source.example.js --source-root examples --format html
python simplegit_rce_check.py --installed-package path/to/node_modules/simple-git/package.json --format json
```

`--npm-lock` reads explicitly named npm lock/shrinkwrap v1/v2/v3 JSON. Nested
instances and aliases carrying an explicit package name remain separate.
Resolved versions are not proof of deployment; linked packages, missing/qualified
versions, conflicting primary/legacy lock records and unsupported coverage keep
uncertainty. Conflicting version candidates are retained. When no determinable
instance is found, the report includes an unknown coverage observation, never proof of absence.
`--installed-package` reads the name/version of an explicitly selected installed
simple-git manifest, without running scripts or importing the module. Manifest
metadata cannot attest that a serving process loads that package.

`--source` explicitly selects JS/TS files and requires `--source-root` for
relative locations. No directory traversal or execution occurs. Simple literal
CommonJS/ES imports (default/named aliases and namespace `simpleGit`), factory
calls, directly assigned client spellings, and clone/mirror argument shapes
produce lexical review candidates. Factory `config` and actual call arguments
are inspected separately; an unrelated same-file `customArgs` or config object
cannot establish a flow. Argument labels describe literal containers/strings or
dynamic expressions, not input trust. Identifiers named trustedConfig or
request.body do not prove trusted input or attacker control.

Shadowing, reassignment, computed syntax, templates (including interpolation),
callbacks, chained methods, execution order and regex/division ambiguity require
manual review. Source rows always remain `unknown` with `not_tested`
exploitability and unfilled operator observations; they never inherit the status
of a separately supplied version/manifest/lock instance. When no supported candidate
is found, the report includes an explicit unknown coverage row rather than an absence verdict.

All new input modes share existing 4 MiB/file, 100-file and 10,000-result limits.
Lock traversal is limited to 64 dependency levels and 10,000 metadata entries;
source is limited to 200,000 tokens/file and 4,096 tokens per inspected argument
window. Source files must resolve within the selected root. Output protection
covers every new input and its aliases even with --force. Stable copies are
recommended; file checks are not a filesystem sandbox. The checker performs no
Git, npm, network, application or sandbox execution.

JSON/CSV schema 1.1 adds `version_candidates`, `source_path`, `source_line`,
`source_operation`, `source_argument_shapes`, `source_factory_options`,
`source_config_argument` and `source_coverage`. HTML includes candidates and
locations in escaped evidence notes. Source strings/snippets, registry URLs and
manifest scripts are not included in reports. The standalone executable bundles
its lexer from vm2-nesting-check commit 1618874 under the same licensing; no
companion checkout is needed. Version rules and their date are unchanged.

## Evidence and reports

JSON accepts one object or an array of objects. Required: integer `schema_version: 1`, string `package_version`. Optional: `package: "simple-git"`, `label`, `build_source`, and the observation keys above. Unknown or duplicate keys, wrong types, non-finite numbers and malformed inputs are rejected. CSV requires `package_version`; optional columns are label, build_source, and observation keys (`true`, `false`, blank). CLI `--version` is repeatable; values are separate instances, not evidence reconciliation for a single instance. `--build-source` and observation flags (underscore becomes hyphen) apply to CLI versions.

Only regular UTF-8 input files are accepted. Limits: 4 MiB/file, 100 files, 10,000 entries total, 512 characters/text field. Work from stable copies; checks are not a filesystem sandbox. JSON, formula-neutralized CSV and escaped script-free HTML share assessments. Output files publish atomically and do not overwrite existing files without `--force`; inputs remain protected even with force.

Exit 0: completed run; 1: potentially affected with `--fail-on-finding`; 2: argument/input/output error; 130: interrupted, preserving completed observations when possible. Interruption during stdout can leave a truncated document and never appends a second report. Unknown does not count as a finding-gate failure or as a clean result. Reports contain operator data; keep real targets, inventories and reports out of commits.

## Sources and delivery

- https://github.com/steveukx/git-js/security/advisories/GHSA-g4wm-2vf7-vfgr
- https://github.com/advisories/GHSA-g4wm-2vf7-vfgr

[Synthetic report](example-report.html), [reference](REFERENCE.md), [implementation status](IMPLEMENTATION.md), [AGENTS](../AGENTS.md), [contribution terms](../CONTRIBUTING.md), [security policy](../SECURITY.md), [license](../LICENSE), [dual licensing](../LICENSING.md). Bounded input and reporting helpers are bundled from the reviewed Node.js checker at `74aa57ba5df05c34d17ae67912cd26ec2335201b`, with package-specific range comparison and the mixed-whitespace CSV fix. No companion repository is needed at runtime.

CSV `record_type=result` rows are asset observations. A zero-result report has a `record_type=summary` row carrying completeness, schema, rule date, CVE and `not_tested`; it is not an asset finding.

Every CSV result and zero-result summary also carries `tool`, `tool_version` and
`generated_at`, matching JSON and HTML. `generated_at` is the UTC assessment-run
time, captured once and retained after interruption. It is separate from
`rules_as_of` (advisory verification date). Evidence collection time remains
unknown unless independently recorded by the operator; neither date attests
deployment or installed patches. Embedding callers can inject `generated_at`
into `write_report` for deterministic rendering across formats.

CSV rejects NUL characters before writing a report. An interruption after a complete report is published preserves that report and exits 130.

If an interrupt leaves file publication indeterminate, the checker exits 130 without retrying. Inspect the output before retrying; the diagnostic does not establish whether publication succeeded.

Npm metadata grammar: [official package-lock reference](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/), reviewed 2026-10-25. Lockfile URLs and scripts are not collected.
