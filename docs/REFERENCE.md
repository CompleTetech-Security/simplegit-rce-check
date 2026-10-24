# Evidence and CLI reference

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

Each observation is boolean or null, is unverified, and never changes the package-version result. No source search, taint analysis, reachability test, or runtime evaluation is performed. Absent observations do not establish mitigation.

## Evidence and reports

JSON accepts one object or an array of objects. Required: integer `schema_version: 1`, string `package_version`. Optional: `package: "simple-git"`, `label`, `build_source`, and the observation keys above. Unknown or duplicate keys, wrong types, non-finite numbers and malformed inputs are rejected. CSV requires `package_version`; optional columns are label, build_source, and observation keys (`true`, `false`, blank). CLI `--version` is repeatable; values are separate instances, not evidence reconciliation for a single instance. `--build-source` and observation flags (underscore becomes hyphen) apply to CLI versions.

Only regular UTF-8 input files are accepted. Limits: 4 MiB/file, 100 files, 10,000 entries total, 512 characters/text field. Work from stable copies; checks are not a filesystem sandbox. JSON, formula-neutralized CSV and escaped script-free HTML share assessments. Output files publish atomically and do not overwrite existing files without `--force`; inputs remain protected even with force.

Exit 0: completed run; 1: potentially affected with `--fail-on-finding`; 2: argument/input/output error; 130: interrupted, preserving completed observations when possible. Interruption during stdout can leave a truncated document and never appends a second report. Unknown does not count as a finding-gate failure or as a clean result. Reports contain operator data; keep real targets, inventories and reports out of commits.

## Sources and delivery

- https://github.com/steveukx/git-js/security/advisories/GHSA-g4wm-2vf7-vfgr
- https://github.com/advisories/GHSA-g4wm-2vf7-vfgr

[Synthetic report](docs/example-report.html), [reference](docs/REFERENCE.md), [implementation status](docs/IMPLEMENTATION.md), [AGENTS](AGENTS.md), [contribution terms](CONTRIBUTING.md), [security policy](SECURITY.md), [license](LICENSE), [dual licensing](LICENSING.md). Bounded input and reporting helpers are bundled from the reviewed Node.js checker at `74aa57ba5df05c34d17ae67912cd26ec2335201b`, with package-specific range comparison and the mixed-whitespace CSV fix. No companion repository is needed at runtime.
