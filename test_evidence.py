"""Synthetic installed dependency, lockfile and lexical source regressions."""
import contextlib
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import simplegit_rce_check as c


class EvidenceTests(unittest.TestCase):
    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = c.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def scan(self, code):
        return c.scan_source_text(code, "src/worker.ts")

    def test_arrow_return_regex_body_is_opaque(self):
        rows = self.scan("const pattern = () => /const git = require('simple-git'); git().clone(repo)/;")
        self.assertEqual(["source_coverage"], [row["evidence_type"] for row in rows])

    def test_javascript_line_terminators_preserve_comment_boundaries(self):
        for ending in ("\n", "\r\n", "\r", "\u2028", "\u2029"):
            with self.subTest(ending=repr(ending)):
                rows = self.scan(("// comment\n" + "import git from 'simple-git';\ngit().clone(repo);").replace("\n", ending))
                self.assertEqual("lexical_source_candidate", rows[0]["evidence_type"])
                self.assertEqual(3, rows[0]["source_line"])

    def test_import_aliases_instances_and_direct_factory_chains(self):
        for declaration, factory in [
            ("import git from 'simple-git';", "git"),
            ("import {simpleGit as git} from 'simple-git';", "git"),
            ("import * as lib from 'simple-git';", "lib.simpleGit"),
            ("const git=require('simple-git');", "git"),
            ("const {simpleGit: git}=require('simple-git');", "git"),
        ]:
            with self.subTest(declaration=declaration):
                rows = self.scan(declaration + "\nconst client=" + factory + "(); client.clone('repo','dest',customArgs);")
                row = rows[0]
                self.assertEqual("lexical_source_candidate", row["evidence_type"])
                self.assertEqual("clone", row["source_operation"])
                self.assertEqual("literal_string,literal_string,dynamic_or_unsupported", row["source_argument_shapes"])
                self.assertEqual(2, row["source_line"])
                self.assertEqual("unknown", row["status"])
                self.assertEqual("not_tested", row["exploitability"])
                self.assertTrue(all(row["precondition_" + k] == "not_reported" for k in c.PRECONDITION_KEYS))
        self.assertEqual("mirror", self.scan("import git from 'simple-git'; git().mirror(repo);")[0]["source_operation"])
        self.assertEqual("clone", self.scan("const client=require('simple-git')(); client.clone(repo);")[0]["source_operation"])

    def test_factory_config_and_constants_are_shapes_not_trust(self):
        for value in ["simple-git", "config", "customArgs"]:
            row = self.scan("import git from 'simple-git'; git().clone('" + value + "');")[0]
            self.assertEqual("literal_string", row["source_argument_shapes"])
        cases = [
            ("{config:['constant']}", "array_literal"),
            ("{config:request.options}", "dynamic_or_unsupported"),
            ("{config:trustedConfiguration}", "dynamic_or_unsupported"),
            ("{config:[] , ...options}", "unknown"),
            ("{config:[], config:external}", "unknown"),
        ]
        for options, config in cases:
            with self.subTest(options=options):
                row = self.scan("import git from 'simple-git'; const client=git(" + options + "); client.clone(repo,dest,['constant']);")[0]
                self.assertEqual(config, row["source_config_argument"])
                self.assertEqual("unknown", row["status"])
        row = self.scan("import git from 'simple-git'; const customArgs=req.body; const other={config:req.body}; git().clone('repo');")[0]
        self.assertEqual("not_observed", row["source_config_argument"])
        self.assertEqual("literal_string", row["source_argument_shapes"])

    def test_unrelated_clone_imports_comments_strings_and_regex(self):
        source = r'''
        import git from 'other';
        const client=git(); client.clone(repo);
        // const git=require('simple-git'); git().clone(repo);
        const text="require('simple-git'); git().clone(repo)";
        const regex=/git\(\)\.clone/;
        const template=`git().clone(repo)`;
        '''
        rows = self.scan(source)
        self.assertEqual(["source_coverage"], [r["evidence_type"] for r in rows])
        self.assertEqual("source_coverage", self.scan("import git from 'simple-git'; other.clone(repo);")[0]["evidence_type"])

    def test_source_never_publishes_literals_or_attests_shadowed_flow(self):
        row = self.scan("import git from 'simple-git'; function f(git) {git().clone('PRIVATE-SYNTHETIC-TEXT');}")[0]
        self.assertNotIn("PRIVATE-SYNTHETIC-TEXT", json.dumps(row))
        self.assertIn("Shadowing", " ".join(row["notes"]))
        self.assertEqual("insufficient", row["evidence_confidence"])

    def test_npm_lock_versions_transitive_instances_and_privacy(self):
        for version in [1, 2, 3]:
            with self.subTest(lockversion=version), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "lock.json"
                data = {"lockfileVersion": version}
                if version == 1:
                    data["dependencies"] = {"parent": {"version": "1.0.0", "dependencies": {"simple-git": {"version": "3.36.0", "resolved": "https://PRIVATE-SYNTHETIC.invalid/token"}}}, "simple-git": {"version": "4.0.0"}}
                else:
                    data["packages"] = {"": {}, "node_modules/parent/node_modules/simple-git": {"version": "3.36.0"}, "node_modules/simple-git": {"version": "4.0.0", "resolved": "https://PRIVATE-SYNTHETIC.invalid/token"}}
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, err = self.cli("--npm-lock", str(path), "--format", "json", "--fail-on-finding")
                self.assertEqual((1, ""), (code, err))
                self.assertEqual({"potentially_affected", "fixed_version_reported"}, {r["status"] for r in json.loads(out)["results"]})
                self.assertNotIn("PRIVATE-SYNTHETIC", out)
                self.assertNotIn(directory, out)

    def test_lock_aliases_links_conflicts_and_absence_keep_uncertainty(self):
        cases = [
            ({"node_modules/alias": {"name": "simple-git", "version": "4.0.0"}}, None, "fixed_version_reported"),
            ({"node_modules/simple-git": {"version": "4.0.0", "link": True}}, None, "unknown"),
            ({"node_modules/simple-git": {"version": "^4.0.0"}}, None, "unknown"),
            ({"node_modules/simple-git": {"version": "4.0.0"}}, {"simple-git": {"version": "3.36.0"}}, "unknown"),
            ({}, None, "unknown"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            for packages, legacy, status in cases:
                data = {"lockfileVersion": 2, "packages": packages}
                if legacy is not None:
                    data["dependencies"] = legacy
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, _ = self.cli("--npm-lock", str(path), "--format", "json")
                self.assertEqual(0, code)
                self.assertEqual({status}, {r["status"] for r in json.loads(out)["results"]})
                if legacy:
                    self.assertEqual(["3.36.0", "4.0.0"], json.loads(out)["results"][0]["version_candidates"])

    def test_malformed_lock_types_keys_locations_and_links_reject_before_output(self):
        cases = [
            '{"lockfileVersion":3,"packages":{},"packages":{}}',
            '{"lockfileVersion":3,"packages":{},"x":NaN}',
            json.dumps({"lockfileVersion": True, "packages": {}}),
            json.dumps({"lockfileVersion": 3, "packages": []}),
            json.dumps({"lockfileVersion": 3, "packages": {"../node_modules/simple-git": {"version": "4.0.0"}}}),
            json.dumps({"lockfileVersion": 3, "packages": {"node_modules/simple-git": {"name": "other", "version": "4.0.0"}}}),
        ]
        for flag in [None, 0, "", [], {}]:
            cases.append(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/simple-git": {"version": "4.0.0", "link": flag}}}))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            for data in cases:
                path.write_text(data, encoding="utf-8")
                code, out, _ = self.cli("--npm-lock", str(path), "--format", "json")
                self.assertEqual((2, ""), (code, out))

    def test_installed_manifest_identity_and_version_evidence_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "package.json"
            path.write_text(json.dumps({"name": "simple-git", "version": "4.0.0", "scripts": {"preinstall": "NEVER-EXECUTE"}}), encoding="utf-8")
            with mock.patch.object(subprocess, "run", side_effect=AssertionError("must not execute")):
                code, out, _ = self.cli("--installed-package", str(path), "--format", "json")
            self.assertEqual(0, code)
            self.assertEqual("fixed_version_reported", json.loads(out)["results"][0]["status"])
            self.assertNotIn("NEVER-EXECUTE", out)
            path.write_text('{"name":"other","version":"4.0.0"}', encoding="utf-8")
            self.assertEqual(2, self.cli("--installed-package", str(path))[0])

    def test_output_protects_every_new_input_mode_even_with_force(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode, name, data in [("--npm-lock", "lock.json", '{"lockfileVersion":3,"packages":{}}'), ("--installed-package", "package.json", '{"name":"simple-git","version":"4.0.0"}'), ("--source", "source.js", "import git from 'simple-git'; git().clone(repo);")]:
                path = root / name
                path.write_text(data, encoding="utf-8")
                args = [mode, str(path), "--output", str(path), "--force"]
                if mode == "--source":
                    args += ["--source-root", directory]
                self.assertEqual(2, self.cli(*args)[0])
                self.assertEqual(data, path.read_text(encoding="utf-8"))

    def test_source_and_metadata_work_limits_and_missing_root(self):
        for text in ["/*open", "'open", "({]", ";" * 200001]:
            with self.assertRaises(ValueError):
                self.scan(text)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.js"
            source.write_text("import git from 'simple-git'; git().clone(repo);", encoding="utf-8")
            self.assertEqual(2, self.cli("--source", str(source))[0])
            with mock.patch.object(c, "MAX_FILES", 1):
                self.assertEqual(2, self.cli("--source", str(source), "--source", str(source), "--source-root", directory)[0])
            path = root / "lock.json"
            tree = {"simple-git": {"version": "4.0.0"}}
            for _ in range(66):
                tree = {"p": {"dependencies": tree}}
            path.write_text(json.dumps({"lockfileVersion": 1, "dependencies": tree}), encoding="utf-8")
            self.assertEqual(2, self.cli("--npm-lock", str(path))[0])
            source.write_bytes(b" " * (c.MAX_INPUT_BYTES + 1))
            self.assertEqual(2, self.cli("--source", str(source), "--source-root", directory)[0])

    def test_source_output_parity_relative_paths_and_standalone_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ts"
            source.write_text("import git from 'simple-git'; git().clone(repo,dest,options);", encoding="utf-8")
            args = ["--source", str(source), "--source-root", directory]
            code, out, _ = self.cli(*args, "--format", "json")
            row = json.loads(out)["results"][0]
            self.assertNotIn(directory, out)
            self.assertEqual("source.ts", row["source_path"])
            _, out, _ = self.cli(*args, "--format", "csv")
            self.assertEqual(row["source_argument_shapes"], list(csv.DictReader(io.StringIO(out)))[0]["source_argument_shapes"])
            _, out, _ = self.cli(*args, "--format", "html")
            self.assertIn("source.ts:1", out)
            checker = root / "checker.py"
            checker.write_bytes(Path(c.__file__).read_bytes())
            result = subprocess.run([sys.executable, str(checker), *args, "--format", "json"], capture_output=True, text=True, check=True)
            self.assertEqual("clone", json.loads(result.stdout)["results"][0]["source_operation"])


if __name__ == "__main__":
    unittest.main()
