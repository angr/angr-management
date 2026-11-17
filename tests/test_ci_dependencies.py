from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import tomllib
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "resolve-uv-sources.py"
SPEC = importlib.util.spec_from_file_location("resolve_uv_sources", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)


class TestCIDependencies(unittest.TestCase):
    """Check companion selection and the configuration consumed by uv."""

    def setUp(self):
        self.sources = {
            "angr": {"git": "https://github.com/angr/angr.git", "branch": "master"},
            "cle": {"git": "https://github.com/angr/cle.git", "branch": "master"},
        }
        self.event = {"number": 10, "pull_request": {"body": "stale angr/angr#20"}}
        self.sha = "a" * 40
        self.current = {
            "body": "sync: angr/angr#30",
            "state": "open",
            "base": {"repo": {"full_name": "angr/angr-management"}},
        }
        self.dependency = {"state": "open", "base": {"repo": {"full_name": "angr/angr"}}, "head": {"sha": self.sha}}
        self.get_json = Mock(side_effect=[self.current, self.dependency])

    def resolve(self):
        return resolver.resolve_sources(self.sources, self.event, "angr/angr-management", self.get_json)

    def test_latest_body_selects_exact_head_from_declared_source(self):
        self.assertEqual(self.resolve(), {"angr": self.sha})
        self.assertEqual(
            [call.args[0] for call in self.get_json.call_args_list],
            ["repos/angr/angr-management/pulls/10", "repos/angr/angr/pulls/30"],
        )

    def test_declared_sources_can_each_select_a_companion(self):
        self.current["body"] += "\nhttps://github.com/angr/cle/pull/40"
        cle = {"state": "open", "base": {"repo": {"full_name": "angr/cle"}}, "head": {"sha": "b" * 40}}
        self.get_json.side_effect = [self.current, self.dependency, cle]
        self.assertEqual(
            self.resolve(),
            {
                "angr": self.sha,
                "cle": "b" * 40,
            },
        )

    def test_push_retains_project_sources_without_network(self):
        self.event = {"ref": "refs/heads/master"}
        self.assertEqual(self.resolve(), {})
        self.get_json.assert_not_called()

    def test_closed_origin_retains_project_sources(self):
        self.current["state"] = "closed"
        self.assertEqual(self.resolve(), {})
        self.get_json.assert_called_once_with("repos/angr/angr-management/pulls/10")

    def test_closed_companion_retains_project_sources(self):
        self.dependency["state"] = "closed"
        self.assertEqual(self.resolve(), {})
        self.assertEqual(self.sources["angr"]["branch"], "master")

    def test_http_failures_do_not_fall_back_to_master(self):
        error = urllib.error.HTTPError("https://api.github.com/", 403, "Forbidden", Message(), None)
        for replies in ([error], [self.current, error]):
            with self.subTest(replies=replies):
                self.get_json.side_effect = replies
                with self.assertRaises(urllib.error.HTTPError):
                    self.resolve()

    def test_invalid_dependency_identity_or_head_is_rejected(self):
        for dependency in (
            {"state": "open", "base": {"repo": {"full_name": "other/angr"}}, "head": {"sha": self.sha}},
            {"state": "open", "base": {"repo": {"full_name": "angr/angr"}}, "head": {"sha": "master"}},
            {"state": "unknown", "base": {"repo": {"full_name": "angr/angr"}}},
        ):
            with self.subTest(dependency=dependency):
                self.get_json.side_effect = [self.current, dependency]
                with self.assertRaises(ValueError):
                    self.resolve()

    def test_undeclared_references_and_shell_text_are_data(self):
        self.current["body"] = "$(touch injected) `echo injected` other/angr#1\n" + self.current["body"]
        with patch("subprocess.run", side_effect=AssertionError("No subprocess may execute body text")):
            self.assertEqual(self.resolve(), {"angr": self.sha})
        self.assertEqual(self.get_json.call_count, 2)

    def test_comment_links_cannot_select_dependencies(self):
        self.current["body"] = "https://github.com/angr/angr/pull/30#issuecomment-12"
        self.assertEqual(self.resolve(), {})
        self.get_json.assert_called_once_with("repos/angr/angr-management/pulls/10")

    def test_duplicate_same_reference_is_resolved_once(self):
        self.current["body"] += "\nhttps://github.com/angr/angr/pull/30"
        self.assertEqual(len(self.resolve()), 1)
        self.assertEqual(self.get_json.call_count, 2)

    def test_conflicting_references_are_rejected(self):
        self.current["body"] += "\nangr/angr#31"
        with self.assertRaisesRegex(ValueError, "Multiple dependency"):
            self.resolve()

    def test_http_transport_uses_fixed_api_origin(self):
        with (
            patch.dict(os.environ, {"GH_TOKEN": "test-token"}),
            patch.object(resolver.urllib.request, "urlopen", return_value=io.BytesIO(b'{"state":"open"}')) as urlopen,
        ):
            self.assertEqual(resolver.github_json("repos/angr/angr/pulls/30"), {"state": "open"})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/angr/angr/pulls/30")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertEqual(urlopen.call_args.kwargs, {"timeout": 30})

    def run_main(self, root):
        event = root / "event.json"
        event.write_text(json.dumps(self.event), encoding="utf-8")
        environment = {
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_REPOSITORY": "angr/angr-management",
            "RUNNER_TEMP": str(root),
            "GITHUB_ENV": str(root / "github-env"),
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(resolver.Path, "cwd", return_value=root),
            patch.object(resolver, "github_json", self.get_json),
        ):
            resolver.main()

    def test_main_preserves_real_project_configuration(self):
        original = (SCRIPT.parents[2] / "pyproject.toml").read_bytes()
        expected = tomllib.loads(original.decode("utf-8"))
        source = expected["tool"]["uv"]["sources"]["angr"]
        for ref in ("branch", "tag", "rev"):
            source.pop(ref, None)
        source["rev"] = self.sha
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "pyproject.toml"
            project.write_bytes(original)
            github_env = root / "github-env"
            github_env.write_text("EXISTING=value\n", encoding="utf-8")
            self.run_main(root)
            actual = tomllib.loads(project.read_text(encoding="utf-8"))
            self.assertEqual(actual, expected)
            self.assertEqual(actual["tool"]["uv"]["extra-build-dependencies"], {"keystone-engine": ["cmake<4"]})
            self.assertEqual(github_env.read_text(encoding="utf-8"), "EXISTING=value\n")
            self.assertFalse((root / "angr-management-uv.toml").exists())

    def test_ref_kinds_preserve_all_other_bytes(self):
        for ref in ("branch", "tag", "rev"):
            for newline in ("\n", "\r\n"):
                with self.subTest(ref=ref, newline=repr(newline)):
                    original = (
                        "# retained comment\n[tool.uv.sources] # sources\n"
                        f'"angr" = {{ git = "https://github.com/angr/angr.git", {ref}  = \'old\', '
                        'subdirectory = "python", marker = "sys_platform == \'linux\'" } # retained\n'
                        'cle = { git = "https://github.com/angr/cle.git", tag = "v1" }\n'
                        '[tool.uv.extra-build-dependencies]\nkeystone-engine = ["cmake<4"]\n'
                    ).replace("\n", newline)
                    self.assertEqual(
                        resolver.pin_sources(original, {"angr": self.sha}),
                        original.replace(f"{ref}  = 'old'", f"rev  = '{self.sha}'"),
                    )

    def test_no_companion_does_not_write_project_or_config(self):
        self.current["body"] = "No companion"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "pyproject.toml"
            original = '[tool.uv.sources.angr]\ngit = "https://github.com/angr/angr.git"\nbranch = "master"\n'
            project.write_text(original, encoding="utf-8")
            with patch.object(resolver.Path, "write_bytes", side_effect=AssertionError("Unexpected project write")):
                self.run_main(root)
            self.assertEqual(project.read_text(encoding="utf-8"), original)
            self.assertFalse((root / "github-env").exists())
            self.assertFalse((root / "angr-management-uv.toml").exists())

    def test_invalid_or_ambiguous_format_refuses_before_writing(self):
        projects = (
            '[tool.uv.sources.angr]\ngit = "https://github.com/angr/angr.git"\nbranch = "master"\n',
            '[tool.uv.sources]\nangr = { git = "https://github.com/angr/angr.git", branch = "master", rev = "old" }\n',
            '[tool.uv.sources]\nangr = { git = "https://github.com/angr/angr.git", "branch" = "master" }\n',
            (
                '[tool.uv.sources]\nangr = { git = "https://github.com/angr/angr.git", branch = "master" }\n'
                'text = """\nangr = { branch = "spoof" }\n"""\n'
            ),
        )
        for original in projects:
            with self.subTest(original=original), tempfile.TemporaryDirectory() as directory:
                self.get_json.side_effect = [self.current, self.dependency]
                root = Path(directory)
                project = root / "pyproject.toml"
                project.write_text(original, encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.run_main(root)
                self.assertEqual(project.read_text(encoding="utf-8"), original)
                self.assertFalse((root / "github-env").exists())

    def test_full_project_comparison_refuses_misleading_string_content(self):
        original = (
            "text = '''\n[tool.uv.sources]\n"
            "angr = { branch = \"spoof\" }\n'''\n"
            '[tool.uv.sources.angr]\ngit = "https://github.com/angr/angr.git"\nbranch = "master"\n'
        )
        with self.assertRaisesRegex(ValueError, "unrelated project configuration"):
            resolver.pin_sources(original, {"angr": self.sha})

    def test_multiple_pins_and_existing_exact_revision(self):
        original = (
            '[tool.uv.sources]\nangr = { git = "https://github.com/angr/angr.git", branch = "master" }\n'
            'cle = { git = "https://github.com/angr/cle.git", tag = "v1" }\n'
        )
        expected = original.replace('branch = "master"', f'rev = "{self.sha}"').replace(
            'tag = "v1"', f'rev = "{"b" * 40}"'
        )
        self.assertEqual(resolver.pin_sources(original, {"angr": self.sha, "cle": "b" * 40}), expected)
        self.assertEqual(resolver.pin_sources(expected, {"angr": self.sha, "cle": "b" * 40}), expected)

    def test_invalid_pin_is_rejected(self):
        original = '[tool.uv.sources]\nangr = { git = "https://github.com/angr/angr.git", branch = "master" }\n'
        with self.assertRaisesRegex(ValueError, "Invalid dependency head"):
            resolver.pin_sources(original, {"angr": "master"})


if __name__ == "__main__":
    unittest.main()
