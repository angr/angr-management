"""Select declared uv Git sources from the current pull request's dependencies."""

from __future__ import annotations

import json
import os
import re
import tomllib
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


PR_REFERENCE = re.compile(
    r"(?<![\w./-])(?:https://github\.com/)?(?P<repository>[\w.-]+/[\w.-]+)"
    r"(?:#|/pull/)(?P<number>[1-9][0-9]*)(?![\w/?#-])"
)


def github_json(endpoint: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com/{endpoint}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def resolve_sources(
    sources: dict[str, Any],
    event: dict[str, Any],
    repository: str,
    get_json: Callable[[str], dict[str, Any]],
) -> dict[str, str]:
    """Return exact Git revisions for referenced project sources."""
    if "pull_request" not in event:
        return {}
    if re.fullmatch(r"[\w.-]+/[\w.-]+", repository) is None:
        raise ValueError("Invalid originating repository")
    number = event["number"]
    if not isinstance(number, int) or number <= 0:
        raise ValueError("Invalid originating pull request number")
    current = get_json(f"repos/{repository}/pulls/{number}")
    if current["base"]["repo"]["full_name"] != repository:
        raise ValueError("Originating pull request belongs to another repository")
    if current["state"] == "closed":
        return {}
    if current["state"] != "open":
        raise ValueError("Invalid originating pull request state")

    declared = {}
    for package, source in sources.items():
        if not isinstance(source, dict):
            continue
        url = source.get("git", "")
        if not isinstance(url, str) or not url.startswith("https://github.com/"):
            continue
        name = url.removeprefix("https://github.com/").removesuffix(".git")
        if re.fullmatch(r"[\w.-]+/[\w.-]+", name) is not None and name != repository:
            declared[name] = package

    selected = {}
    seen = {}
    # Event bodies are snapshots; fetch again so reruns honor dependency edits.
    for match in PR_REFERENCE.finditer(current.get("body") or ""):
        name, dependency_number = match["repository"], int(match["number"])
        if name not in declared:
            continue
        if name in seen:
            if seen[name] != dependency_number:
                raise ValueError(f"Multiple dependency pull requests for {name}")
            continue
        seen[name] = dependency_number
        dependency = get_json(f"repos/{name}/pulls/{dependency_number}")
        if dependency["base"]["repo"]["full_name"] != name:
            raise ValueError(f"Dependency pull request belongs to another repository: {name}")
        if dependency["state"] == "closed":
            continue
        if dependency["state"] != "open":
            raise ValueError(f"Invalid dependency pull request state: {name}")
        sha = dependency["head"]["sha"]
        if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise ValueError(f"Invalid dependency head: {name}")
        package = declared[name]
        selected[package] = sha
        print(f"Using {package} from {name}#{dependency_number} at {sha}")
    return selected


def pin_sources(text: str, selected: dict[str, str]) -> str:
    """Replace inline Git refs while preserving the rest of the project configuration."""
    if not selected:
        return text
    expected = tomllib.loads(text)
    headers = list(re.finditer(r"(?m)^[ \t]*\[tool\.uv\.sources\][ \t]*(?:#[^\r\n]*)?\r?$", text))
    if len(headers) != 1:
        raise ValueError("Expected one [tool.uv.sources] table")
    start = headers[0].end()
    next_header = re.search(r"(?m)^[ \t]*\[", text[start:])
    end = start + next_header.start() if next_header else len(text)
    body = text[start:end]
    for package, sha in selected.items():
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise ValueError(f"Invalid dependency head: {package}")
        source = expected["tool"]["uv"]["sources"][package]
        refs = {"branch", "tag", "rev"}.intersection(source)
        if len(refs) != 1:
            raise ValueError(f"Expected one Git ref for {package}")
        ref = refs.pop()
        del source[ref]
        source["rev"] = sha
        key = re.escape(package)
        entries = list(
            re.finditer(
                rf"(?m)^[ \t]*(?:{key}|\"{key}\"|'{key}')[ \t]*=[ \t]*\{{(?P<fields>[^{{}}\r\n]*)\}}"
                r"[ \t]*(?:#[^\r\n]*)?\r?$",
                body,
            )
        )
        if len(entries) != 1:
            raise ValueError(f"Expected one inline source entry for {package}")
        entry = entries[0]
        fields = entry["fields"]
        references = list(
            re.finditer(
                r"(?:^|,)[ \t]*(?P<key>branch|tag|rev)(?P<equals>[ \t]*=[ \t]*)"
                r"(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*')(?=[ \t]*(?:,|$))",
                fields,
            )
        )
        if len(references) != 1 or references[0]["key"] != ref:
            raise ValueError(f"Unsupported Git ref format for {package}")
        match = references[0]
        quote = match["value"][0]
        offset = entry.start("fields")
        body = (
            body[: offset + match.start("key")]
            + f"rev{match['equals']}{quote}{sha}{quote}"
            + body[offset + match.end("value") :]
        )
    updated = text[:start] + body + text[end:]
    if tomllib.loads(updated) != expected:
        raise ValueError("Source ref replacement changed unrelated project configuration")
    return updated


def main() -> None:
    path = Path.cwd() / "pyproject.toml"
    original = path.read_bytes().decode("utf-8")
    project = tomllib.loads(original)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    selected = resolve_sources(project["tool"]["uv"]["sources"], event, os.environ["GITHUB_REPOSITORY"], github_json)
    updated = pin_sources(original, selected)
    if updated != original:
        path.write_bytes(updated.encode("utf-8"))


if __name__ == "__main__":
    main()
