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
    """Return exact Git requirements without changing unreferenced project sources."""
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
            declared[name] = (package, url)

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
        package, url = declared[name]
        selected[package] = f"{package} @ git+{url}@{sha}"
        print(f"Using {package} from {name}#{dependency_number} at {sha}")
    return selected


def main() -> None:
    project = tomllib.loads((Path.cwd() / "pyproject.toml").read_text(encoding="utf-8"))
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    selected = resolve_sources(project["tool"]["uv"]["sources"], event, os.environ["GITHUB_REPOSITORY"], github_json)
    config = Path(os.environ["RUNNER_TEMP"]) / "angr-management-uv.toml"
    config.write_text(
        f"no-sources-package = {json.dumps(sorted(selected))}\n"
        f"upgrade-package = {json.dumps([selected[name] for name in sorted(selected)])}\n",
        encoding="utf-8",
    )
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
        output.write(f"UV_CONFIG_FILE={config}\n")


if __name__ == "__main__":
    main()
