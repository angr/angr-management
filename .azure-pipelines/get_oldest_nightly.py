#!/usr/bin/env python3
"""
To avoid clutter in the releases tab on GitHub, this script has been written to
pick an old release to delete, which is passed to a GitHubRelease task in
./master.yml. It doesn't handle cases there are multiple old releases, but since
this script is run after every nightly release, that shouldn't be a real issue.
"""

import github
import re
import sys


def main():
    if len(sys.argv) < 2:
        print("Missing repo argument!")
        sys.exit(1)
    repo_name = sys.argv[1]

    g = github.Github()
    r = g.get_repo(sys.argv[1])
    releases = r.get_releases()
    filtered = [x for x in releases if re.match("^nightly-\\d+$", x.tag_name)]

    if len(filtered) > 1:
        time_map = {k.created_at: k for k in filtered}
        oldest = time_map[min(time_map.keys())]
        print(f"##vso[task.setvariable variable=old_release]{oldest.tag_name}")


if __name__ == "__main__":
    main()
