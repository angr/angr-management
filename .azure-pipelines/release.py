#!/usr/bin/env python3

import github
import glob
import logging
import os
import shutil
import sys

GITHUB_AUTH_TOKEN = os.environ["GITHUB_AUTH_TOKEN"]
AM_BUILD_NUMBER = os.environ["AM_BUILD_NUMBER"]
GIT_HASH = os.environ["GIT_HASH"]

l = logging.getLogger()

def create_release_tag(repo):
    tag_name = f"refs/tags/nightly-{AM_BUILD_NUMBER}"
    author = github.InputGitAuthor(
        "angr-release-bot", "angr@lists.cs.ucsb.edu")
    repo.create_git_ref(tag_name, GIT_HASH)
    tag = repo.create_git_tag(tag_name, tag_name, GIT_HASH, "commit", tagger=author)
    if tag is not None:
        l.info("Successfully created tag named `%s`", tag_name)
    else:
        l.critical("Failed to create tag!")
    return tag


def create_release(repo, tag):
    title = f"angr-management nightly release #{AM_BUILD_NUMBER}"
    message = f"This is an automated release based on commit {GIT_HASH}. It has not recieved any testing or validation, but may be useful to users looking to test the latest and greatest features of angr-management."
    release = repo.create_git_release(tag.tag, title, message, prerelease=True)
    if release is not None:
        l.info("Successfully created release.")
    else:
        l.critical("Failed to create release!")
    return release


def publish_release_artifacts(release):
    for artifact in glob.glob("dist/*"):
        # Need to zip up macOS .apps
        if os.path.isdir(artifact):
            shutil.make_archive(artifact, "zip", artifact)
            artifact = f"{artifact}.zip"
        asset = release.upload_asset(artifact)
        if asset is not None:
            l.info("Successfully uploaded asset %s", artifact)
        else:
            l.warning("Failed to upload asset %s", artifact)


def main():
    g = github.Github(GITHUB_AUTH_TOKEN)
    repo = g.get_repo("angr/angr-management")
    tag = create_release_tag(repo)
    release = create_release(repo, tag)
    publish_release_artifacts(release)


if __name__ == "__main__":
    l.setLevel(logging.DEBUG)
    main()
