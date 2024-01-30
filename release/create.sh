#!/usr/bin/env bash

# Copyright 2023- IBM Inc. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# creates a release version commit for `vpc-network-config-analyzer`
# Use like: create.sh <release-version>
# EG: create.sh 0.3.0

UPSTREAM='https://github.com/np-guard/vpc-network-config-analyzer.git'

# cd to the repo root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${REPO_ROOT}"

# check for arguments
if [ "$#" -ne 1 ]; then
    echo "Usage: create.sh release-version"
    exit 1
fi

SED="sed"
if which gsed &>/dev/null; then
  SED="gsed"
fi
if ! (${SED} --version 2>&1 | grep -q GNU); then
  echo "!!! GNU sed is required.  If on OS X, use 'brew install gnu-sed'." >&2
  exit 1
fi

VERSION_FILE="./pkg/version/version.go"

# update core version in go code to $1
set_version() {
  ${SED} -i "s/VersionCore = .*/VersionCore = \"${1}\"/" "${VERSION_FILE}"
  echo "Updated ${VERSION_FILE} for ${1}"
}

# create a new branch for a release from ($1)
create_release_branch() {
  git checkout -b "release_${1}"
  echo "Created release branch for ${1}"
}

# make a commit denoting the version ($1)
make_commit() {
  git add "${VERSION_FILE}"
  git commit -m "version ${1}"
  echo "Created commit for ${1}"
}

# make a commit denoting the version ($1)
push_commit() {
  git push --set-upstream origin "release_${1}"
  echo "Pushed commit ${1}"
}

set_version "${1}"
create_release_branch "${1}"
make_commit "v${1}"
push_commit "${1}"


# print follow-up instructions
echo ""
echo "Created commit for v${1}, you should now:"
echo " - File a PR with the pushed commit"
echo " - Merge the PR to main"
echo " - Run './release/tag.sh'"
echo " - Create a GitHub release from the pushed tag v${1}"