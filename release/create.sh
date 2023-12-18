#!/usr/bin/env bash

# Copyright 2023- IBM Inc. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# creates a release version commit for `cloud-resource-collector`
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

# make a commit denoting the version ($1)
make_commit() {
  git add "${VERSION_FILE}"
  git commit -m "version ${1}"
  echo "Created commit for ${1}"
}

# add a git tag with $1
add_tag() {
  git tag "${1}"
  echo "Tagged ${1}"
}

set_version "${1}"
make_commit "v${1}"
add_tag "v${1}"


# print follow-up instructions
echo ""
echo "Created commits for v${1}, you should now:"
echo " - git push"
echo " - File a PR with these pushed commits"
echo " - Merge the PR"
echo " - git push ${UPSTREAM} v${1}"
echo " - Create a GitHub release from the pushed tag v${1}"