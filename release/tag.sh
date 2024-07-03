#!/usr/bin/env bash

# Copyright 2023- IBM Inc. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Adds a git tag
# Use after creating a release commit with create.sh


UPSTREAM='https://github.com/np-guard/vpc-network-config-analyzer.git'

# cd to the repo root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${REPO_ROOT}"

VERSION_FILE="./pkg/version/version.go"
version_var="VersionCore"

# Use grep and awk to find and extract the constant value
version_core=$(grep -E "\bconst[[:space:]]+$version_var\b" "$VERSION_FILE" | awk -F'"' '/^const[[:space:]]*'"$version_var"'/ {print $2}')

if [ -z "$version_core" ]; then
    echo "$version_var not found in the Go file."
    exit 1
fi

checkout_main() {
  git checkout main
  git pull
}

# add a git tag with $1
add_tag() {
  git tag ${1}
  echo "Tagged ${1}"
}

# push git tag with $1
push_tag() {
    git push origin ${1}
}

checkout_main
add_tag v$version_core
push_tag v$version_core
