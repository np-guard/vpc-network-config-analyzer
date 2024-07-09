/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

type linter interface {
	check() (bool, error)    // false if issues found
	lintName() string        // this lint Name
	lintDescription() string // this string Name
	string() string          // string with this lint's finding
	toJSON() []any           // this lint finding in JSON
	getFindings() []finding
}

type finding interface {
	vpc() string
	string() string
	toJSON() any
}

type basicLinter struct {
	configs map[string]*vpcmodel.VPCConfig
}
