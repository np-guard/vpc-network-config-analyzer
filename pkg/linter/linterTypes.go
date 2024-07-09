/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// todo: export certain functionality
type linter interface {
	Check() ([]finding, error) // false if issues found
	LintName() string          // this lint Name
	LintDescription() string   // this string Name
	String() string            // string with this lint's finding
	ToJSON() []any             // this lint finding in JSON
}

type finding interface {
	vpc() string
	string() string
	toJSON() any
}

type basicLinter struct {
	configs map[string]*vpcmodel.VPCConfig
}
