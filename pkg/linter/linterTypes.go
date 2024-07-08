/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

type linter interface {
	check() ([]string, error) // returns []string of size 0 if no lint issues
	getName() string
	getDescription() string
	getFindings() []finding
}

type finding interface {
	String() string
	ToJSON() any
	VPC() string
	Linter() string
}

type basicLinter struct {
	config *vpcmodel.VPCConfig
}
