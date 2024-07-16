/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const overlappingSubnetsName = "overlapping-subnets"

// overlappingSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type overlappingSubnetsLint struct {
	basicLinter
}

// a rule with the list of subnets it splits
type overlappingTwoSubnets struct {
	overlappingSubnets [2]vpcmodel.Subnet
}

// /////////////////////////////////////////////////////////
// lint interface implementation for overlappingSubnets
// ////////////////////////////////////////////////////////
func (lint *overlappingSubnetsLint) lintName() string {
	return overlappingSubnetsName
}

func (lint *overlappingSubnetsLint) lintDescription() string {
	return "Overlapping CIDR ranges between different subnets"
}

func (lint *overlappingSubnetsLint) check() error {
	//for _, config := range lint.configs {
	//
	//}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for splitRuleSubnet
//////////////////////////////////////////////////////////

func (finding *overlappingTwoSubnets) vpc() []string {
	return []string{finding.overlappingSubnets[0].VPC().Name(), finding.overlappingSubnets[1].VPC().Name()}
}

func (finding *overlappingTwoSubnets) string() string {
	return ""
}

func (finding *overlappingTwoSubnets) toJSON() any {
	return nil
}
