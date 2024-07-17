/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const overlappingSubnetsName = "overlapping-subnets"

// overlapSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type overlappingSubnetsLint struct {
	basicLinter
}

// a couple of overlapping subnets
type overlapSubnets struct {
	overlapSubnets  [2]vpcmodel.Subnet
	overlapIPBlocks *ipblock.IPBlock
}

// /////////////////////////////////////////////////////////
// lint interface implementation for overlapSubnets
// ////////////////////////////////////////////////////////
func (lint *overlappingSubnetsLint) lintName() string {
	return overlappingSubnetsName
}

func (lint *overlappingSubnetsLint) lintDescription() string {
	return "Overlapping CIDR ranges between different subnets"
}

func (lint *overlappingSubnetsLint) check() error {
	allSubnets := []vpcmodel.Subnet{}
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue
		}
		allSubnets = append(allSubnets, config.Subnets...)
	}
	for i, subnet1 := range allSubnets {
		subnet1IPBlock, err1 := ipblock.FromCidr(subnet1.CIDR())
		if err1 != nil {
			return err1
		}
		for _, subnet2 := range allSubnets[i+1:] {
			subnet2IPBlock, err2 := ipblock.FromCidr(subnet2.CIDR())
			if err2 != nil {
				return err2
			}
			intersectIPBlock := subnet1IPBlock.Intersect(subnet2IPBlock)
			if !intersectIPBlock.IsEmpty() {
				lint.addFinding(&overlapSubnets{overlapSubnets: [2]vpcmodel.Subnet{subnet1, subnet2}, overlapIPBlocks: intersectIPBlock})
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for splitRuleSubnet
//////////////////////////////////////////////////////////

func (finding *overlapSubnets) vpc() []string {
	return []string{finding.overlapSubnets[0].VPC().Name(), finding.overlapSubnets[1].VPC().Name()}
}

func (finding *overlapSubnets) string() string {
	subnet1 := finding.overlapSubnets[0]
	subnet2 := finding.overlapSubnets[1]
	subnetsStr := ""
	if subnet1.VPC().Name() == finding.overlapSubnets[1].VPC().Name() {
		// same VPC
		subnetsStr = fmt.Sprintf("%s and %s, both from VPC %s,", subnetStr(subnet1), subnetStr(subnet2), subnet1.VPC().Name())
	} else {
		// different VPC
		subnetsStr = fmt.Sprintf("VPC %s's %s and VPC %s's %s ", subnet1.VPC().Name(), subnetStr(subnet1),
			subnet2.VPC().Name(), subnetStr(subnet2))
	}
	overlapStr := fmt.Sprintf(" overlaps in %s", finding.overlapIPBlocks.String()) + "\n"
	return subnetsStr + overlapStr
}

func subnetStr(subnet vpcmodel.Subnet) string {
	return fmt.Sprintf("subnet %s of cidr %s", subnet.Name(), subnet.CIDR())
}

func (finding *overlapSubnets) toJSON() any {
	return nil
}
