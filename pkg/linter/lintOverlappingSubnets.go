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
				if subnetStr(subnet1) > subnetStr(subnet2) {
					subnet1, subnet2 = subnet2, subnet1
				}
				lint.addFinding(&overlapSubnets{overlapSubnets: [2]vpcmodel.Subnet{subnet1, subnet2}, overlapIPBlocks: intersectIPBlock})
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for overlapSubnets
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
	overlapStr := ""
	if finding.overlapIPBlocks.String() == subnet1.CIDR() && subnet1.CIDR() == subnet2.CIDR() {
		overlapStr = " overlap in the entire subnets' CIDR range"
	} else {
		overlapStr = fmt.Sprintf(" overlap in %s", finding.overlapIPBlocks.String())
	}

	return subnetsStr + overlapStr
}

func subnetStr(subnet vpcmodel.Subnet) string {
	return fmt.Sprintf("subnet %s of cidr %s", subnet.Name(), subnet.CIDR())
}

// for json: details of overlapping subnets
type overlapSubnetsJSON struct {
	OverlapSubnets []subnetJSON `json:"couple_overlap_subnets"`
	OverlapCidr    string       `json:"overlap_cidr"`
}

type subnetJSON struct {
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	VpcName string `json:"vpc_name,omitempty"`
}

func (finding *overlapSubnets) toJSON() any {
	overlapsSubnetsJSON := make([]subnetJSON, 2)
	for i, overlapSubnet := range finding.overlapSubnets {
		overlapsSubnetsJSON[i] = subnetJSON{Name: overlapSubnet.Name(), VpcName: overlapSubnet.VPC().Name(), CIDR: overlapSubnet.CIDR()}
	}
	res := overlapSubnetsJSON{OverlapSubnets: overlapsSubnetsJSON, OverlapCidr: finding.overlapIPBlocks.String()}
	return res
}
