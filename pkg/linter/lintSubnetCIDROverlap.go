/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// overlapSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type overlappingSubnetsLint struct {
	basicLinter
}

func newSubnetCIDROverlap(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &overlappingSubnetsLint{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "Overlapping subnet address spaces",
			enable:      true,
		}}
}

// a couple of overlapping subnets
type overlapSubnets struct {
	overlapSubnets  [2]vpcmodel.Subnet
	overlapIPBlocks *netset.IPBlock
}

// /////////////////////////////////////////////////////////
// lint interface implementation for overlapSubnets
// ////////////////////////////////////////////////////////

func (lint *overlappingSubnetsLint) check() error {
	allSubnets := []vpcmodel.Subnet{}
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue
		}
		allSubnets = append(allSubnets, config.Subnets...)
	}
	for i, subnet1 := range allSubnets {
		subnet1IPBlock := subnet1.AddressRange()
		for _, subnet2 := range allSubnets[i+1:] {
			subnet2IPBlock := subnet2.AddressRange()
			intersectIPBlock := subnet1IPBlock.Intersect(subnet2IPBlock)
			if !intersectIPBlock.IsEmpty() {
				// to make the content of the overlapSubnets struct deterministic
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

func (finding *overlapSubnets) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.overlapSubnets[0].VPC(), finding.overlapSubnets[1].VPC()}
}

func (finding *overlapSubnets) string() string {
	subnet1 := finding.overlapSubnets[0]
	subnet2 := finding.overlapSubnets[1]
	return fmt.Sprintf("VPC %q's %s and VPC %q's %s overlap", subnet1.VPC().Name(), subnetStr(subnet1),
		subnet2.VPC().Name(), subnetStr(subnet2))
}

func subnetStr(subnet vpcmodel.Subnet) string {
	return fmt.Sprintf("subnet %q [%s]", subnet.Name(), subnet.CIDR())
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
	for i := range finding.overlapSubnets {
		overlapsSubnetsJSON[i] = subnetJSON{Name: finding.overlapSubnets[i].Name(),
			VpcName: finding.overlapSubnets[i].VPC().Name(), CIDR: finding.overlapSubnets[i].CIDR()}
	}
	res := overlapSubnetsJSON{OverlapSubnets: overlapsSubnetsJSON, OverlapCidr: finding.overlapIPBlocks.String()}
	return res
}
