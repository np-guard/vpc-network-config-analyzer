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

const nonConnectedTablesName = "non-connected tables"
const securityGroup = "security group"
const networkACL = "network ACL"

// nonConnectedTables: tables - sgs/nacls - not connected to any endpoint/subnet
type nonConnectedTablesLint struct {
	basicLinter
}

// a rule with the list of subnets it splits
type nonConnectedTable struct {
	vpcResource vpcmodel.VPC // todo: remove
	layerName   string
	filterName  string // todo: replace with FilterResource Interface which also has VPC
}

// /////////////////////////////////////////////////////////
// lint interface implementation for filterRuleSplitSubnetLint
// ////////////////////////////////////////////////////////
func (lint *nonConnectedTablesLint) lintName() string {
	return nonConnectedTablesName
}

func (lint *nonConnectedTablesLint) lintDescription() string {
	return "Access control tables not connected to any resource"
}

func (lint *nonConnectedTablesLint) check() error {
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		thisConfigInternalIP := getInternalIPBlocks(config)
		for _, table := range config.FilterResources {
			tableConnected := false
			for _, tableIPBlock := range table.ReferencedIPblocks() {
				if tableIPBlock.Overlap(thisConfigInternalIP) {
					tableConnected = true
					break
				}
			}
			layerName := securityGroup
			if table.Kind() == vpcmodel.NaclLayer {
				layerName = networkACL
			}
			if !tableConnected {
				lint.addFinding(&nonConnectedTable{vpcResource: config.VPC, layerName: layerName, filterName: table.Name()})
			}
		}
	}
	return nil
}

// returns an IPBlock of all the internal endpoints (e.g. VSI) of a given VPCConfig
func getInternalIPBlocks(config *vpcmodel.VPCConfig) *ipblock.IPBlock {
	internalIPBlock := ipblock.IPBlock{}
	for _, node := range config.Nodes {
		if node.IsExternal() {
			continue
		}
		internalIPBlock.Union(node.IPBlock())
	}
	return &internalIPBlock
}

///////////////////////////////////////////////////////////
// finding interface implementation for nonConnectedTable
//////////////////////////////////////////////////////////

func (finding *nonConnectedTable) vpc() []string {
	return []string{finding.vpcResource.Name()}
}

func (finding *nonConnectedTable) string() string {
	return fmt.Sprintf("%s %s of VPC %s has no resources connected to it", finding.layerName, finding.filterName,
		finding.vpc())
}

func (finding *nonConnectedTable) toJSON() any {
	return nil
}
