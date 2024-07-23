/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
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
	layerName  string
	vpcOfTable vpcmodel.VPC
	table      vpcmodel.Filter
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
		for _, layer := range vpcmodel.FilterLayers {
			filterLayer := config.GetFilterTrafficResourceOfKind(layer)
			layerName := securityGroup
			if layer == vpcmodel.NaclLayer {
				layerName = networkACL
			}
			_, _ = filterLayer, layerName
			//rulesDetails, err := filterLayer.GetRules()
			//if err != nil {
			//	return err
			//}
			//tablesToIPBlocks := getMapFromTablesToIPBlocks(&rulesDetails)
			//for table, tableIPBlock := range tablesToIPBlocks {
			//	if !tableIPBlock.Overlap(thisConfigInternalIP) {
			//		fmt.Printf("about to add non connected table %+v\n", table)
			//		lint.addFinding(&nonConnectedTable{layerName: layerName, vpcOfTable: config.VPC, table: table})
			//	}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for nonConnectedTable
//////////////////////////////////////////////////////////

func (finding *nonConnectedTable) vpc() []string {
	return []string{finding.vpcOfTable.Name()}
}

func (finding *nonConnectedTable) string() string {
	return fmt.Sprintf("%s %s of VPC %s has no resources connected to it", finding.layerName, finding.table.FilterName,
		finding.vpc())
}

type nonConnectedTableJSON struct {
	vpcName   string
	layerName string
	tableName string
}

func (finding *nonConnectedTable) toJSON() any {
	return nonConnectedTableJSON{vpcName: finding.vpc()[0], layerName: finding.layerName, tableName: finding.table.FilterName}
}
