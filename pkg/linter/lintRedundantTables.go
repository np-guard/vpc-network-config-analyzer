/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// redundantTablesLint: tables - sgs/nacls - that no endpoint/subnet are attached to them
type redundantTablesLint struct {
	basicLinter
}

func newRedundantTablesLint(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &redundantTablesLint{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "Access control tables for which there are no resources attached to",
			enable:      true,
		}}
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

// todo: followup https://github.com/np-guard/vpc-network-config-analyzer/issues/718
func (lint *redundantTablesLint) check() error {
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		for _, layer := range vpcmodel.FilterLayers {
			filterLayer := config.GetFilterTrafficResourceOfKind(layer)
			layerName := vpcmodel.FilterKindName(layer)
			filtersAttachedResources := filterLayer.GetFiltersAttachedResources()
			for table, attached := range filtersAttachedResources {
				if len(attached) == 0 {
					lint.addFinding(&nonConnectedTable{layerName: layerName, vpcOfTable: config.VPC, table: table})
				}
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for nonConnectedTable
//////////////////////////////////////////////////////////

func (finding *nonConnectedTable) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.vpcOfTable}
}

func (finding *nonConnectedTable) string() string {
	return fmt.Sprintf("%s %s of VPC %s has no resources attached to it", finding.layerName, finding.table.FilterName,
		finding.vpc()[0].Name())
}

type nonConnectedTableJSON struct {
	vpcName   string
	layerName string
	tableName string
}

func (finding *nonConnectedTable) toJSON() any {
	return nonConnectedTableJSON{vpcName: finding.vpc()[0].Name(), layerName: finding.layerName, tableName: finding.table.FilterName}
}
