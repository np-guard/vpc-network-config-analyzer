/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func newNACLUnattachedLint(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "NACL for which there are no resources attached to",
			enable:      true,
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findUnattachedTables}
}

func newSGUnattachedLint(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "SG for which there are no resources attached to",
			enable:      true,
		},
		layer:          vpcmodel.SecurityGroupLayer,
		checkForFilter: findUnattachedTables}
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
func findUnattachedTables(configs map[string]*vpcmodel.VPCConfig, filterLayerName string) (res []finding, err error) {
	for _, config := range configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing this lint on dummy vpcs
		}
		filterLayer := config.GetFilterTrafficResourceOfKind(filterLayerName)
		layerName := vpcmodel.FilterKindName(filterLayerName)
		filtersAttachedResources := filterLayer.GetFiltersAttachedResources()
		for table, attached := range filtersAttachedResources {
			if len(attached) == 0 {
				res = append(res, &nonConnectedTable{layerName: layerName, vpcOfTable: config.VPC, table: table})
			}
		}
	}
	return res, nil
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
