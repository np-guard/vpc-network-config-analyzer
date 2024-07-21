/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const nonConnectedTablesName = "non-connected tables"

// nonConnectedTables: tables - sgs/nacls - not connected to any endpoint/subnet
type nonConnectedTables struct {
	basicLinter
}

// a rule with the list of subnets it splits
type nonConnectedTable struct {
	LayerName   string `json:"layer"`
	FilterName  string `json:"table"`
	FilterIndex int    `json:"-"`
}

// /////////////////////////////////////////////////////////
// lint interface implementation for filterRuleSplitSubnetLint
// ////////////////////////////////////////////////////////
func (lint *nonConnectedTables) lintName() string {
	return nonConnectedTablesName
}

func (lint *nonConnectedTables) lintDescription() string {
	return "Security tables not connected to any resource"
}

func (lint *nonConnectedTables) check() error {
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		for _, layer := range vpcmodel.FilterLayers {
			_ = layer // todo tmp
			//filterLayer := config.GetFilterTrafficResourceOfKind(layer)
			//rules, err := filterLayer.GetRules()
			//if err != nil {
			//	return err
			//}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for nonConnectedTable
//////////////////////////////////////////////////////////

func (finding *nonConnectedTable) vpc() []string {
	return nil
}

func (finding *nonConnectedTable) string() string {
	return ""
}

func (finding *nonConnectedTable) toJSON() any {
	return nil
}
