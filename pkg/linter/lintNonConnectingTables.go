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
type nonConnectedTablesLint struct {
	basicLinter
}

// a rule with the list of subnets it splits
type nonConnectedTable struct {
	vpcmodel.Table
}

// /////////////////////////////////////////////////////////
// lint interface implementation for filterRuleSplitSubnetLint
// ////////////////////////////////////////////////////////
func (lint *nonConnectedTablesLint) lintName() string {
	return nonConnectedTablesName
}

func (lint *nonConnectedTablesLint) lintDescription() string {
	return "Traffic controloing tables not connected to any resource"
}

func (lint *nonConnectedTablesLint) check() error {
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		for _, layer := range vpcmodel.FilterLayers {
			filterLayer := config.GetFilterTrafficResourceOfKind(layer)
			_, _ = layer, filterLayer // todo tmp
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
