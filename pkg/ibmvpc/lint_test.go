/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

var lintTests = []*commonvpc.VpcLintTest{
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "basic_acl3",
			InputConfig: "acl_testing3",
		},
		Enable: []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "acl3_shadowed_rules",
			InputConfig: "acl_testing3_with_redundant_rules",
		},
		Enable: []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "acl3_shadowed_rules_other_lints_disabled",
			InputConfig: "acl_testing3_with_redundant_rules",
		},
		Disable: []string{"nacl-split-subnet", "subnet-cidr-overlap", "nacl-unattached",
			"sg-unattached", "sg-rule-cidr-out-of-range", "nacl-rule-cidr-out-of-range",
			"tcp-response-blocked", "sg-rule-implied"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "acl3_3rd",
			InputConfig: "acl_testing3_3rd",
		},
		Enable: []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "basic_sg1",
			InputConfig: "sg_testing1_new",
		},
		Enable: []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "multivpc",
			InputConfig: "tgw_larger_example",
		},
		Enable: []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "multivpc_print_all",
			InputConfig: "tgw_larger_example",
		},
		PrintAllLints: true,
		Enable:        []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "multivpc_partly_overlap",
			InputConfig: "tgw_larger_example_partly_overlap",
		},
		Enable: []string{"sg-split-subnet"},
	},
	{
		VpcTestCommon: commonvpc.VpcTestCommon{
			Name:        "PartialTCPRespond",
			InputConfig: "sg_testing1_new_respond_partly",
		},
		Enable: []string{"sg-split-subnet"},
	},
}

func TestAllLint(t *testing.T) {
	// lintTests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.Mode = commonvpc.OutputComparison
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &IBMresourcesContainer{}
			tt.TestSingleLint(t, rc)
		})
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing

/*func TestAllLintWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.Mode = commonvpc.OutputGeneration
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &IBMresourcesContainer{}
			tt.TestSingleLint(t, rc)
		})
	}
	fmt.Println("done")
}*/
