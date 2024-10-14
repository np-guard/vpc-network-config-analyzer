/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc/testfunc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

var diffTests = []*testfunc.VpcDiffTest{
	// diff tests:
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{ // example with diff with partial TCP respond
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_copy",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{ // example with diff in which the diff is in the amount of TCP respond enabled
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new_respond_partly",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{
		// diff between VPCs of different UIDs
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing_3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{
		// diff between identical VPCs
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing_default",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
	{
		// ports manipulation
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_diff_ports",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
			Format:      vpcmodel.Text,
		},
	},
}

// uncomment the function below to run for updating the expected output

/*
func TestDiffWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range diffTests {
		tt := diffTests[testIdx]
		tt.TestDiffSingle(t, testfunc.OutputGeneration, &IBMresourcesContainer{}, diffOut, tt.InputConfig)
	}
	fmt.Println("done")
}
*/

const diffOut = "diff_out"

func TestDiffWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range diffTests {
		tt := diffTests[testIdx]
		tt.TestDiffSingle(t, testfunc.OutputComparison, &IBMresourcesContainer{}, diffOut, tt.InputConfig)
	}
	fmt.Println("done")
}
