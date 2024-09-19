/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const synthesisOut = "synthesis_out"

var synthesisTests = []*commonvpc.VpcTestCommon{
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
	},
	{
		InputConfig: "acl_testing4",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
	},
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
	},
	// multi-vpc
	{
		InputConfig: "multiple_vpcs",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
	},
	{
		InputConfig: "experiments_env",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
	},
	// grouping
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
	},
	{
		InputConfig: "subnet_grouping",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
	},
}

// uncomment the function below to run for updating the expected output

/*func TestSynthesisWithGeneration(t *testing.T) {
	for testIdx := range synthesisTests {
		tt := synthesisTests[testIdx]
		tt.Format = vpcmodel.Synthesis
		tt.TestCommonSingleTest(t, commonvpc.OutputGeneration, &IBMresourcesContainer{}, synthesisOut, tt.InputConfig)
	}
	fmt.Println("done")
}*/

func TestSynthesisWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range synthesisTests {
		tt := synthesisTests[testIdx]
		tt.Format = vpcmodel.Synthesis
		tt.TestCommonSingleTest(t, commonvpc.OutputComparison, &IBMresourcesContainer{}, synthesisOut, tt.InputConfig)
	}
	fmt.Println("done")
}
