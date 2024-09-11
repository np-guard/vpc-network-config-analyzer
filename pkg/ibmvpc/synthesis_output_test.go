/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const synthesisOut = "synthesis_out"

var synthesisTests = []*commonvpc.VpcGeneralTest{
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
}

// uncomment the function below to run for updating the expected output
/*
func TestAllWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range synthesisTests {
		tt := synthesisTests[testIdx]
		tt.Mode = commonvpc.OutputGeneration
		tt.Name = tt.InputConfig
		tt.Format = vpcmodel.Synthesis
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			runTestSynthesis(tt, t)
		})
	}
	fmt.Println("done")
}
*/

func TestAllSynthesis(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range synthesisTests {
		tt := synthesisTests[testIdx]
		tt.Mode = commonvpc.OutputComparison
		tt.Name = tt.InputConfig
		tt.Format = vpcmodel.Synthesis
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			runTestSynthesis(tt, t)
		})
	}
	fmt.Println("done")
}

func runTestSynthesis(tt *commonvpc.VpcGeneralTest, t *testing.T) {
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := commonvpc.GetVPCConfigs(t, tt, true, &IBMresourcesContainer{})
	// generate actual output for all use cases specified for this test
	for _, uc := range tt.UseCases {
		err := commonvpc.RunTestPerUseCase(t, tt, vpcConfigs, uc, tt.Mode, synthesisOut, nil)
		require.Equal(t, tt.ErrPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}
