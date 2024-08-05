/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const synthesisOut = "synthesis_out"

var synthesisTests = []*vpcGeneralTest{
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
	},
	{
		inputConfig: "acl_testing5",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
	},
}

// uncomment the function below to run for updating the expected output
/*
func TestAllWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range synthesisTests {
		tt := synthesisTests[testIdx]
		tt.mode = outputGeneration
		tt.name = tt.inputConfig
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTestSynthesis(t)
		})
	}
	fmt.Println("done")
}
*/

func TestAllSynthesis(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range synthesisTests {
		tt := synthesisTests[testIdx]
		tt.mode = outputComparison
		tt.name = tt.inputConfig
		tt.format = vpcmodel.Synthesis
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTestSynthesis(t)
		})
	}
	fmt.Println("done")
}

func (tt *vpcGeneralTest) runTestSynthesis(t *testing.T) {
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := getVPCConfigs(t, tt, true)
	// generate actual output for all use cases specified for this test
	for _, uc := range tt.useCases {
		err := runTestPerUseCase(t, tt, vpcConfigs, uc, tt.mode, synthesisOut, nil)
		require.Equal(t, tt.errPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}
