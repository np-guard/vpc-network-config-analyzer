/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
	"github.com/stretchr/testify/require"
)

const synthesisOut = "synthesis_out"

var synthesisTests = []*vpcGeneralTest{
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
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
		err := runTestPerUseCaseSynthesis(t, tt, vpcConfigs, uc, tt.mode, synthesisOut)
		require.Equal(t, tt.errPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

// runTestPerUseCase runs the connectivity analysis for the required use case and compares/generates the output
func runTestPerUseCaseSynthesis(t *testing.T,
	tt *vpcGeneralTest,
	cConfigs *vpcmodel.MultipleVPCConfigs,
	uc vpcmodel.OutputUseCase,
	mode testMode,
	outDir string) error {
	if err := initTestFileNames(tt, uc, "", true, outDir); err != nil {
		return err
	}
	og, err := vpcmodel.NewOutputGenerator(cConfigs, false, uc, false,
		nil, vpcmodel.Synthesis, !tt.noLbAbstract)
	if err != nil {
		return err
	}
	actualOutput, err := og.Generate(vpcmodel.Synthesis, tt.actualOutput[uc])
	if err != nil {
		return err
	}
	if err := compareOrRegenerateOutputPerTest(t, mode, actualOutput, synthesisOut, tt, uc); err != nil {
		return err
	}
	return nil
}
