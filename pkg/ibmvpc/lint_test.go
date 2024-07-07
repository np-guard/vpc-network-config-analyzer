/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const lintOut = "lint_out"

var lintTests = []*vpcGeneralTest{}

func TestAllLint(t *testing.T) {
	// lintTests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runExplainTest(t)
		})
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing

//func TestAllLintWithGeneration(t *testing.T) {
//	// tests is the list of tests to run
//	for testIdx := range lintTests {
//		tt := lintTests[testIdx]
//		tt.mode = outputGeneration
//		t.Run(tt.name, func(t *testing.T) {
//			t.Parallel()
//			tt.runExplainTest(t)
//		})
//	}
//	fmt.Println("done")
//}

func (tt *vpcGeneralTest) runLintTest(t *testing.T) {
	// all tests in lint mode
	tt.useCases = []vpcmodel.OutputUseCase{vpcmodel.Explain}
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := getVPCConfigs(t, tt, true)

	// generate actual output for all use cases specified for this test
	err := runExplainTestPerUseCase(t, tt, vpcConfigs, explainOut)
	require.Equal(t, tt.errPerUseCase[vpcmodel.Explain], err, "comparing actual err to expected err")
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

// runExplainTestPerUseCase executes lint for the required use case and compares/generates the output
func runExplainTestPerUseCase(t *testing.T,
	tt *vpcGeneralTest,
	cConfigs *vpcmodel.MultipleVPCConfigs,
	outDir string) error {
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	if err := initTestFileNames(tt, vpcmodel.AllEndpoints, "", true, outDir); err != nil {
		return err
	}
	// todo: support multiCPV config
	var myConfig *vpcmodel.VPCConfig
	for _, config := range cConfigs.Configs() {
		myConfig = config
		continue // todo: tmp
	}
	_, actualOutput := linter.LinterExecute(myConfig)
	if err := compareOrRegenerateOutputPerTest(t, outputComparison, actualOutput, tt, vpcmodel.AllEndpoints); err != nil {
		return err
	}
	return nil
}
