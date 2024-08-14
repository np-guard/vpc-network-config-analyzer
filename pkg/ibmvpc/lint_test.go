/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const lintOut = "lint_out"

var lintTests = []*vpcGeneralTest{
	{
		name:        "basic_acl3",
		inputConfig: "acl_testing3",
		enable:      []string{"sg-split-subnet"},
	},
	{
		name:        "acl3_shadowed_rules",
		inputConfig: "acl_testing3_with_redundant_rules",
		enable:      []string{"sg-split-subnet"},
	},
	{
		name:        "acl3_shadowed_rules_other_lints_disabled",
		inputConfig: "acl_testing3_with_redundant_rules",
		disable: []string{"nacl-split-subnet", "subnet-cidr-overlap", "nacl-unattached",
			"sg-unattached", "sg-rule-cidr-out-of-range", "nacl-rule-cidr-out-of-range",
			"tcp-response-blocked", "sg-rule-implied"},
	},
	{
		name:        "acl3_3rd",
		inputConfig: "acl_testing3_3rd",
		enable:      []string{"sg-split-subnet"},
	},
	{
		name:        "basic_sg1",
		inputConfig: "sg_testing1_new",
		enable:      []string{"sg-split-subnet"},
	},
	{
		name:        "multivpc",
		inputConfig: "tgw_larger_example",
		enable:      []string{"sg-split-subnet"},
	},
	{
		name:        "multivpc_partly_overlap",
		inputConfig: "tgw_larger_example_partly_overlap",
		enable:      []string{"sg-split-subnet"},
	},
	{
		name:        "PartialTCPRespond",
		inputConfig: "sg_testing1_new_respond_partly",
		enable:      []string{"sg-split-subnet"},
	},
}

func TestAllLint(t *testing.T) {
	// lintTests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.mode = outputComparison
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runLintTest(t)
		})
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing
/*
func TestAllLintWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.mode = outputGeneration
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runLintTest(t)
		})
	}
	fmt.Println("done")
}
*/
func (tt *vpcGeneralTest) runLintTest(t *testing.T) {
	// all tests in lint mode
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.useCases = []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints}
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := getVPCConfigs(t, tt, true)

	// generate actual output for all use cases specified for this test
	err := runLintTestPerUseCase(t, tt, vpcConfigs.Configs(), lintOut)
	require.Equal(t, tt.errPerUseCase[vpcmodel.AllEndpoints], err, "comparing actual err to expected err")
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

// runExplainTestPerUseCase executes lint for the required use case and compares/generates the output
func runLintTestPerUseCase(t *testing.T,
	tt *vpcGeneralTest,
	cConfigs map[string]*vpcmodel.VPCConfig,
	outDir string) error {
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	initLintTestFileNames(tt, outDir)
	_, actualOutput, _ := linter.LinterExecute(cConfigs, tt.printAllLints, tt.enable, tt.disable)
	if err := compareOrRegenerateOutputPerTest(t, tt.mode, actualOutput, tt, vpcmodel.AllEndpoints); err != nil {
		return err
	}
	return nil
}

func initLintTestFileNames(tt *vpcGeneralTest, testDir string) {
	expectedFileName, actualFileName := getLintTestFileName(tt.name)
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.actualOutput[vpcmodel.AllEndpoints] = filepath.Join(getTestsDirOut(testDir), actualFileName)
	tt.expectedOutput[vpcmodel.AllEndpoints] = filepath.Join(getTestsDirOut(testDir), expectedFileName)
}

// getLintTestFileName returns expected file name and actual file name, for the relevant use case
func getLintTestFileName(testName string) (expectedFileName, actualFileName string) {
	res := testName + "_Lint"
	expectedFileName = res
	actualFileName = actualOutFilePrefix + res
	return expectedFileName, actualFileName
}
