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

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const lintOut = "lint_out"

var lintTests = []*commonvpc.VpcGeneralTest{
	{
		Name:        "basic_acl3",
		InputConfig: "acl_testing3",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "acl3_shadowed_rules",
		InputConfig: "acl_testing3_with_redundant_rules",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "acl3_shadowed_rules_other_lints_disabled",
		InputConfig: "acl_testing3_with_redundant_rules",
		Disable: []string{"nacl-split-subnet", "subnet-cidr-overlap", "nacl-unattached",
			"sg-unattached", "sg-rule-cidr-out-of-range", "nacl-rule-cidr-out-of-range",
			"tcp-response-blocked", "sg-rule-implied"},
	},
	{
		Name:        "acl3_3rd",
		InputConfig: "acl_testing3_3rd",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "basic_sg1",
		InputConfig: "sg_testing1_new",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "multivpc",
		InputConfig: "tgw_larger_example",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:          "multivpc_print_all",
		InputConfig:   "tgw_larger_example",
		PrintAllLints: true,
		Enable:        []string{"sg-split-subnet"},
	},
	{
		Name:        "multivpc_partly_overlap",
		InputConfig: "tgw_larger_example_partly_overlap",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "PartialTCPRespond",
		InputConfig: "sg_testing1_new_respond_partly",
		Enable:      []string{"sg-split-subnet"},
	},
}

func TestAllLint(t *testing.T) {
	// lintTests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.Mode = commonvpc.OutputComparison
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			runLintTest(tt, t)
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
		tt.Mode = commonvpc.OutputGeneration
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			runLintTest(tt, t)
		})
	}
	fmt.Println("done")
}
*/
func runLintTest(tt *commonvpc.VpcGeneralTest, t *testing.T) {
	// all tests in lint mode
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.UseCases = []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints}
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	rc := &IBMresourcesContainer{}
	vpcConfigs := commonvpc.GetVPCConfigs(t, tt, true, rc)

	// generate actual output for all use cases specified for this test
	err := runLintTestPerUseCase(t, tt, vpcConfigs.Configs(), lintOut)
	require.Equal(t, tt.ErrPerUseCase[vpcmodel.AllEndpoints], err, "comparing actual err to expected err")
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}

// runExplainTestPerUseCase executes lint for the required use case and compares/generates the output
func runLintTestPerUseCase(t *testing.T,
	tt *commonvpc.VpcGeneralTest,
	cConfigs map[string]*vpcmodel.VPCConfig,
	outDir string) error {
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	initLintTestFileNames(tt, outDir)
	_, actualOutput, _ := linter.LinterExecute(cConfigs, tt.PrintAllLints, tt.Enable, tt.Disable)
	if err := commonvpc.CompareOrRegenerateOutputPerTest(t, tt.Mode, actualOutput, lintOut, tt, vpcmodel.AllEndpoints); err != nil {
		return err
	}
	return nil
}

func initLintTestFileNames(tt *commonvpc.VpcGeneralTest, testDir string) {
	expectedFileName, actualFileName := getLintTestFileName(tt.Name)
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.ActualOutput[vpcmodel.AllEndpoints] = filepath.Join(commonvpc.GetTestsDirOut(testDir), actualFileName)
	tt.ExpectedOutput[vpcmodel.AllEndpoints] = filepath.Join(commonvpc.GetTestsDirOut(testDir), expectedFileName)
}

// getLintTestFileName returns expected file name and actual file name, for the relevant use case
func getLintTestFileName(testName string) (expectedFileName, actualFileName string) {
	res := testName + "_Lint"
	expectedFileName = res
	actualFileName = commonvpc.ActualOutFilePrefix + res
	return expectedFileName, actualFileName
}
