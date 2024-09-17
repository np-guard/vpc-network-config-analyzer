/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"fmt"
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type VpcLintTest struct {
	VpcTestCommon
	Enable        []string
	Disable       []string
	PrintAllLints bool
}

///////////////////////////////////////////////////////////////////////////////////////////
// lint:
//////////////////////////////////////////////////////////////////////////////////////////////

const lintOut = "lint_out"

func (tt *VpcLintTest) TestSingleLint(t *testing.T, rc ResourcesContainer) {
	// all tests in lint mode
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.UseCases = []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints}
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := tt.GetVPCConfigs(t, tt.InputConfig, rc)

	// generate actual output for all use cases specified for this test
	err := tt.runLintTestPerUseCase(t, vpcConfigs.Configs(), lintOut)
	require.Equal(t, tt.ErrPerUseCase[vpcmodel.AllEndpoints], err, "comparing lint actual err to expected err")
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("lint test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}

// runExplainTestPerUseCase executes lint for the required use case and compares/generates the output
func (tt *VpcLintTest) runLintTestPerUseCase(t *testing.T, cConfigs map[string]*vpcmodel.VPCConfig, outDir string) error {
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.initLintTestFileNames(outDir)
	_, actualOutput, _ := linter.LinterExecute(cConfigs, tt.PrintAllLints, tt.Enable, tt.Disable)
	if err := compareOrRegenerateOutputPerTest(t, tt.Mode, actualOutput, lintOut, tt.Name, tt.ExpectedOutput,
		vpcmodel.AllEndpoints); err != nil {
		return err
	}
	return nil
}

func (tt *VpcLintTest) initLintTestFileNames(testDir string) {
	expectedFileName, actualFileName := getLintTestFileName(tt.Name)
	// output use case is not significant here, but being used so that lint test can rely on existing mechanism
	tt.ActualOutput[vpcmodel.AllEndpoints] = filepath.Join(getTestsDirOut(testDir), actualFileName)
	tt.ExpectedOutput[vpcmodel.AllEndpoints] = filepath.Join(getTestsDirOut(testDir), expectedFileName)
}

// getLintTestFileName returns expected file name and actual file name, for the relevant use case
func getLintTestFileName(testName string) (expectedFileName, actualFileName string) {
	res := testName + "_Lint"
	expectedFileName = res
	actualFileName = ActualOutFilePrefix + res
	return expectedFileName, actualFileName
}
