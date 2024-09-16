/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type VpcAnalysisTest struct {
	VpcTestCommon
}

func (tt *VpcAnalysisTest) TestReportSingleTest(t *testing.T, mode testMode, rc ResourcesContainer, testDir, testName string) {
	tt.Name = testName
	tt.setMode(mode)
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runReportSingleTest(t, testDir, rc)
	})
}

func (tt *VpcAnalysisTest) runReportSingleTest(t *testing.T, testDir string, rc ResourcesContainer) {
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := tt.GetVPCConfigs(t, tt.InputConfig, rc)

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.UseCases {
		err := tt.RunTestPerUseCase(t, vpcConfigs, uc, tt.Mode, testDir, nil)
		require.Equal(t, tt.ErrPerUseCase[uc], err, "comparing report's actual err to expected err")
	}
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}
