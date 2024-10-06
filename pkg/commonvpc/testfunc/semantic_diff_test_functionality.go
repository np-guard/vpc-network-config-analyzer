/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testfunc

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

const secJSONOutSuffix = "_2nd.json"

type VpcDiffTest struct {
	VpcTestCommon
	InputConfig2nd string // 2nd input file for diff
}

func (tt *VpcDiffTest) TestDiffSingle(t *testing.T, mode testMode, rc commonvpc.ResourcesContainer, testDir, testName string) {
	tt.Name = testName
	tt.setMode(mode)
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runDiffSingleTest(t, testDir, rc)
	})
}

func (tt *VpcDiffTest) runDiffSingleTest(t *testing.T, testDir string, rc commonvpc.ResourcesContainer) {
	// init test - set the input/output file names according to test name
	tt.InputConfig2nd = InputFilePrefix + tt.InputConfig + secJSONOutSuffix
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := tt.getVPCConfigs(t, tt.InputConfig, rc)
	vpcConfigs2nd := tt.getVPCConfigs(t, tt.InputConfig2nd, rc)
	vpcConfigs.SetConfigsToCompare(vpcConfigs2nd.Configs())

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.UseCases {
		err := tt.runTestPerUseCase(t, vpcConfigs, uc, tt.Mode, testDir, false, false,
			nil, false)
		require.Equal(t, tt.ErrPerUseCase[uc], err, "comparing diff's actual err to expected err")
	}
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}
