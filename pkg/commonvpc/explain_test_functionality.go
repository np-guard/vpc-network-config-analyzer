/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type VpcExplainTest struct {
	VpcTestCommon
	ESrc          string
	EDst          string
	EProtocol     netp.ProtocolString
	ESrcMinPort   int64
	ESrcMaxPort   int64
	EDstMinPort   int64
	EDstMaxPort   int64
	DetailExplain bool
}

///////////////////////////////////////////////////////////////////////////////////////////
// explainability:
//////////////////////////////////////////////////////////////////////////////////////////////

const explainOut = "explain_out"

func (tt *VpcExplainTest) TestSingleExplain(t *testing.T, mode testMode, rc ResourcesContainer, testName string) {
	tt.Name = testName
	tt.setMode(mode)
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runExplainSingleTest(t, rc)
	})
}

func (tt *VpcExplainTest) runExplainSingleTest(t *testing.T, rc ResourcesContainer) {
	// all tests in explain mode
	tt.UseCases = []vpcmodel.OutputUseCase{vpcmodel.Explain}
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := tt.GetVPCConfigs(t, tt.InputConfig, rc)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.DetailExplain)

	// generate actual output for all use cases specified for this test
	err := tt.RunTestPerUseCase(t, vpcConfigs, vpcmodel.Explain, tt.Mode, explainOut, explanationArgs)
	require.Equal(t, tt.ErrPerUseCase[vpcmodel.Explain], err, "comparing explain actual err to expected err")
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("explain test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}
