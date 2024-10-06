/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testfunc

import (
	"testing"

	"github.com/np-guard/models/pkg/netp"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
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

func (tt *VpcExplainTest) TestSingleExplain(t *testing.T, mode testMode, rc commonvpc.ResourcesContainer, testName string) {
	tt.Name = testName
	tt.setMode(mode)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.DetailExplain)
	tt.UseCases = []vpcmodel.OutputUseCase{vpcmodel.Explain}
	tt.Format = vpcmodel.Text
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runSingleCommonTest(t, explainOut, rc, false, false, explanationArgs, false)
	})
}
