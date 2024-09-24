/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testfunc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"testing"

	_ "embed"
)

type VpcAnalysisTest struct {
	VpcTestCommon
	Grouping     bool
	NoLbAbstract bool
}

func (tt *VpcAnalysisTest) TestAnalysisSingleTest(t *testing.T, mode testMode, rc commonvpc.ResourcesContainer, testDir, testName string) {
	tt.Name = testName
	tt.setMode(mode)
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runSingleCommonTest(t, testDir, rc, tt.Grouping, tt.NoLbAbstract, nil)
	})
}
