/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"testing"

	_ "embed"
)

type VpcAnalysisTest struct {
	VpcTestCommon
}

func (tt *VpcAnalysisTest) TestAnalysisSingleTest(t *testing.T, mode testMode, rc ResourcesContainer, testDir, testName string) {
	tt.Name = testName
	tt.setMode(mode)
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runSingleCommonTest(t, testDir, rc, nil)
	})
}
