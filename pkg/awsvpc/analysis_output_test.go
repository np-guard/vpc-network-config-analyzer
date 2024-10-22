/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc/testfunc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const analysisOut = "analysis_out"

var tests = []*testfunc.VpcAnalysisTest{
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "basic_config_with_sg",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "aws_sg_1",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "aws_sg_1",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "aws_acl_1",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "aws_mixed",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "aws_mixed",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
	},
}

// uncomment the function below to run for updating the expected output

/*func TestReportWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		tt.TestAnalysisSingleTest(t, testfunc.OutputGeneration, NewAWSresourcesContainer(), analysisOut, tt.InputConfig)
	}
	fmt.Println("done")
}*/

func TestReportWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		tt.TestAnalysisSingleTest(t, testfunc.OutputComparison, NewAWSresourcesContainer(), analysisOut, tt.InputConfig)
	}
	fmt.Println("done")
}
