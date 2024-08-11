/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const analysisOut = "analysis_out"

var tests = []*commonvpc.VpcGeneralTest{
	{
		InputConfig: "basic_config_with_sg",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "aws_sg_1",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "aws_sg_1",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig: "aws_acl_1",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
}

var formatsAvoidComparison = map[vpcmodel.OutFormat]bool{
	vpcmodel.DRAWIO:     true,
	vpcmodel.ARCHDRAWIO: true,
	vpcmodel.SVG:        true,
	vpcmodel.ARCHSVG:    true,
	vpcmodel.HTML:       true,
	vpcmodel.ARCHHTML:   true,
}

// uncomment the function below to run for updating the expected output
/*
var formatsAvoidOutputGeneration = formatsAvoidComparison

func TestAllWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		// todo - remove the following if when drawio is stable
		if formatsAvoidOutputGeneration[tt.Format] {
			tt.mode = commonvpc.OutputIgnore
		} else {
			tt.mode = commonvpc.OutputGeneration
		}
		tt.name = tt.InputConfig
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc := &IBMresourcesContainer{}
			tt.RunTest(t, analysisOut, rc)
		})
	}
	fmt.Println("done")
}
*/
func TestAllWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		// todo - remove the following if when drawio is stable
		if formatsAvoidComparison[tt.Format] {
			tt.Mode = commonvpc.OutputIgnore
		} else {
			tt.Mode = commonvpc.OutputComparison
		}
		tt.Name = tt.InputConfig
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &AWSresourcesContainer{}
			tt.RunTest(t, analysisOut, rc)
		})
	}
	fmt.Println("done")
}
