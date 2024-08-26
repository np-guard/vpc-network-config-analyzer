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

var explainTests = []*commonvpc.VpcGeneralTest{
	{
		Name:          "ip_to_ip",
		InputConfig:   "aws_sg_1",
		ESrc:          "10.240.40.217",
		EDst:          "10.240.20.43",
		Format:        vpcmodel.Text,
		DetailExplain: true,
	},
	{
		Name:          "to_external_private_subnet",
		InputConfig:   "aws_sg_1",
		ESrc:          "10.240.20.245",
		EDst:          "161.26.0.0",
		Format:        vpcmodel.Text,
		DetailExplain: true,
	},
}

func TestAll(t *testing.T) {
	// explainTests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &AWSresourcesContainer{}
			commonvpc.RunExplainTest(tt, t, rc)
		})
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing
/*
func TestAllWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		tt.Mode = commonvpc.OutputGeneration
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &AWSresourcesContainer{}
			commonvpc.RunExplainTest(tt, t,rc)
		})
	}
	fmt.Println("done")
}*/
