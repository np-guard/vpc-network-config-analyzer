/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/testfunc"
)

var explainTests = []*testfunc.VpcExplainTest{
	// existing connection between two endpoints of different subnets
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "ip_to_ip",
			InputConfig: "aws_sg_1",
		},
		ESrc:          "10.240.40.217",
		EDst:          "10.240.20.43",
		DetailExplain: true,
	},
	// non-existing connection between two endpoints of different subnets due to one of the nacls
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "nacl_blocking",
			InputConfig: "aws_mixed",
		},
		ESrc:          "10.240.2.28",
		EDst:          "10.240.32.122",
		DetailExplain: true,
	},
	// existing sub-connection between two endpoints of the same subnet
	// todo: https://github.com/np-guard/vpc-network-config-analyzer/issues/859
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "same_subnet_partial_connection",
			InputConfig: "aws_mixed",
		},
		ESrc:          "10.240.32.122",
		EDst:          "10.240.32.91",
		DetailExplain: true,
	},
	// no connection between two endpoints of the same subnet
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "subnet_to_subnet",
			InputConfig: "aws_mixed",
		},
		ESrc:          "private2",
		EDst:          "private1",
		DetailExplain: true,
	},
	// connection to the public internet blocked by sg and private subnet
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "to_external_private_subnet",
			InputConfig: "aws_sg_1",
		},
		ESrc:          "10.240.20.245",
		EDst:          "161.26.0.0",
		DetailExplain: true,
	},
	// existing connection to the public internet
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "to_external_public_subnet",
			InputConfig: "aws_sg_1",
		},
		ESrc:          "10.240.10.42",
		EDst:          "161.26.0.0",
		DetailExplain: true,
	},
	// existing connection from the public internet
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "from_external_public_subnet",
			InputConfig: "aws_mixed",
		},
		ESrc:          "147.235.0.0/16",
		EDst:          "10.240.0.96",
		DetailExplain: true,
	},
	// connection to the public internet blocked only by private subnet
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			Name:        "to_external_blocked_only_private_subnet",
			InputConfig: "aws_sg_1_allow_sg_private",
		},
		ESrc:          "10.240.20.245",
		EDst:          "161.26.0.0",
		DetailExplain: true,
	},
}

func TestExplainWithComparsion(t *testing.T) {
	// explainTests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		tt.TestSingleExplain(t, testfunc.OutputComparison, &AWSresourcesContainer{}, tt.Name)
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing

/*func TestExplainWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		tt.TestSingleExplain(t, commonvpc.OutputGeneration, &AWSresourcesContainer{}, tt.Name)
	}
	fmt.Println("done")
}*/
