/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

var lintTests = []*commonvpc.VpcGeneralTest{
	{
		Name:        "aws_acl1",
		InputConfig: "aws_acl_1",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "aws_mixed",
		InputConfig: "aws_mixed",
		Enable:      []string{"sg-split-subnet"},
	},
	{
		Name:        "aws_sg_1",
		InputConfig: "aws_sg_1",
		Enable:      []string{"sg-split-subnet"},
		Disable: []string{"nacl-split-subnet", "subnet-cidr-overlap", "nacl-unattached",
			"sg-unattached", "sg-rule-cidr-out-of-range", "nacl-rule-cidr-out-of-range",
			"tcp-response-blocked", "sg-rule-implied", "nacl-rule-shadowed"},
	},
}

func TestAllLint(t *testing.T) {
	// lintTests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.Mode = commonvpc.OutputComparison
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &AWSresourcesContainer{}
			commonvpc.RunLintTest(tt, t, rc)
		})
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing

/*func TestAllLintWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range lintTests {
		tt := lintTests[testIdx]
		tt.Mode = commonvpc.OutputGeneration
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			rc := &AWSresourcesContainer{}
			commonvpc.RunLintTest(tt, t, rc)
		})
	}
	fmt.Println("done")
}*/
