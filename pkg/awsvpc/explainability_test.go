/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const explainOut = "explain_out"

// getConfigs returns  *vpcmodel.MultipleVPCConfigs obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) *vpcmodel.MultipleVPCConfigs {
	inputConfigFile := filepath.Join(commonvpc.GetTestsDirInput(),
		commonvpc.InputFilePrefix+fileName+commonvpc.JSONOutSuffix)
	rc := AWSresourcesContainer{}
	err := rc.ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := rc.VPCConfigsFromResources("", "", nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return vpcConfigs
}

var explainTests = []*commonvpc.VpcGeneralTest{
	{
		Name:          "ip_to_ip",
		InputConfig:   "aws_sg_1",
		ESrc:          "10.240.40.184",
		EDst:          "10.240.20.141",
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
			runExplainTest(tt, t)
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
			runExplainTest(tt, t)
		})
	}
	fmt.Println("done")
}*/

func runExplainTest(tt *commonvpc.VpcGeneralTest, t *testing.T) {
	// all tests in explain mode
	tt.UseCases = []vpcmodel.OutputUseCase{vpcmodel.Explain}
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	rc := &AWSresourcesContainer{}
	vpcConfigs := commonvpc.GetVPCConfigs(t, tt, true, rc)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.DetailExplain)

	// generate actual output for all use cases specified for this test
	err := commonvpc.RunTestPerUseCase(t, tt, vpcConfigs, vpcmodel.Explain, tt.Mode, explainOut, explanationArgs)
	require.Equal(t, tt.ErrPerUseCase[vpcmodel.Explain], err, "comparing actual err to expected err")
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}

