package ibmvpc

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

//go:embed examples/sg_testing1_new.json
var sg1Input []byte

//go:embed examples/sg_testing1.txt
var sg1Output []byte

//go:embed examples/acl_testing3.json
var acl3Input []byte

//go:embed examples/acl_testing3.txt
var acl3Output []byte

type vpcTest struct {
	name               string
	inputResourcesJSON []byte
	expectedOutputText []byte // expected text output
	actualOutput       string // actual text output
}

func TestWithParsing(t *testing.T) {
	tests := []*vpcTest{
		{
			name:               "acl_testing3",
			inputResourcesJSON: acl3Input,
			expectedOutputText: acl3Output,
		},
		{
			name:               "sg_testing1",
			inputResourcesJSON: sg1Input,
			expectedOutputText: sg1Output,
		},
	}
	for _, test := range tests {
		cloudConfig, vpcConn := runTest(t, test)
		// generate output
		o := vpcmodel.NewOutputGenerator(cloudConfig, vpcConn)
		setTestOutputFiles(o, test)
		getTestOutput(test, t, o)
		// compare output to expected
		checkTestOutput(test, t)
	}
}

func runTest(t *testing.T, test *vpcTest) (*vpcmodel.CloudConfig, *vpcmodel.VPCConnectivity) {
	rc, err := ParseResources(test.inputResourcesJSON)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConn := cloudConfig.GetVPCNetworkConnectivity()
	return cloudConfig, vpcConn
}

func setTestOutputFiles(o *vpcmodel.OutputGenerator, t *vpcTest) {
	filePrfix := filepath.Join(getTestsDir(), "out_"+t.name)
	txtFile := filePrfix + ".txt"
	jsonFile := filePrfix + ".json"
	o.SetOutputFile(txtFile, vpcmodel.Text)
	o.SetOutputFile(jsonFile, vpcmodel.JSON)
}

func getTestOutput(test *vpcTest, t *testing.T, o *vpcmodel.OutputGenerator) {
	var textOutput string
	var err error
	if textOutput, err = o.Generate(vpcmodel.Text); err != nil {
		t.Fatalf("err: %s", err)
	}
	if _, err := o.Generate(vpcmodel.JSON); err != nil {
		t.Fatalf("err: %s", err)
	}
	test.actualOutput = textOutput
}

func checkTestOutput(test *vpcTest, t *testing.T) {
	if test.actualOutput != string(test.expectedOutputText) {
		fmt.Printf("%s", test.actualOutput)
		t.Fatalf("TestWithParsing unexpected output result : %s", test.name)
	}
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, "examples")
}
