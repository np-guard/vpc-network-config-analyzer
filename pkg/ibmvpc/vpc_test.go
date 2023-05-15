package ibmvpc

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type outputUseCase int

const (
	uc1 outputUseCase = iota
	uc2
	uc3
)

type vpcGeneralTest struct {
	name           string                   // test name
	inputConfig    string                   // name (relative path) of input config file (json)
	expectedOutput map[outputUseCase]string // expected output file path
	actualOutput   map[outputUseCase]string // actual output file path
}

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

func TestGenOutput(t *testing.T) {
	generateOutput(t, demoWithInstances, "demoWithInstances")
}

// genetate output for usecase #1
//not a testing function, only to run and generate output
func generateOutput(t *testing.T, inputConfig []byte, inputName string) {
	tt := &vpcTest{name: inputName, inputResourcesJSON: inputConfig}
	cloudConfig, vpcConn := runTest(t, tt)
	o := vpcmodel.NewOutputGenerator(cloudConfig, vpcConn)
	setTestOutputFiles(o, tt)
	getTestOutput(tt, t, o)
}

func TestGenOutputUC3(t *testing.T) {
	generateOutputSubnetsBased(t, demoWithInstances, "demoWithInstances", true)
}

func TestGenOutputUC2(t *testing.T) {
	generateOutputPerSingleSubnet(t, demoWithInstances, "demoWithInstances")
}

func generateOutputPerSingleSubnet(t *testing.T, inputConfig []byte, inputName string) {
	rc, err := ParseResources(inputConfig)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	res := ""
	for _, r := range cloudConfig.FilterResources {
		if naclLayer, ok := r.(*NaclLayer); ok {
			for _, nacl := range naclLayer.naclList {
				for subnet := range nacl.subnets {
					res += nacl.GeneralConnectivityPerSubnet(subnet)
				}
			}
		}
	}
	outName := "out_" + inputName + "_analysisPerSubnetSeparately.txt"
	vpcmodel.WriteToFile(res, filepath.Join(getTestsDir(), outName))
}

func generateOutputSubnetsBased(t *testing.T, inputConfig []byte, inputName string, includePGW bool) {
	rc, err := ParseResources(inputConfig)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConn, err := cloudConfig.GetSubnetsConnectivity(includePGW)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	actualOutput := vpcConn.String()
	fmt.Println(actualOutput)
	outName := "out_" + inputName + "subnetsBased.txt"
	vpcmodel.WriteToFile(actualOutput, filepath.Join(getTestsDir(), outName))

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
		override := false
		if override {
			overrideExpectedOutput(test, t, o)
		}
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
	mdFile := filePrfix + ".md"
	o.SetOutputFile(txtFile, vpcmodel.Text)
	o.SetOutputFile(jsonFile, vpcmodel.JSON)
	o.SetOutputFile(mdFile, vpcmodel.MD)
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
	if _, err := o.Generate(vpcmodel.MD); err != nil {
		t.Fatalf("err: %s", err)
	}
	test.actualOutput = textOutput
}

func overrideExpectedOutput(test *vpcTest, t *testing.T, o *vpcmodel.OutputGenerator) {
	o.SetOutputFile(filepath.Join(getTestsDir(), test.name+".txt"), vpcmodel.Text)
	if _, err := o.Generate(vpcmodel.Text); err != nil {
		t.Fatalf("err: %s", err)
	}
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

//go:embed examples/demo/demo1.json
var demoInput []byte

//go:embed examples/demo/demo2.json
var demo2Input []byte

//go:embed examples/demo/demo_with_instances.json
var demoWithInstances []byte

func TestDemo(t *testing.T) {
	rc, err := ParseResources(demoInput)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConn := cloudConfig.GetVPCNetworkConnectivity()
	actualOutput := vpcConn.String()
	fmt.Printf("%s", actualOutput)
	for _, r := range cloudConfig.FilterResources {
		if naclLayer, ok := r.(*NaclLayer); ok {
			for _, nacl := range naclLayer.naclList {
				for subnet := range nacl.subnets {
					//fmt.Println(nacl.GeneralConnectivityPerSubnet(subnet))
					nacl.GeneralConnectivityPerSubnet(subnet)
				}
			}
		}
	}
	fmt.Println("===============================================")
	test := &vpcTest{name: "demo2", inputResourcesJSON: demo2Input}
	cloudConfig2, vpcConn2 := runTest(t, test)
	// generate output
	o := vpcmodel.NewOutputGenerator(cloudConfig2, vpcConn2)
	setTestOutputFiles(o, test)
	getTestOutput(test, t, o)
}

func TestVPCsubnetConnectivityWithPGW(t *testing.T) {
	rc, err := ParseResources(demo2Input)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConn, err := cloudConfig.GetSubnetsConnectivity(true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	actualOutput := vpcConn.String()
	fmt.Println(actualOutput)
	vpcmodel.WriteToFile(actualOutput, filepath.Join(getTestsDir(), "out_demo_subnets_connectivity_with_pgw.txt"))
	fmt.Println("done")
}

func TestVPCsubnetConnectivityWithoutPGW(t *testing.T) {
	rc, err := ParseResources(demo2Input)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConn, err := cloudConfig.GetSubnetsConnectivity(false)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	actualOutput := vpcConn.String()
	fmt.Println(actualOutput)
	vpcmodel.WriteToFile(actualOutput, filepath.Join(getTestsDir(), "out_demo_subnets_connectivity_without_pgw.txt"))
	fmt.Println("done")
}
