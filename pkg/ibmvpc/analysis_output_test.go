package ibmvpc

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

/*
tests for the entire flow:
	- input from config json file
	- output comparison, for the possible output use-cases
	- currently comparing only txt output formats
*/

type outputUseCase int

type testMode int

const (
	uc1  outputUseCase = iota // connectivity between network interfaces and external ip-blocks
	uc2                       // connectivity per single subnet with nacl
	uc3a                      // connectivity between subnets (consider nacl + pgw)
	uc3b                      // connectivity between subnets (consider nacl only)
)

const (
	outputComparison testMode = iota // compare actual output to expected output
	outputGeneration                 // generate expected output
)

type vpcGeneralTest struct {
	name           string                   // test name
	inputConfig    string                   // name (relative path) of input config file (json)
	expectedOutput map[outputUseCase]string // expected output file path
	actualOutput   map[outputUseCase]string // actual output file path
	useCases       []outputUseCase          // the list of output use cases to test
	errPerUseCase  map[outputUseCase]error
}

const (
	actualOutFilePrefix = "out_"
	inputFilePrefix     = "input_"
)

// initTest: based on the test name, set the input config file name, and the output
// files names (actual and expected), per use case
func (tt *vpcGeneralTest) initTest() {
	tt.inputConfig = inputFilePrefix + tt.name + ".json"
	tt.expectedOutput = map[outputUseCase]string{}
	tt.actualOutput = map[outputUseCase]string{}

	// init field of expected errs
	if tt.errPerUseCase == nil {
		tt.errPerUseCase = map[outputUseCase]error{}
	}
	for _, uc := range tt.useCases {
		if _, ok := tt.errPerUseCase[uc]; !ok {
			tt.errPerUseCase[uc] = nil // if errs not specified, by default not expecting errs
		}
	}
}

// uncomment the function below to run for updating the expected output
/*func TestAllUpdateExpectedOutput(t *testing.T) {
	testAll(t, outputGeneration)
}*/

// TestAllCompareToExpectedOutput runs all output comparison tests (all specified use-cases, txt formats compared)
func TestAllCompareToExpectedOutput(t *testing.T) {
	testAll(t, outputComparison)
}

// TODO: this test function should be removed after supporting this analysis
func TestUnsupportedAnalysis(t *testing.T) {
	test := &vpcGeneralTest{
		name:     "acl_testing3",
		useCases: []outputUseCase{uc3a},
		errPerUseCase: map[outputUseCase]error{
			uc3a: errors.New("unsupported connectivity map with partial subnet ranges per connectivity result"),
		},
	}
	runTest(t, test, outputGeneration)
}

func testAll(t *testing.T, mode testMode) {
	// tests is the list of tests to run
	tests := []*vpcGeneralTest{
		{
			name: "acl_testing3",
			// TODO: currently skipping uc3 since it is not supported with partial subnet connectivity
			useCases: []outputUseCase{uc1, uc2},
		},
		{
			name:     "sg_testing1_new",
			useCases: []outputUseCase{uc1, uc2, uc3a},
		},
		{
			name:     "demo_with_instances",
			useCases: []outputUseCase{uc1, uc2, uc3a},
		},
	}

	for _, tt := range tests {
		runTest(t, tt, mode)
	}
	fmt.Println("done")
}

func runTest(t *testing.T, tt *vpcGeneralTest, mode testMode) {
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get CloudConfig obj from parsing + analyzing input config file
	cloudConfig := getCloudConfig(t, tt)

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.useCases {
		err := runTestPerUseCase(t, tt, cloudConfig, uc, mode)
		require.Equal(t, tt.errPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

// getCloudConfig returns CloudConfig obj for the input test (config json file)
func getCloudConfig(t *testing.T, tt *vpcGeneralTest) *vpcmodel.CloudConfig {
	inputConfigFile := filepath.Join(getTestsDir(), tt.inputConfig)
	inputConfigContent, err := os.ReadFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	rc, err := ParseResources(inputConfigContent)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	cloudConfig, err := NewCloudConfig(rc)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return cloudConfig
}

// runTestPerUseCase runs the connectivity analysis for the required use case and compares/generates the output
func runTestPerUseCase(t *testing.T, tt *vpcGeneralTest, c *vpcmodel.CloudConfig, uc outputUseCase, mode testMode) error {
	expectedFileName, actualFileName := getTestFileName(tt.name, uc)
	tt.actualOutput[uc] = filepath.Join(getTestsDir(), actualFileName)
	tt.expectedOutput[uc] = filepath.Join(getTestsDir(), expectedFileName)
	var actualOutput string

	switch uc {
	// connectivity between network interfaces and external ip-blocks
	case uc1:
		vpcConn := c.GetVPCNetworkConnectivity()
		// generate output
		o := vpcmodel.NewOutputGenerator(c, vpcConn)
		setTestOutputFiles(o, tt.name)
		actualOutput = getTestOutput(t, o)

	// connectivity per each subnet separately with its attached nacl
	case uc2:
		actualOutput = getConnectivityOutputPerEachSubnetSeparately(c)

	// connectivity between subnets (consider nacl + pgw)
	case uc3a:
		vpcConn, err := c.GetSubnetsConnectivity(true)
		if err != nil {
			return err
		}
		actualOutput = vpcConn.String()

	// connectivity between subnets (consider nacl only)
	case uc3b:
		vpcConn, err := c.GetSubnetsConnectivity(false)
		if err != nil {
			return err
		}
		actualOutput = vpcConn.String()
	}

	if uc != uc1 { // for uc1 func getTestOutput() already writes output to file
		if err := vpcmodel.WriteToFile(actualOutput, tt.actualOutput[uc]); err != nil {
			return err
		}
	}

	if mode == outputComparison {
		expectedOutput, err := os.ReadFile(tt.expectedOutput[uc])
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		expectedOutputStr := string(expectedOutput)
		if expectedOutputStr != actualOutput {
			compareTextualResult(expectedOutputStr, actualOutput)
			t.Fatalf("output mismatch expected-vs-actual on test name: %s, use case: %d", tt.name, uc)
		}
	}

	if mode == outputGeneration {
		// create or override expected output file
		if err := vpcmodel.WriteToFile(actualOutput, tt.expectedOutput[uc]); err != nil {
			return err
		}
	}

	return nil
}

// getConnectivityOutputPerEachSubnetSeparately returns the output of connectivity per single subnet - on all subnets in config
func getConnectivityOutputPerEachSubnetSeparately(c *vpcmodel.CloudConfig) string {
	res := []string{}
	// iterate over all subnets, collect all outputs per subnet connectivity
	for _, r := range c.FilterResources {
		if naclLayer, ok := r.(*NaclLayer); ok {
			for _, nacl := range naclLayer.naclList {
				for subnet := range nacl.subnets {
					res = append(res, nacl.GeneralConnectivityPerSubnet(subnet))
				}
			}
		}
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

// getTestFileName returns expected file name and actual file name, for the relevant use case
func getTestFileName(testName string, uc outputUseCase) (expectedFileName, actualFileName string) {
	var res string
	switch uc {
	case uc1:
		res = testName
	case uc2:
		res = testName + "_analysisPerSubnetSeparately"
	case uc3a:
		res = testName + "subnetsBased_withPGW"
	case uc3b:
		res = testName + "subnetsBased_withoutPGW"
	}
	res += ".txt"
	expectedFileName = res
	actualFileName = actualOutFilePrefix + res
	return expectedFileName, actualFileName
}

// compareTextualResult is called in case of output mismatch, to provide more details on the difference
func compareTextualResult(expected, actual string) {
	var err1, err2 error
	err1 = vpcmodel.WriteToFile(expected, filepath.Join(getTestsDir(), "expected.txt"))
	err2 = vpcmodel.WriteToFile(actual, filepath.Join(getTestsDir(), "actual.txt"))
	if err1 != nil || err2 != nil {
		fmt.Printf("compareTextualResult: error writing actual/expected output to files: %s, %s \n", err1, err2)
	}

	expectedLines := strings.Split(expected, "\n")
	actualLines := strings.Split(actual, "\n")
	if len(expectedLines) != len(actualLines) {
		fmt.Printf("different number of lines: %d of expected, %d of actual", len(expectedLines), len(actualLines))
		return
	}
	for i := range expectedLines {
		if expectedLines[i] != actualLines[i] {
			fmt.Printf("first line of difference: %d\n", i)
			fmt.Printf("expected: %s\n", expectedLines[i])
			fmt.Printf("actual: %s\n", actualLines[i])
			return
		}
	}
}

// getTestsDir returns the path to the dir where test input and output files are located
func getTestsDir() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, "examples")
}

func setTestOutputFiles(o *vpcmodel.OutputGenerator, testName string) {
	filePrefix := filepath.Join(getTestsDir(), actualOutFilePrefix+testName)
	txtFile := filePrefix + ".txt"
	jsonFile := filePrefix + ".json"
	mdFile := filePrefix + ".md"
	o.SetOutputFile(txtFile, vpcmodel.Text)
	o.SetOutputFile(jsonFile, vpcmodel.JSON)
	o.SetOutputFile(mdFile, vpcmodel.MD)
}

// getTestOutput generates test output with md,txt,json formats and returns the txt output string
func getTestOutput(t *testing.T, o *vpcmodel.OutputGenerator) string {
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
	return textOutput
}
