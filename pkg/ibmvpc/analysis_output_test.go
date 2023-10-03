package ibmvpc

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

type testMode int

const (
	outputComparison testMode = iota // compare actual output to expected output
	outputGeneration                 // generate expected output
	outputIgnore                     // ignore expected output
)

type vpcGeneralTest struct {
	name           string                            // test name
	inputConfig    string                            // name (relative path) of input config file (json)
	expectedOutput map[vpcmodel.OutputUseCase]string // expected output file path
	actualOutput   map[vpcmodel.OutputUseCase]string // actual output file path
	useCases       []vpcmodel.OutputUseCase          // the list of output use cases to test
	errPerUseCase  map[vpcmodel.OutputUseCase]error
	mode           testMode
	grouping       bool
	format         vpcmodel.OutFormat
}

const (
	actualOutFilePrefix            = "out_"
	inputFilePrefix                = "input_"
	suffixOutFileWithGrouping      = "_with_grouping"
	suffixOutFileDebugSubnet       = "_analysisPerSubnetSeparately"
	suffixOutFileSubnetsLevel      = "subnetsBased_withPGW"
	suffixOutFileSubnetsLevelNoPGW = "subnetsBased_withoutPGW"
	txtOutSuffix                   = ".txt"
	debugOutSuffix                 = "_debug.txt"
	mdOutSuffix                    = ".md"
	jsonOutSuffix                  = ".json"
	drawioOutSuffix                = ".drawio"
	archDrawioOutSuffix            = "_arch.drawio"
)

// getTestFileName returns expected file name and actual file name, for the relevant use case
func getTestFileName(testName string, uc vpcmodel.OutputUseCase, grouping bool, format vpcmodel.OutFormat) (
	expectedFileName, actualFileName string,
	err error) {
	var res string
	switch uc {
	case vpcmodel.AllEndpoints:
		res = testName
		if grouping {
			res += suffixOutFileWithGrouping
		}
	case vpcmodel.SingleSubnet:
		res = testName + suffixOutFileDebugSubnet
	case vpcmodel.AllSubnets:
		res = testName + suffixOutFileSubnetsLevel
	case vpcmodel.AllSubnetsNoPGW:
		res = testName + suffixOutFileSubnetsLevelNoPGW
	}
	switch format {
	case vpcmodel.Text:
		res += txtOutSuffix
	case vpcmodel.Debug:
		res += debugOutSuffix
	case vpcmodel.MD:
		res += mdOutSuffix
	case vpcmodel.JSON:
		res += jsonOutSuffix
	case vpcmodel.DRAWIO:
		res += drawioOutSuffix
	case vpcmodel.ARCHDRAWIO:
		res += archDrawioOutSuffix
	default:
		return "", "", errors.New("unexpected out format")
	}

	expectedFileName = res
	actualFileName = actualOutFilePrefix + res
	return expectedFileName, actualFileName, nil
}

// initTest: based on the test name, set the input config file name, and the output
// files names (actual and expected), per use case
func (tt *vpcGeneralTest) initTest() {
	tt.inputConfig = inputFilePrefix + tt.name + ".json"
	tt.expectedOutput = map[vpcmodel.OutputUseCase]string{}
	tt.actualOutput = map[vpcmodel.OutputUseCase]string{}

	// init field of expected errs
	if tt.errPerUseCase == nil {
		tt.errPerUseCase = map[vpcmodel.OutputUseCase]error{}
	}
	for _, uc := range tt.useCases {
		if _, ok := tt.errPerUseCase[uc]; !ok {
			tt.errPerUseCase[uc] = nil // if errs not specified, by default not expecting errs
		}
	}
}


var tests = []*vpcGeneralTest{
	{
	name:     "acl_testing3",
	useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
	grouping: true,
	format:   vpcmodel.DRAWIO,
},
}

var tests2 = []*vpcGeneralTest{
	{
		name:     "acl_testing5",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	{
		name:     "acl_testing5_old",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	// batch1: cover all use-cases, with text output format , no grouping
	{
		name: "acl_testing3",
		// TODO: currently skipping uc3 since it is not supported with partial subnet connectivity
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet},
		format:   vpcmodel.Text,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},

	// batch2: only vsi-level use-case, with grouping , text format
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.Text,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.Text,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.Text,
	},

	//batch3: only vsi-level use-case, no grouping, with debug / md  output formats
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.MD,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.MD,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.MD,
	},
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.Debug,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.Debug,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.Debug,
	},
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.DRAWIO,
	},

	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.ARCHDRAWIO,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.ARCHDRAWIO,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.ARCHDRAWIO,
	},
	{
		name:     "sg_testing1_new_grouping",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping: true,
		format:   vpcmodel.Text,
	},
	// iks-nodes example
	{
		name:     "iks_config_object",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.Text,
	},
	// json example
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:   vpcmodel.JSON,
	},
}

var formatsAvoidComparison = map[vpcmodel.OutFormat]bool{vpcmodel.ARCHDRAWIO: true, vpcmodel.DRAWIO: true, vpcmodel.JSON: true}

// uncomment the function below to run for updating the expected output
/* var formatsAvoidOutputGeneration = map[vpcmodel.OutFormat]bool{vpcmodel.ARCHDRAWIO: true, vpcmodel.DRAWIO: true}
func TestAllWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		// todo - remove the following if when drawio is stable
		if formatsAvoidOutputGeneration[tt.format] {
			tt.mode = outputIgnore
		} else {
			tt.mode = outputGeneration
		}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}*/

func TestAllWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		// todo - remove the following if when drawio is stable
		if formatsAvoidComparison[tt.format] {
			tt.mode = outputIgnore
		} else {
			tt.mode = outputComparison
		}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}

// TODO: this test function should be removed after supporting this analysis
func TestUnsupportedAnalysis(t *testing.T) {
	test := &vpcGeneralTest{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
		errPerUseCase: map[vpcmodel.OutputUseCase]error{
			vpcmodel.AllSubnets: errors.New("unsupported connectivity map with partial subnet ranges per connectivity result"),
		},
	}
	test.mode = outputGeneration
	test.runTest(t)
}

func (tt *vpcGeneralTest) runTest(t *testing.T) {
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get CloudConfig obj from parsing + analyzing input config file
	cloudConfig := getCloudConfig(t, tt)

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.useCases {
		err := runTestPerUseCase(t, tt, cloudConfig, uc, tt.mode)
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
func runTestPerUseCase(t *testing.T, tt *vpcGeneralTest, c *vpcmodel.CloudConfig, uc vpcmodel.OutputUseCase, mode testMode) error {
	expectedFileName, actualFileName, err := getTestFileName(tt.name, uc, tt.grouping, tt.format)
	if err != nil {
		return err
	}
	tt.actualOutput[uc] = filepath.Join(getTestsDir(), actualFileName)
	tt.expectedOutput[uc] = filepath.Join(getTestsDir(), expectedFileName)
	var actualOutput string

	og, err := vpcmodel.NewOutputGenerator(c, tt.grouping, uc, tt.format == vpcmodel.ARCHDRAWIO)
	if err != nil {
		return err
	}
	actualOutput, err = og.Generate(tt.format, tt.actualOutput[uc])
	if err != nil {
		return err
	}

	if mode == outputComparison {
		expectedOutput, err := os.ReadFile(tt.expectedOutput[uc])
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		expectedOutputStr := string(expectedOutput)
		if cleanStr(expectedOutputStr) != cleanStr(actualOutput) {
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

// comparison should be insensitive to line comparators; cleaning strings from line comparators
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "/n", ""), "\r", "")
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
