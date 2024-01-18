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
	inputConfig2nd string                            // 2nd input file for diff
	expectedOutput map[vpcmodel.OutputUseCase]string // expected output file path
	actualOutput   map[vpcmodel.OutputUseCase]string // actual output file path
	useCases       []vpcmodel.OutputUseCase          // the list of output use cases to test
	errPerUseCase  map[vpcmodel.OutputUseCase]error
	mode           testMode
	grouping       bool
	format         vpcmodel.OutFormat
	vpc            string
}

const (
	actualOutFilePrefix            = "out_"
	inputFilePrefix                = "input_"
	suffixOutFileWithGrouping      = "_with_grouping"
	suffixOutFileDebugSubnet       = "_analysisPerSubnetSeparately"
	suffixOutFileSubnetsLevel      = "subnetsBased_withPGW"
	suffixOutFileSubnetsLevelNoPGW = "subnetsBased_withoutPGW"
	suffixOutFileDiffSubnets       = "subnetsDiff"
	suffixOutFileDiffEndpoints     = "endpointsDiff"
	txtOutSuffix                   = ".txt"
	debugOutSuffix                 = "_debug.txt"
	mdOutSuffix                    = ".md"
	jsonOutSuffix                  = ".json"
	drawioOutSuffix                = ".drawio"
	archDrawioOutSuffix            = "_arch.drawio"
)

// getTestFileName returns expected file name and actual file name, for the relevant use case
func getTestFileName(testName string,
	uc vpcmodel.OutputUseCase,
	grouping bool,
	format vpcmodel.OutFormat,
	configName string,
	allVPCs bool) (
	expectedFileName,
	actualFileName string,
	err error) {
	var res string

	// if there are more than one vpc in the config, split to a file per one vpc analysis
	baseName := testName
	if allVPCs {
		baseName += "_all_vpcs_"
	} else {
		baseName += "_" + configName
	}

	switch uc {
	case vpcmodel.AllEndpoints:
		res = baseName
	case vpcmodel.SingleSubnet:
		res = baseName + suffixOutFileDebugSubnet
	case vpcmodel.AllSubnets:
		res = baseName + suffixOutFileSubnetsLevel
	case vpcmodel.AllSubnetsNoPGW:
		res = baseName + suffixOutFileSubnetsLevelNoPGW
	case vpcmodel.SubnetsDiff:
		res = baseName + suffixOutFileDiffSubnets
	case vpcmodel.EndpointsDiff:
		res = baseName + suffixOutFileDiffEndpoints
	}
	if grouping {
		res += suffixOutFileWithGrouping
	}
	suffix, suffixErr := getTestFileSuffix(format)
	if suffixErr != nil {
		return "", "", suffixErr
	}
	res += suffix
	expectedFileName = res
	actualFileName = actualOutFilePrefix + res
	return expectedFileName, actualFileName, nil
}

func getTestFileSuffix(format vpcmodel.OutFormat) (suffix string, err error) {
	switch format {
	case vpcmodel.Text:
		return txtOutSuffix, nil
	case vpcmodel.Debug:
		return debugOutSuffix, nil
	case vpcmodel.MD:
		return mdOutSuffix, nil
	case vpcmodel.JSON:
		return jsonOutSuffix, nil
	case vpcmodel.DRAWIO:
		return drawioOutSuffix, nil
	case vpcmodel.ARCHDRAWIO:
		return archDrawioOutSuffix, nil
	default:
		return "", errors.New("unexpected out format")
	}
}

// initTest: based on the test name, set the input config file name, and the output
// files names (actual and expected), per use case
func (tt *vpcGeneralTest) initTest() {
	tt.inputConfig = inputFilePrefix + tt.name + ".json"
	tt.inputConfig2nd = inputFilePrefix + tt.name + "_2nd.json"
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
	name:     "tgw_basic_example",
	useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
	format:   vpcmodel.DRAWIO,
	grouping: true,
},
{
	name:     "tgw_larger_example",
	useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
	format:   vpcmodel.DRAWIO,
	grouping: true,
},
}

var tests2 = []*vpcGeneralTest{
	{
		name:     "acl_testing5",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.MD,
	},
	{
		name:     "acl_testing5_old",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.MD,
	},
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
	{
		name:     "acl_testing5",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping: true,
		format:   vpcmodel.DRAWIO,
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
	{
		name:     "sg_testing_3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
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

	// batch2.5: only vsi-level use-case, with grouping , drawio format
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "demo_with_instances",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "iks_config_object",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "mult_NIs_single_VSI",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.DRAWIO,
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
	// disable drawio tests until supported with VPE
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
	// multi-vpc config example
	{
		name:     "acl_testing3_with_two_vpcs",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.Text,
		vpc:      "crn:12", // specify the vpc to analyze
	},
	// vpe example
	{
		name:     "demo_with_instances_vpes",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.Text,
	},
	// multi-vpc config examples
	{
		name:     "experiments_env",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.Text,
	},
	{
		name:     "experiments_env",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.JSON,
	},
	{
		name:     "multiple_vpcs",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	// diff examples:
	{
		name:     "acl_testing5",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
		format:   vpcmodel.Text,
	},
	{
		name:     "acl_testing5",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
		format:   vpcmodel.MD,
	},
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:   vpcmodel.Text,
	},
	{
		name:     "acl_testing3",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:   vpcmodel.MD,
	},
	{
		name:     "sg_testing1_new",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:   vpcmodel.Text,
	},
	// tgw examples
	{
		name:     "tgw_basic_example",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	{
		name:     "tgw_basic_example_multiple_regions",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	{
		name:     "tgw_larger_example",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:   vpcmodel.Text,
	},
	// multivpc drawio:
	{
		name:     "multiple_vpcs",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "multiple_vpcs",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
	{
		name:     "experiments_env",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:   vpcmodel.ARCHDRAWIO,
	},
	{
		name:     "experiments_env",
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping: true,
		format:   vpcmodel.DRAWIO,
	},
}

var formatsAvoidComparison = map[vpcmodel.OutFormat]bool{vpcmodel.ARCHDRAWIO: true, vpcmodel.DRAWIO: true}

// uncomment the function below to run for updating the expected output
/*var formatsAvoidOutputGeneration = map[vpcmodel.OutFormat]bool{vpcmodel.ARCHDRAWIO: true, vpcmodel.DRAWIO: true}

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

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := getVPCConfigs(t, tt, true)
	var vpcConfigs2nd map[string]*vpcmodel.VPCConfig
	diffUseCase := false
	for _, useCase := range tt.useCases {
		if useCase == vpcmodel.SubnetsDiff || useCase == vpcmodel.EndpointsDiff {
			diffUseCase = true
		}
	}
	if diffUseCase {
		vpcConfigs2nd = getVPCConfigs(t, tt, false)
	} else { // inputConfig2nd should be ignored if not diffUseCase
		tt.inputConfig2nd = ""
	}

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.useCases {
		err := runTestPerUseCase(t, tt, vpcConfigs, vpcConfigs2nd, uc, tt.mode)
		require.Equal(t, tt.errPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

// getVPCConfigs returns  map[string]*vpcmodel.VPCConfig obj for the input test (config json file)
func getVPCConfigs(t *testing.T, tt *vpcGeneralTest, firstCfg bool) map[string]*vpcmodel.VPCConfig {
	var inputConfig string
	if firstCfg {
		inputConfig = tt.inputConfig
	} else {
		inputConfig = tt.inputConfig2nd
	}
	inputConfigFile := filepath.Join(getTestsDir(), inputConfig)
	rc, err := ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := VPCConfigsFromResources(rc, tt.vpc, false)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return vpcConfigs
}

func compareOrRegenerateOutputPerTest(t *testing.T,
	mode testMode,
	actualOutput string,
	tt *vpcGeneralTest,
	uc vpcmodel.OutputUseCase) error {
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
		if _, err := vpcmodel.WriteToFile(actualOutput, tt.expectedOutput[uc]); err != nil {
			return err
		}
	}
	return nil
}

func initTestFileNames(tt *vpcGeneralTest,
	uc vpcmodel.OutputUseCase,
	vpcName string,
	allVPCs bool) error {
	expectedFileName, actualFileName, err := getTestFileName(
		tt.name, uc, tt.grouping, tt.format, vpcName, allVPCs)
	if err != nil {
		return err
	}
	tt.actualOutput[uc] = filepath.Join(getTestsDir(), actualFileName)
	tt.expectedOutput[uc] = filepath.Join(getTestsDir(), expectedFileName)
	return nil
}

// runTestPerUseCase runs the connectivity analysis for the required use case and compares/generates the output
func runTestPerUseCase(t *testing.T,
	tt *vpcGeneralTest,
	c1, c2 map[string]*vpcmodel.VPCConfig,
	uc vpcmodel.OutputUseCase,
	mode testMode) error {
	if err := initTestFileNames(tt, uc, "", true); err != nil {
		return err
	}
	og, err := vpcmodel.NewOutputGenerator(c1, c2, tt.grouping, uc, tt.format == vpcmodel.ARCHDRAWIO)
	if err != nil {
		return err
	}
	actualOutput, err := og.Generate(tt.format, tt.actualOutput[uc])
	if err != nil {
		return err
	}
	if err := compareOrRegenerateOutputPerTest(t, mode, actualOutput, tt, uc); err != nil {
		return err
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
	_, err1 = vpcmodel.WriteToFile(expected, filepath.Join(getTestsDir(), "expected.txt"))
	_, err2 = vpcmodel.WriteToFile(actual, filepath.Join(getTestsDir(), "actual.txt"))
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
