/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/np-guard/models/pkg/netp"

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
	OutputComparison testMode = iota // compare actual output to expected output
	OutputGeneration                 // generate expected output
	OutputIgnore                     // ignore expected output
)

const (
	examplesDir = "examples/"
	inputDir    = "input/"
	outDir      = "out/"
)

const errString = "err: %s"
const carriageReturn = "\r"

type VpcGeneralTest struct {
	Name string // test name
	// todo: support multiple configs input
	InputConfig    string                            // name (relative path) of input config file (json)
	InputConfig2nd string                            // 2nd input file for diff
	ExpectedOutput map[vpcmodel.OutputUseCase]string // expected output file path
	ActualOutput   map[vpcmodel.OutputUseCase]string // actual output file path
	UseCases       []vpcmodel.OutputUseCase          // the list of output use cases to test
	ErrPerUseCase  map[vpcmodel.OutputUseCase]error
	ResourceGroup  string   // filter vpc configs by resource group
	Regions        []string // filter vpc configs by region
	Mode           testMode
	Grouping       bool
	NoLbAbstract   bool
	Format         vpcmodel.OutFormat
	VpcList        []string
	ESrc           string
	EDst           string
	EProtocol      netp.ProtocolString
	ESrcMinPort    int64
	ESrcMaxPort    int64
	EDstMinPort    int64
	EDstMaxPort    int64
	DetailExplain  bool
	Enable         []string
	Disable        []string
	PrintAllLints  bool
}

const (
	ActualOutFilePrefix               = "out_"
	InputFilePrefix                   = "input_"
	suffixOutFileWithGrouping         = "_with_grouping"
	suffixOutFileWithoutLbAbstraction = "_no_lbAbstract"
	suffixOutFileDebugSubnet          = "_analysisPerSubnetSeparately"
	suffixOutFileSubnetsLevel         = "subnetsBased_withPGW"
	suffixOutFileSubnetsLevelNoPGW    = "subnetsBased_withoutPGW"
	suffixOutFileDiffSubnets          = "subnetsDiff"
	suffixOutFileDiffEndpoints        = "endpointsDiff"
	suffixOutFileExplain              = "explain"
	suffixOutFileDetail               = "_detail"
	txtOutSuffix                      = ".txt"
	mdOutSuffix                       = ".md"
	JSONOutSuffix                     = ".json"
	secJSONOutSuffix                  = "_2nd.json"
	drawioOutSuffix                   = ".drawio"
	archDrawioOutSuffix               = "_arch.drawio"
	svgOutSuffix                      = ".svg"
	archSvgOutSuffix                  = "_arch.svg"
	htmlOutSuffix                     = ".html"
	archHTMLOutSuffix                 = "_arch.html"
)

// getTestFileName returns expected file name and actual file name, for the relevant use case
func getTestFileName(testName string,
	uc vpcmodel.OutputUseCase,
	grouping bool,
	noLbAbstract bool,
	detailExplain bool,
	format vpcmodel.OutFormat,
	configName string,
	allVPCs bool,
	vpcIDs []string) (
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
	case vpcmodel.Explain:
		res = baseName + suffixOutFileExplain
	}
	if grouping {
		res += suffixOutFileWithGrouping
	}
	if noLbAbstract {
		res += suffixOutFileWithoutLbAbstraction
	}
	if detailExplain {
		res += suffixOutFileDetail
	}
	if !allVPCs {
		res += strings.ReplaceAll(strings.Join(vpcIDs, ""), ":", "")
	}
	suffix, suffixErr := getTestFileSuffix(format)
	if suffixErr != nil {
		return "", "", suffixErr
	}
	res += suffix

	expectedFileName = res
	actualFileName = ActualOutFilePrefix + res
	return expectedFileName, actualFileName, nil
}

func getTestFileSuffix(format vpcmodel.OutFormat) (suffix string, err error) {
	switch format {
	case vpcmodel.Text:
		return txtOutSuffix, nil
	case vpcmodel.MD:
		return mdOutSuffix, nil
	case vpcmodel.JSON:
		return JSONOutSuffix, nil
	case vpcmodel.Synthesis:
		return JSONOutSuffix, nil
	case vpcmodel.DRAWIO:
		return drawioOutSuffix, nil
	case vpcmodel.ARCHDRAWIO:
		return archDrawioOutSuffix, nil
	case vpcmodel.SVG:
		return svgOutSuffix, nil
	case vpcmodel.ARCHSVG:
		return archSvgOutSuffix, nil
	case vpcmodel.HTML:
		return htmlOutSuffix, nil
	case vpcmodel.ARCHHTML:
		return archHTMLOutSuffix, nil
	default:
		return "", errors.New("unexpected out format")
	}
}

func (tt *VpcGeneralTest) RunTest(t *testing.T, testDir string, rc ResourcesContainer) {
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := GetVPCConfigs(t, tt, true, rc)
	var vpcConfigs2nd *vpcmodel.MultipleVPCConfigs
	diffUseCase := false
	explainUseCase := false
	for _, useCase := range tt.UseCases {
		if useCase == vpcmodel.SubnetsDiff || useCase == vpcmodel.EndpointsDiff {
			diffUseCase = true
		}
		if useCase == vpcmodel.Explain {
			explainUseCase = true
		}
	}
	if diffUseCase {
		vpcConfigs2nd = GetVPCConfigs(t, tt, false, rc)
		vpcConfigs.SetConfigsToCompare(vpcConfigs2nd.Configs())
	} else { // inputConfig2nd should be ignored if not diffUseCase
		tt.InputConfig2nd = ""
	}

	var explanationArgs *vpcmodel.ExplanationArgs
	if explainUseCase {
		explanationArgs = vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
			tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.DetailExplain)
	}

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.UseCases {
		err := RunTestPerUseCase(t, tt, vpcConfigs, uc, tt.Mode, testDir, explanationArgs)
		require.Equal(t, tt.ErrPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}

// GetVPCConfigs returns  *vpcmodel.MultipleVPCConfigs obj for the input test (config json file)
func GetVPCConfigs(t *testing.T, tt *VpcGeneralTest, firstCfg bool, rc ResourcesContainer) *vpcmodel.MultipleVPCConfigs {
	var inputConfig string
	if firstCfg {
		inputConfig = tt.InputConfig
	} else {
		inputConfig = tt.InputConfig2nd
	}
	inputConfigFile := filepath.Join(GetTestsDirInput(), inputConfig)
	err := rc.ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf(errString, err)
	}
	vpcConfigs, err := rc.VPCConfigsFromResources(tt.ResourceGroup, tt.VpcList, tt.Regions)
	if err != nil {
		t.Fatalf(errString, err)
	}
	return vpcConfigs
}

// InitTest: based on the test name, set the input config file name, and the output
// files names (actual and expected), per use case
func (tt *VpcGeneralTest) InitTest() {
	tt.InputConfig2nd = InputFilePrefix + tt.InputConfig + secJSONOutSuffix
	tt.InputConfig = InputFilePrefix + tt.InputConfig + JSONOutSuffix
	tt.ExpectedOutput = map[vpcmodel.OutputUseCase]string{}
	tt.ActualOutput = map[vpcmodel.OutputUseCase]string{}
	// init field of expected errs
	if tt.ErrPerUseCase == nil {
		tt.ErrPerUseCase = map[vpcmodel.OutputUseCase]error{}
	}
	for _, uc := range tt.UseCases {
		if _, ok := tt.ErrPerUseCase[uc]; !ok {
			tt.ErrPerUseCase[uc] = nil // if errs not specified, by default not expecting errs
		}
	}
}

func CompareOrRegenerateOutputPerTest(t *testing.T,
	mode testMode,
	actualOutput string,
	testDir string,
	tt *VpcGeneralTest,
	uc vpcmodel.OutputUseCase) error {
	if mode == OutputComparison {
		expectedOutput, err := os.ReadFile(tt.ExpectedOutput[uc])
		if err != nil {
			t.Fatalf(errString, err)
		}
		expectedOutputStr := string(expectedOutput)
		if cleanStr(expectedOutputStr) != cleanStr(actualOutput) {
			compareTextualResult(expectedOutputStr, actualOutput, testDir)
			t.Fatalf("output mismatch expected-vs-actual on test name: %s, use case: %d", tt.Name, uc)
		}
	} else if mode == OutputGeneration {
		fmt.Printf("outputGeneration\n")
		// create or override expected output file
		if _, err := vpcmodel.WriteToFile(actualOutput, tt.ExpectedOutput[uc]); err != nil {
			return err
		}
	}
	return nil
}

func initTestFileNames(tt *VpcGeneralTest,
	uc vpcmodel.OutputUseCase,
	vpcName string,
	allVPCs bool,
	testDirOut string) error {
	expectedFileName, actualFileName, err := getTestFileName(
		tt.Name, uc, tt.Grouping, tt.NoLbAbstract, tt.DetailExplain, tt.Format, vpcName, allVPCs, tt.VpcList)
	if err != nil {
		return err
	}
	tt.ActualOutput[uc] = filepath.Join(GetTestsDirOut(testDirOut), actualFileName)
	tt.ExpectedOutput[uc] = filepath.Join(GetTestsDirOut(testDirOut), expectedFileName)
	return nil
}

// runTestPerUseCase runs the connectivity analysis for the required use case and compares/generates the output
func RunTestPerUseCase(t *testing.T,
	tt *VpcGeneralTest,
	cConfigs *vpcmodel.MultipleVPCConfigs,
	uc vpcmodel.OutputUseCase,
	mode testMode,
	outDir string,
	explanationArgs *vpcmodel.ExplanationArgs) error {
	allVpcs := len(tt.VpcList) == 0
	if err := initTestFileNames(tt, uc, "", allVpcs, outDir); err != nil {
		return err
	}
	og, err := vpcmodel.NewOutputGenerator(cConfigs, tt.Grouping, uc, tt.Format == vpcmodel.ARCHDRAWIO,
		explanationArgs, tt.Format, !tt.NoLbAbstract)
	if err != nil {
		return err
	}
	actualOutput, err := og.Generate(tt.Format, tt.ActualOutput[uc])
	if err != nil {
		return err
	}
	if err := CompareOrRegenerateOutputPerTest(t, mode, actualOutput, outDir, tt, uc); err != nil {
		return err
	}
	return nil
}

// comparison should be insensitive to line comparators; cleaning strings from line comparators
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "/n", ""), carriageReturn, "")
}

// compareTextualResult is called in case of output mismatch, to provide more details on the difference
func compareTextualResult(expected, actual, testDir string) {
	var err1, err2 error
	_, err1 = vpcmodel.WriteToFile(expected, filepath.Join(GetTestsDirOut(testDir), "expected.txt"))
	_, err2 = vpcmodel.WriteToFile(actual, filepath.Join(GetTestsDirOut(testDir), "actual.txt"))
	if err1 != nil || err2 != nil {
		fmt.Printf("compareTextualResult: error writing actual/expected output to files: %s, %s \n", err1, err2)
	}

	expectedLines := strings.Split(strings.ReplaceAll(expected, carriageReturn, ""), "\n")
	actualLines := strings.Split(strings.ReplaceAll(actual, carriageReturn, ""), "\n")
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

// GetTestsDirOut returns the path to the dir where test output files are located
func GetTestsDirOut(testDir string) string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+outDir+testDir)
}

// getTestsDir returns the path to the dir where test input files are located
func GetTestsDirInput() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+inputDir)
}

var formatsAvoidComparisonAndGeneration = map[vpcmodel.OutFormat]bool{
	vpcmodel.DRAWIO:     true,
	vpcmodel.ARCHDRAWIO: true,
	vpcmodel.SVG:        true,
	vpcmodel.ARCHSVG:    true,
	vpcmodel.HTML:       true,
	vpcmodel.ARCHHTML:   true,
}

func TestAll(tt *VpcGeneralTest, t *testing.T, mode testMode, rc ResourcesContainer, testDir, testName string) {
	// todo - remove the following if when drawio is stable
	if formatsAvoidComparisonAndGeneration[tt.Format] {
		tt.Mode = OutputIgnore
	} else {
		tt.Mode = mode
	}
	tt.Name = testName
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.RunTest(t, testDir, rc)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////
// explainability:
//////////////////////////////////////////////////////////////////////////////////////////////

const explainOut = "explain_out"

func RunExplainTest(tt *VpcGeneralTest, t *testing.T, rc ResourcesContainer) {
	// all tests in explain mode
	tt.UseCases = []vpcmodel.OutputUseCase{vpcmodel.Explain}
	// init test - set the input/output file names according to test name
	tt.InitTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := GetVPCConfigs(t, tt, true, rc)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.DetailExplain)

	// generate actual output for all use cases specified for this test
	err := RunTestPerUseCase(t, tt, vpcConfigs, vpcmodel.Explain, tt.Mode, explainOut, explanationArgs)
	require.Equal(t, tt.ErrPerUseCase[vpcmodel.Explain], err, "comparing explain actual err to expected err")
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("explain test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}
