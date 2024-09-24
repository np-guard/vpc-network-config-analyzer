/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testfunc

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type testMode int

const (
	OutputComparison testMode = iota // compare actual output to expected output
	OutputGeneration                 // generate expected output
	OutputIgnore                     // ignore expected output
)

const (
	examplesDir    = "examples/"
	inputDir       = "input/"
	outDir         = "out/"
	errString      = "err: %s"
	carriageReturn = "\r"

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
	drawioOutSuffix                   = ".drawio"
	archDrawioOutSuffix               = "_arch.drawio"
	svgOutSuffix                      = ".svg"
	archSvgOutSuffix                  = "_arch.svg"
	htmlOutSuffix                     = ".html"
	archHTMLOutSuffix                 = "_arch.html"
)

/*
tests for the entire flow:
	- input from config json file
	- output comparison, for the possible output use-cases
	- currently comparing only txt output formats
*/

type VpcTestCommon struct {
	Name string // test name
	// todo: support multiple configs input
	InputConfig    string                            // name (relative path) of input config file (json)
	ExpectedOutput map[vpcmodel.OutputUseCase]string // expected output file path
	ActualOutput   map[vpcmodel.OutputUseCase]string // actual output file path
	UseCases       []vpcmodel.OutputUseCase          // the list of output use cases to test
	ErrPerUseCase  map[vpcmodel.OutputUseCase]error
	Format         vpcmodel.OutFormat
	ResourceGroup  string   // filter vpc configs by resource group
	Regions        []string // filter vpc configs by region
	Mode           testMode
	VpcList        []string
}

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

// getVPCConfigs returns  *vpcmodel.MultipleVPCConfigs obj for the input test (config json file)
func (tt *VpcTestCommon) getVPCConfigs(t *testing.T, inputConfig string, rc commonvpc.ResourcesContainer) *vpcmodel.MultipleVPCConfigs {
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

// initTest based on the test name, set the input config file name, and the output
// files names (actual and expected), per use case
func (tt *VpcTestCommon) initTest() {
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

func (tt *VpcTestCommon) initTestFileNames(uc vpcmodel.OutputUseCase,
	vpcName string, allVPCs, detailExplain bool, testDirOut string, grouping, noLbAbstract bool) error {
	expectedFileName, actualFileName, err := getTestFileName(
		tt.Name, uc, grouping, noLbAbstract, detailExplain, tt.Format, vpcName, allVPCs, tt.VpcList)
	if err != nil {
		return err
	}
	tt.ActualOutput[uc] = filepath.Join(getTestsDirOut(testDirOut), actualFileName)
	tt.ExpectedOutput[uc] = filepath.Join(getTestsDirOut(testDirOut), expectedFileName)
	return nil
}

// runTestPerUseCase runs the connectivity analysis for the required use case and compares/generates the output
func (tt *VpcTestCommon) runTestPerUseCase(t *testing.T,
	cConfigs *vpcmodel.MultipleVPCConfigs,
	uc vpcmodel.OutputUseCase,
	mode testMode,
	outDir string,
	grouping, noLbAbstract bool,
	explanationArgs *vpcmodel.ExplanationArgs) error {
	detailExplain := false
	if explanationArgs != nil {
		detailExplain = explanationArgs.Detail
	}
	allVpcs := len(tt.VpcList) == 0
	if err := tt.initTestFileNames(uc, "", allVpcs, detailExplain, outDir, grouping, noLbAbstract); err != nil {
		return err
	}
	og, err := vpcmodel.NewOutputGenerator(cConfigs, grouping, uc, tt.Format == vpcmodel.ARCHDRAWIO,
		explanationArgs, tt.Format, !noLbAbstract)
	if err != nil {
		return err
	}
	actualOutput, err := og.Generate(tt.Format, tt.ActualOutput[uc])
	if err != nil {
		return err
	}
	if err := compareOrRegenerateOutputPerTest(t, mode, actualOutput, outDir, tt.Name, tt.ExpectedOutput, uc); err != nil {
		return err
	}
	return nil
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

// comparison should be insensitive to line comparators; cleaning strings from line comparators
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "/n", ""), carriageReturn, "")
}

// compareTextualResult is called in case of output mismatch, to provide more details on the difference
func compareTextualResult(expected, actual, testDir string) {
	var err1, err2 error
	_, err1 = vpcmodel.WriteToFile(expected, filepath.Join(getTestsDirOut(testDir), "expected.txt"))
	_, err2 = vpcmodel.WriteToFile(actual, filepath.Join(getTestsDirOut(testDir), "actual.txt"))
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

// getTestsDirOut returns the path to the dir where test output files are located
func getTestsDirOut(testDir string) string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+outDir+testDir)
}

// GetTestsDirInput returns the path to the dir where test input files are located
func GetTestsDirInput() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+inputDir)
}

func compareOrRegenerateOutputPerTest(t *testing.T, mode testMode, actualOutput, testDir, name string,
	expectedOutput map[vpcmodel.OutputUseCase]string, uc vpcmodel.OutputUseCase) error {
	if mode == OutputComparison {
		expectedOutput, err := os.ReadFile(expectedOutput[uc])
		if err != nil {
			t.Fatalf(errString, err)
		}
		expectedOutputStr := string(expectedOutput)
		if cleanStr(expectedOutputStr) != cleanStr(actualOutput) {
			compareTextualResult(expectedOutputStr, actualOutput, testDir)
			t.Fatalf("output mismatch expected-vs-actual on test name: %s, use case: %d", name, uc)
		}
	} else if mode == OutputGeneration {
		fmt.Printf("outputGeneration\n")
		// create or override expected output file
		if _, err := vpcmodel.WriteToFile(actualOutput, expectedOutput[uc]); err != nil {
			return err
		}
	}
	return nil
}

var formatsAvoidComparisonAndGeneration = map[vpcmodel.OutFormat]bool{
	vpcmodel.DRAWIO:     true,
	vpcmodel.ARCHDRAWIO: true,
	vpcmodel.SVG:        true,
	vpcmodel.ARCHSVG:    true,
	vpcmodel.HTML:       true,
	vpcmodel.ARCHHTML:   true,
}

// todo - remove once drawio is stable
func (tt *VpcTestCommon) setMode(mode testMode) {
	if formatsAvoidComparisonAndGeneration[tt.Format] {
		tt.Mode = OutputIgnore
	} else {
		tt.Mode = mode
	}
}

func (tt *VpcTestCommon) runSingleCommonTest(t *testing.T, testDir string, rc commonvpc.ResourcesContainer,
	grouping, noLbAbstract bool, explanationArgs *vpcmodel.ExplanationArgs) {
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := tt.getVPCConfigs(t, tt.InputConfig, rc)

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.UseCases {
		err := tt.runTestPerUseCase(t, vpcConfigs, uc, tt.Mode, testDir, grouping, noLbAbstract, explanationArgs)
		require.Equal(t, tt.ErrPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.ActualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.Name, uc, outFile)
	}
}

func (tt *VpcTestCommon) TestCommonSingleTest(t *testing.T, mode testMode, rc commonvpc.ResourcesContainer, testDir,
	testName string, grouping, noLbAbstract bool) {
	tt.Name = testName
	tt.setMode(mode)
	t.Run(tt.Name, func(t *testing.T) {
		t.Parallel()
		tt.runSingleCommonTest(t, testDir, rc, grouping, noLbAbstract, nil)
	})
}
