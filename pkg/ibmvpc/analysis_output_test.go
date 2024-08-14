/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

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

	"github.com/np-guard/models/pkg/netp"

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

const (
	examplesDir = "examples/"
	inputDir    = "input/"
	outDir      = "out/"
	analysisOut = "analysis_out"
)

type vpcGeneralTest struct {
	name string // test name
	// todo: support multiple configs input
	inputConfig    string                            // name (relative path) of input config file (json)
	inputConfig2nd string                            // 2nd input file for diff
	expectedOutput map[vpcmodel.OutputUseCase]string // expected output file path
	actualOutput   map[vpcmodel.OutputUseCase]string // actual output file path
	useCases       []vpcmodel.OutputUseCase          // the list of output use cases to test
	errPerUseCase  map[vpcmodel.OutputUseCase]error
	resourceGroup  string   // filter vpc configs by resource group
	regions        []string // filter vpc configs by region
	mode           testMode
	grouping       bool
	noLbAbstract   bool
	format         vpcmodel.OutFormat
	vpc            string
	ESrc           string
	EDst           string
	EProtocol      netp.ProtocolString
	ESrcMinPort    int64
	ESrcMaxPort    int64
	EDstMinPort    int64
	EDstMaxPort    int64
	detailExplain  bool
	enable         []string
	disable        []string
}

const (
	actualOutFilePrefix               = "out_"
	inputFilePrefix                   = "input_"
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
	jsonOutSuffix                     = ".json"
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
	case vpcmodel.MD:
		return mdOutSuffix, nil
	case vpcmodel.JSON:
		return jsonOutSuffix, nil
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

// initTest: based on the test name, set the input config file name, and the output
// files names (actual and expected), per use case
func (tt *vpcGeneralTest) initTest() {
	tt.inputConfig2nd = inputFilePrefix + tt.inputConfig + secJSONOutSuffix
	tt.inputConfig = inputFilePrefix + tt.inputConfig + jsonOutSuffix
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
		inputConfig: "acl_testing5",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "acl_testing5_old",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "acl_testing5",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "acl_testing5_old",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "acl_testing5",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	// batch1: cover all use-cases, with text output format , no grouping
	{
		inputConfig: "acl_testing3",
		// TODO: currently skipping uc3 since it is not supported with partial subnet connectivity
		useCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet},
		format:   vpcmodel.Text,
	},
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.HTML,
	},
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.HTML,
	},
	{
		inputConfig: "tg-prefix-filters",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.HTML,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "sg_testing_3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "sg_testing_3_with_empty_remote",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
	},

	// batch2: only vsi-level use-case, with grouping , text format
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	// respond enabled only on part of the TCP connection
	{
		inputConfig: "sg_testing1_new_respond_partly",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},

	// batch2.5: only vsi-level use-case, with grouping , drawio format
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "iks_config_object",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "mult_NIs_single_VSI",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},

	//batch3: only vsi-level use-case, no grouping, with md output formats
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.DRAWIO,
	},

	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.ARCHDRAWIO,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.ARCHDRAWIO,
	},
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.ARCHDRAWIO,
	},
	{
		inputConfig: "sg_testing1_new_grouping",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	// iks-nodes example
	// iks_config_object example has three SG, one of them two targets - a pgw and a LB.
	// this SG has four rules, which are reflected at the connectivity map:
	// 1. outbound, tcp, ports 30000-32767
	// 2. outbound, udp, ports 30000-32767
	// 3. inbound, udp, ports 1-65535
	// 4. inbound, udp, ports 1-65535

	{
		inputConfig: "iks_config_object",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig:  "iks_config_object",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:     true,
		noLbAbstract: true,
		format:       vpcmodel.Text,
	},
	// json examples
	{
		inputConfig: "demo_with_instances",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.JSON,
	},
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.JSON,
	},
	// multi-vpc config example
	{
		inputConfig: "acl_testing3_with_two_vpcs",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
		vpc:         "crn:12", // specify the vpc to analyze
	},
	// vpe example
	{
		inputConfig: "demo_with_instances_vpes",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
	},
	// multi-vpc config examples
	{
		inputConfig: "experiments_env",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "experiments_env",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.JSON,
	},
	{
		inputConfig: "multiple_vpcs",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	// diff examples:
	{
		inputConfig: "acl_testing5",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "acl_testing5",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "acl_testing3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.MD,
	},
	{
		inputConfig: "sg_testing1_new",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.Text,
	},
	{ // example with diff with partial TCP respond
		inputConfig: "sg_testing1_copy",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.Text,
	},
	{ // example with diff in which the diff is in the amount of TCP respond enabled
		inputConfig: "sg_testing1_new_respond_partly",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.Text,
	},
	{
		// diff between VPCs of different UIDs
		inputConfig: "sg_testing_3",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.Text,
	},
	{
		// diff between identical VPCs
		inputConfig: "sg_testing_default",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		format:      vpcmodel.Text,
	},
	// tgw examples
	{
		inputConfig: "tgw_basic_example",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "tgw_basic_example_multiple_regions",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "tgw_basic_example_with_some_default_deny",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "tgw_larger_example",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "tgw_larger_example",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
		grouping:    true,
	},

	{
		inputConfig: "tg-prefix-filters",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.Text,
	},
	// tgw examples with drawio
	{
		inputConfig: "tgw_larger_example",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "tgw_larger_example",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		format:      vpcmodel.DRAWIO,
		grouping:    true,
	},
	// multivpc drawio:
	{
		inputConfig: "multiple_vpcs",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "multiple_vpcs",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "experiments_env",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.ARCHDRAWIO,
	},
	{
		inputConfig: "experiments_env",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	// resource group filtering example
	// ete-storage-project and ete-backup-and-storage vpcs expected to be filtered out
	// global-tg-ky and local-tg-ky tgws expected to be filtered out
	{
		inputConfig:   "multi_resource_groups",
		useCases:      []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:        vpcmodel.Text,
		resourceGroup: "ola",
	},
	// region filtering example
	// zn-vpc1, zn-vpc2, zn-vpc3 expected to be filtered out
	// global-tg-zn and local-tg-zn tgws expected to be filtered out
	{
		inputConfig: "multi_regions",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
		regions:     []string{"us-east"},
	},
	{
		inputConfig: "iks_workers_large",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "iks_workers_large",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		grouping:    false,
		format:      vpcmodel.DRAWIO,
	},
	{
		inputConfig: "iks_workers_large",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		grouping:    true,
		format:      vpcmodel.HTML,
	},
	{
		inputConfig: "iks_workers_large",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.ARCHSVG,
	},
	{
		inputConfig: "iks_workers_large",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.DRAWIO,
	},
	// grouping test of identical names different resources and thus different UIDs that should not be merged
	{
		inputConfig: "sg_testing1_new_dup_subnets_names",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig:  "iks_workers_large",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:     true,
		noLbAbstract: true,
		format:       vpcmodel.HTML,
	},
	{
		inputConfig:  "iks_workers_large",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:     true,
		noLbAbstract: true,
		format:       vpcmodel.DRAWIO,
	},
	// LB examples:
	{
		inputConfig: "lb_bad_practice",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "lb_bad_practice",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "iks_w_lb",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.HTML,
	},
	{
		inputConfig: "lb_policies",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.HTML,
	},
	{
		inputConfig:  "load_balancer",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		grouping:     true,
		noLbAbstract: true,
		format:       vpcmodel.HTML,
	},
	{
		inputConfig: "load_balancer",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig:  "load_balancer",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:     true,
		noLbAbstract: true,
		format:       vpcmodel.Text,
	},
	{
		inputConfig: "nacl_split_subnet",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
	},
	// filters_split_lb_subnet example has one load balancer with three subnets, subnets Cidrs:
	//  10.240.65.0/24
	//  10.240.1.0/24
	//  10.240.129.0/24

	// acl filters with the following cidr:
	//  10.240.129.0/25

	// sg filters with the following Cidrs:
	//  10.240.1.0/25
	//  10.240.65.0/25

	// as a result:
	// 1. each subnet has two private IPs
	// 2. after abstraction, all connections from/to the LB are marked with **, (i.e. the abstraction did over approximation)
	// for example here only four private IPs are connected to vsi1-sub3[10.240.128.5]:
	//     vsi1-sub3[10.240.128.5] => alb[Potential LB private IP][10.240.1.0/25] : All Connections
	//     vsi1-sub3[10.240.128.5] => alb[Potential LB private IP][10.240.1.128/25] : All Connections
	//     vsi1-sub3[10.240.128.5] => alb[Potential LB private IP][10.240.129.128/25] : All Connections
	//     vsi1-sub3[10.240.128.5] => alb[Potential LB private IP][10.240.65.128/25] : All Connections
	//     vsi1-sub3[10.240.128.5] => alb[LB private IP][10.240.65.4] : All Connections
	// is over approximated to:
	//	   vsi1-sub3[10.240.128.5] => alb[LoadBalancer] : All Connections **

	{
		inputConfig:  "filters_split_lb_subnet",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:       vpcmodel.Text,
		grouping:     false,
		noLbAbstract: true,
	},
	{
		inputConfig: "filters_split_lb_subnet",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:      vpcmodel.Text,
		grouping:    false,
	},
	{
		inputConfig:  "filters_split_lb_subnet",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:       vpcmodel.HTML,
		grouping:     true,
		noLbAbstract: true,
	},
	{
		inputConfig: "hub_n_spoke_1",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig:  "hub_n_spoke_1",
		useCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		format:       vpcmodel.HTML,
		grouping:     true,
		noLbAbstract: true,
	},
	{
		inputConfig: "fabricated",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		format:      vpcmodel.HTML,
		grouping:    true,
	},
	{
		inputConfig: "vni_basic",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.Text,
	},
	{
		inputConfig: "vni_basic",
		useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		grouping:    true,
		format:      vpcmodel.HTML,
	},
}

var formatsAvoidComparison = map[vpcmodel.OutFormat]bool{
	vpcmodel.DRAWIO:     true,
	vpcmodel.ARCHDRAWIO: true,
	vpcmodel.SVG:        true,
	vpcmodel.ARCHSVG:    true,
	vpcmodel.HTML:       true,
	vpcmodel.ARCHHTML:   true,
}

// uncomment the function below to run for updating the expected output
/*
var formatsAvoidOutputGeneration = formatsAvoidComparison

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
		tt.name = tt.inputConfig
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}
*/
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
		tt.name = tt.inputConfig
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}

// TestUnsupportedAnalysis demonstrates cases where analysis is not supported
func TestUnsupportedAnalysis(t *testing.T) {
	tests := []*vpcGeneralTest{
		{
			// here the connectivity per subnet is getting split to few parts by various local ranges within the subnet cidr,
			// and the split is by the ACL's rules "local" part (e.g. "from" in egress rule / "to" in ingress rule)
			name:        "unsupported_analysis_acl_testing3",
			inputConfig: "acl_testing3",
			useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			format:      vpcmodel.Text,
			errPerUseCase: map[vpcmodel.OutputUseCase]error{
				vpcmodel.AllSubnets: errors.New("unsupported connectivity map with partial subnet ranges per connectivity result"),
			},
			mode: outputGeneration,
		},
		{
			// here the split is by  ACL's rules "remote" part (e.g. "to" in egress rule / "from" in ingress rule)
			name:        "unsupported_nacl_split_subnet",
			inputConfig: "nacl_split_subnet",
			useCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			format:      vpcmodel.Text,
			errPerUseCase: map[vpcmodel.OutputUseCase]error{
				vpcmodel.AllSubnets: errors.New("unsupported subnets connectivity analysis - no consistent connectivity for entire subnet sub1"),
			},
			mode: outputGeneration,
		},
	}
	for testIdx := range tests {
		test := tests[testIdx]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.runTest(t)
		})
	}
}

func (tt *vpcGeneralTest) runTest(t *testing.T) {
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := getVPCConfigs(t, tt, true)
	var vpcConfigs2nd *vpcmodel.MultipleVPCConfigs
	diffUseCase := false
	explainUseCase := false
	for _, useCase := range tt.useCases {
		if useCase == vpcmodel.SubnetsDiff || useCase == vpcmodel.EndpointsDiff {
			diffUseCase = true
		}
		if useCase == vpcmodel.Explain {
			explainUseCase = true
		}
	}
	if diffUseCase {
		vpcConfigs2nd = getVPCConfigs(t, tt, false)
		vpcConfigs.SetConfigsToCompare(vpcConfigs2nd.Configs())
	} else { // inputConfig2nd should be ignored if not diffUseCase
		tt.inputConfig2nd = ""
	}

	var explanationArgs *vpcmodel.ExplanationArgs
	if explainUseCase {
		explanationArgs = vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
			tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.detailExplain)
	}

	// generate actual output for all use cases specified for this test
	for _, uc := range tt.useCases {
		err := runTestPerUseCase(t, tt, vpcConfigs, uc, tt.mode, analysisOut, explanationArgs)
		require.Equal(t, tt.errPerUseCase[uc], err, "comparing actual err to expected err")
	}
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

// getVPCConfigs returns  *vpcmodel.MultipleVPCConfigs obj for the input test (config json file)
func getVPCConfigs(t *testing.T, tt *vpcGeneralTest, firstCfg bool) *vpcmodel.MultipleVPCConfigs {
	var inputConfig string
	if firstCfg {
		inputConfig = tt.inputConfig
	} else {
		inputConfig = tt.inputConfig2nd
	}
	inputConfigFile := filepath.Join(getTestsDirInput(), inputConfig)
	rc := IBMresourcesContainer{}
	err := rc.ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := rc.VPCConfigsFromResources(tt.vpc, tt.resourceGroup, tt.regions)
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
	} else if mode == outputGeneration {
		fmt.Printf("outputGeneration\n")
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
	allVPCs bool,
	testDir string) error {
	expectedFileName, actualFileName, err := getTestFileName(
		tt.name, uc, tt.grouping, tt.noLbAbstract, tt.detailExplain, tt.format, vpcName, allVPCs)
	if err != nil {
		return err
	}
	tt.actualOutput[uc] = filepath.Join(getTestsDirOut(testDir), actualFileName)
	tt.expectedOutput[uc] = filepath.Join(getTestsDirOut(testDir), expectedFileName)
	return nil
}

// runTestPerUseCase runs the connectivity analysis for the required use case and compares/generates the output
func runTestPerUseCase(t *testing.T,
	tt *vpcGeneralTest,
	cConfigs *vpcmodel.MultipleVPCConfigs,
	uc vpcmodel.OutputUseCase,
	mode testMode,
	outDir string,
	explanationArgs *vpcmodel.ExplanationArgs) error {
	if err := initTestFileNames(tt, uc, "", true, outDir); err != nil {
		return err
	}
	og, err := vpcmodel.NewOutputGenerator(cConfigs, tt.grouping, uc, tt.format == vpcmodel.ARCHDRAWIO,
		explanationArgs, tt.format, !tt.noLbAbstract)
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
	_, err1 = vpcmodel.WriteToFile(expected, filepath.Join(getTestsDirOut(analysisOut), "expected.txt"))
	_, err2 = vpcmodel.WriteToFile(actual, filepath.Join(getTestsDirOut(analysisOut), "actual.txt"))
	if err1 != nil || err2 != nil {
		fmt.Printf("compareTextualResult: error writing actual/expected output to files: %s, %s \n", err1, err2)
	}

	expectedLines := strings.Split(strings.ReplaceAll(expected, "\r", ""), "\n")
	actualLines := strings.Split(strings.ReplaceAll(actual, "\r", ""), "\n")
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

// getTestsDir returns the path to the dir where test output files are located
func getTestsDirOut(testDir string) string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+outDir+testDir)
}

// getTestsDir returns the path to the dir where test input files are located
func getTestsDirInput() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+inputDir)
}
