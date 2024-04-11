/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll // styles are too long and can not be split
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const expectedOutDir = "expected_out/"

// TODO: this file need to be rewritten
func TestMain(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{
			name: "drawio_multi_vpc_all_subnets",
			args: "-output-file multi_vpc.drawio -vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -format drawio -analysis-type all_subnets",
		},
		{
			name: "drawio_multi_vpc_all_subnets_grouped",
			args: "-output-file multi_vpc_grouped.drawio -vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -format drawio -analysis-type all_subnets -grouping",
		},
		{
			name: "txt_multi_vpc",
			args: "-output-file multi_vpc.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -format txt -analysis-type all_subnets",
		},
		/*{
			name: "json_diff_acl_testing5",
			args: "-output-file acl_testing5_diff.json -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing5_2nd.json -format json -analysis-type diff_all_subnets",
		},*/

		// diff analysis_type
		{
			name: "txt_diff_acl_testing5",
			args: "-output-file acl_testing5_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json -format txt -analysis-type diff_all_subnets",
		},
		{
			name: "txt_diff_acl_testing3",
			args: "-output-file acl_testing3_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json -format txt -analysis-type diff_all_endpoints",
		},
		{
			name: "md_diff_acl_testing5",
			args: "-output-file acl_testing5_diff.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json -format md -analysis-type diff_all_subnets",
		},
		{
			name: "md_diff_acl_testing3",
			args: "-output-file acl_testing3_diff.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json -format md -analysis-type diff_all_endpoints",
		},

		// all_subnets analysis_type
		{
			name: "txt_all_subnets_342",
			args: "-output-file 342_all_subnets.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_obj_from_issue_342.json -format txt -analysis-type all_subnets",
		},
		{
			name: "txt_all_subnets_acl_testing5",
			args: "-output-file acl_testing5_all_subnets.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format txt -analysis-type all_subnets",
		},
		{
			name: "md_all_subnets_acl_testing5",
			args: "-output-file acl_testing5_all_subnets.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format md -analysis-type all_subnets",
		},
		{
			name: "json_all_subnets_acl_testing5",
			args: "-output-file acl_testing5_all_subnets.json -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format json -analysis-type all_subnets",
		},

		// all_endpoints analysis_type
		{
			name: "txt_all_endpoints_acl_testing5",
			args: "-output-file acl_testing5_all_endpoints.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format txt -analysis-type all_endpoints",
		},
		{
			name: "md_all_endpoints_acl_testing5",
			args: "-output-file acl_testing5_all_endpoints.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format md -analysis-type all_endpoints",
		},
		{
			name: "json_all_endpoints_acl_testing5",
			args: "-output-file acl_testing5_all_endpoints.json -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format json -analysis-type all_endpoints",
		},
		{
			name: "debug_all_endpoints_acl_testing5",
			args: "-output-file acl_testing5_all_endpoints.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format debug -analysis-type all_endpoints",
		},

		// single_subnet analysis_type
		{
			name: "txt_single_subnet_acl_testing5",
			args: "-output-file acl_testing5_single_subnet.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format txt -analysis-type single_subnet",
		},

		// explain_mode analysis_type
		{
			name: "txt_explain_acl_testing3",
			args: "-output-file acl_testing3_explain.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -format txt -analysis-type explain -src 10.240.10.4 -dst vsi2-ky",
		},
		{
			name: "debug_explain_acl_testing3",
			args: "-output-file acl_testing3_explain_debug.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -format txt -analysis-type explain -src vsi2-ky -dst 10.240.10.4",
		},
		{
			name: "txt_explain_acl_testing3_3rd",
			args: "-output-file acl_testing3_3rd_explain.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3_3rd.json -format txt -analysis-type explain -src vsi1-ky -dst 161.26.0.0/16 -protocol tcp -src-min-port 5 -src-max-port 4398",
		},

		// specific vpc
		{
			name: "txt_specific_vpc_acl_testing3_with_two_vpcs",
			args: "-output-file specific_vpc_acl_testing3_with_two_vpcs.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3_with_two_vpcs.json -format txt -vpc crn:12",
		},

		// version
		{
			name: "version",
			args: "-output-file version.txt -version",
		},

		// read from account // need to export api-key first
		/*{
			name: "read_from_account_mode",
			args: "-output-file account.txt -provider ibm -resource-group ola",
		},
		{
			name: "read_from_account_mode_dump_resources",
			args: "-output-file account.txt -provider ibm -dump-resources account_resources_file.json",
		},*/

		// resource group and region filter
		{
			name: "txt_resource_group_filter_multi_resource_groups",
			args: "-output-file multi_resource_groups_resource_group_filter.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json -format txt -resource-group ola",
		},
		{
			name: "txt_region_filter_multi_regions",
			args: "-output-file multi_regions_region_filter.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_multi_regions.json -format txt -region us-east",
		},
		// multi vpc configs input
		{
			name: "multi_vpc_configs",
			args: "-output-file multi_vpc_configs.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -vpc-config ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := _main(strings.Split(tt.args, " ")); err != nil {
				t.Errorf("_main(), name %s, error = %v", tt.name, err)
			}
		})
	}
	removeGeneratedFiles()
}

func TestMainWithExpectedOut(t *testing.T) {
	tests := []struct {
		name    string
		args    string // must include output-file arg
		outFile string // must be as in the command line arg output-file
	}{
		// multi vpc configs input
		{
			name:    "multi_vpc_configs",
			args:    "-output-file multi_vpc_configs.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -vpc-config ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
			outFile: "multi_vpc_configs.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := _main(strings.Split(tt.args, " ")); err != nil {
				t.Errorf("_main(), name %s, error = %v", tt.name, err)
			}
			expectedOutput, err := os.ReadFile(expectedOutDir + tt.outFile)
			if err != nil {
				t.Fatalf("err: %s", err)
			}
			expectedOutputStr := string(expectedOutput)
			actualOutput, err := os.ReadFile(tt.outFile)
			if err != nil {
				t.Fatalf("err: %s", err)
			}
			actualOutputStr := string(actualOutput)
			if cleanStr(expectedOutputStr) != cleanStr(actualOutputStr) {
				t.Fatalf("output mismatch expected-vs-actual on test name: %s", tt.name)
			}
		})
	}
	removeGeneratedFiles()
}

// comparison should be insensitive to line comparators; cleaning strings from line comparators
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "/n", ""), "\r", "")
}

func removeGeneratedFiles() {
	files1, err1 := filepath.Glob("*.txt")
	files2, err2 := filepath.Glob("*.drawio")
	files3, err3 := filepath.Glob("*.md")
	files4, err4 := filepath.Glob("*.json")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		panic(errors.Join(err1, err2, err3, err4))
	}
	for _, f := range append(files1, append(files2, append(files3, files4...)...)...) {
		if err := os.Remove(f); err != nil {
			panic(err)
		}
	}
}

func TestCommandsFailExecute(t *testing.T) {
	tests := []struct {
		name                  string
		args                  []string
		expectedErrorContains string
	}{
		{
			name:                  "bad_flag_syntax",
			args:                  []string{"-output-file", "out.txt", "vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "bad flag syntax",
		},
		{
			name:                  "missing_arg_flag",
			args:                  []string{"-output-file", "out.txt", "-vpc-config"},
			expectedErrorContains: "flag needs an argument",
		},
		{
			name:                  "vpc_config_or_provider_not_specified",
			args:                  []string{"-output-file", "out.txt"},
			expectedErrorContains: "vpc-config flag or provider flag must be specified",
		},
		{
			name:                  "wrong_analysis_type_format",
			args:                  []string{"-vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json", "-analysis-type", "single_subnet", "-format", "md"},
			expectedErrorContains: "wrong output format 'md' for analysis type 'single_subnet';",
		},
		{
			name:                  "src_and_dst_not_specified_for_explain_mode",
			args:                  []string{"-vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json", "-analysis-type", "explain"},
			expectedErrorContains: "please specify src and dst network_interface / external ip you want to explain connectivity for",
		},
		{
			name:                  "missing_sec_vpc_config_for_diff_analysis",
			args:                  []string{"-vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json", "-analysis-type", "diff_all_endpoints"},
			expectedErrorContains: "missing parameter vpc-config-second for diff analysis",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := _main(tt.args)
			require.Contains(t, err.Error(), tt.expectedErrorContains,
				"error mismatch for test %q, actual: %q, expected contains: %q", tt.name, err.Error(), tt.expectedErrorContains)
		})
	}
}
