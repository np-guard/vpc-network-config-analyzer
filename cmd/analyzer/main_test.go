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
			args: "report subnets --output-file multi_vpc.drawio --vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -o drawio",
		},
		{
			name: "drawio_multi_vpc_all_subnets_grouped",
			args: "report subnets --output-file multi_vpc_grouped.drawio -c ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -o=drawio --grouping",
		},
		{
			name: "txt_multi_vpc",
			args: "report subnets --output-file multi_vpc.txt --vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -otxt",
		},

		// diff analysis_type
		{
			name: "txt_diff_acl_testing5",
			args: "diff subnets --output-file acl_testing5_diff.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json --format txt",
		},
		{
			name: "txt_diff_acl_testing3",
			args: "diff endpoints --output-file acl_testing3_diff.txt --vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json --format txt",
		},
		{
			name: "md_diff_acl_testing5",
			args: "diff subnets --output-file acl_testing5_diff.md --vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json --format md",
		},
		{
			name: "md_diff_acl_testing3",
			args: "diff endpoints --output-file acl_testing3_diff.md --vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json --format md",
		},

		// all_subnets analysis_type
		{
			name: "txt_all_subnets_342",
			args: "report subnets --output-file 342_all_subnets.txt -c ../../pkg/ibmvpc/examples/input/input_obj_from_issue_342.json --format txt",
		},
		{
			name: "txt_all_subnets_acl_testing5",
			args: "report subnets --output-file acl_testing5_all_subnets.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format txt",
		},
		{
			name: "md_all_subnets_acl_testing5",
			args: "report subnets --output-file acl_testing5_all_subnets.md -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format md",
		},
		{
			name: "json_all_subnets_acl_testing5",
			args: "report subnets --output-file acl_testing5_all_subnets.json -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format json",
		},

		// all_endpoints analysis_type
		{
			name: "txt_all_endpoints_acl_testing5",
			args: "report endpoints --output-file acl_testing5_all_endpoints.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format txt",
		},
		{
			name: "md_all_endpoints_acl_testing5",
			args: "report endpoints --output-file acl_testing5_all_endpoints.md -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format md",
		},
		{
			name: "json_all_endpoints_acl_testing5",
			args: "report endpoints --output-file acl_testing5_all_endpoints.json -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format json",
		},
		{
			name: "debug_all_endpoints_acl_testing5",
			args: "report endpoints --output-file acl_testing5_all_endpoints.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format debug",
		},

		// single_subnet analysis_type
		{
			name: "txt_single_subnet_acl_testing5",
			args: "report single-subnet --output-file acl_testing5_single_subnet.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --format txt",
		},

		// explain_mode analysis_type
		{
			name: "txt_explain_acl_testing3",
			args: "explain --output-file acl_testing3_explain.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --format txt --src 10.240.10.4 --dst vsi2-ky",
		},
		{
			name: "debug_explain_acl_testing3",
			args: "explain --output-file acl_testing3_explain_debug.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --format txt --src vsi2-ky --dst 10.240.10.4",
		},
		{
			name: "txt_explain_acl_testing3_3rd",
			args: "explain --output-file acl_testing3_3rd_explain.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3_3rd.json --format txt --src vsi1-ky --dst 161.26.0.0/16 --protocol tcp --src-min-port 5 --src-max-port 4398",
		},

		// specific vpc
		{
			name: "txt_specific_vpc_acl_testing3_with_two_vpcs",
			args: "report endpoints --output-file specific_vpc_acl_testing3_with_two_vpcs.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3_with_two_vpcs.json --format txt --vpc crn:12",
		},

		// version
		{
			name: "version",
			args: "--output-file version.txt --version",
		},

		// resource group and region filter
		{
			name: "txt_resource_group_filter_multi_resource_groups",
			args: "report endpoints --output-file multi_resource_groups_resource_group_filter.txt -c ../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json --format txt --resource-group ola",
		},
		{
			name: "txt_region_filter_multi_regions",
			args: "report endpoints --output-file multi_regions_region_filter.txt -c ../../pkg/ibmvpc/examples/input/input_multi_regions.json --format txt --region us-east",
		},
		// multi vpc configs input
		{
			name: "multi_vpc_configs",
			args: "report endpoints --output-file multi_vpc_configs.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -c ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
		},
		{
			name: "diff_with_different_uid",
			args: "diff endpoints --quiet --vpc-config ../../pkg/ibmvpc/examples/input/input_sg_testing_default.json --vpc-config-second ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
		},
		{
			name: "test_routing_cmd",
			args: "report routing --vpc-config ../../pkg/ibmvpc/examples/input/input_hub_n_spoke_1.json",
		},

		// read from account // need to export api-key first
		/*{
			name: "read_from_account_mode",
			args: "report endpoints --output-file account.txt --provider ibm --resource-group ola",
		},
		{
			name: "read_from_account_mode_dump_resources",
			args: "report endpoints --output-file account.txt --provider ibm --dump-resources account_resources_file.json",
		},*/
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
			args:    "report endpoints --output-file multi_vpc_configs.txt --vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --vpc-config ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
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
			args:                  []string{"report", "endpoints", "--output-file", "out.txt", "vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "unknown command",
		},
		{
			name:                  "missing_arg_flag",
			args:                  []string{"report", "endpoints", "--output-file", "out.txt", "--vpc-config"},
			expectedErrorContains: "flag needs an argument",
		},
		{
			name:                  "vpc_config_or_provider_not_specified",
			args:                  []string{"report", "endpoints", "--output-file", "out.txt"},
			expectedErrorContains: "at least one of the flags in the group",
		},
		{
			name:                  "wrong_analysis_type_format",
			args:                  []string{"report", "single-subnet", "--vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json", "--format", "md"},
			expectedErrorContains: "output format for single-subnet must be one of [txt]",
		},
		{
			name:                  "src_and_dst_not_specified_for_explain_mode",
			args:                  []string{"explain", "--vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "required flag(s) \"src\", \"dst\" not set",
		},
		{
			name:                  "missing_sec_vpc_config_for_diff_analysis",
			args:                  []string{"diff", "subnets", "--vpc-config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "required flag(s) \"vpc-config-second\" not set",
		},
		{
			name:                  "nacls_split_subnets",
			args:                  []string{"report", "subnets", "--vpc-config", "../../pkg/ibmvpc/examples/input/input_split_subnet.json"},
			expectedErrorContains: "partial subnet ranges",
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
