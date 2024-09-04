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
		// aws
		{
			name: "aws_all_endpoints",
			args: "report endpoints -f aws.txt -c ../../pkg/awsvpc/examples/input/input_basic_config_with_sg.json -o txt",
		},
		{
			name: "aws_all_subnets",
			args: "report subnets -f aws.txt -c ../../pkg/awsvpc/examples/input/input_aws_acl_1.json -o txt",
		},
		// drawio
		{
			name: "drawio_multi_vpc_all_subnets",
			args: "report subnets -f multi_vpc.drawio --config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -o drawio",
		},
		{
			name: "drawio_multi_vpc_all_subnets_grouped",
			args: "report subnets -f multi_vpc_grouped.drawio -c ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -o=drawio --grouping",
		},
		{
			name: "txt_multi_vpc",
			args: "report subnets -f multi_vpc.txt --config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -o txt",
		},

		// diff analysis_type
		{
			name: "txt_diff_acl_testing5",
			args: "diff subnets -f acl_testing5_diff.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json -o txt",
		},
		{
			name: "txt_diff_acl_testing3",
			args: "diff endpoints -f acl_testing3_diff.txt --config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json -o txt",
		},
		{
			name: "md_diff_acl_testing5",
			args: "diff subnets -f acl_testing5_diff.md --config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json --config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json -o md",
		},
		{
			name: "md_diff_acl_testing3",
			args: "diff endpoints -f acl_testing3_diff.md --config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json -o md",
		},

		// all_subnets analysis_type
		{
			name: "txt_all_subnets_342",
			args: "report subnets -f 342_all_subnets.txt -c ../../pkg/ibmvpc/examples/input/input_obj_from_issue_342.json -o txt",
		},
		{
			name: "txt_all_subnets_acl_testing5",
			args: "report subnets -f acl_testing5_all_subnets.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o txt",
		},
		{
			name: "md_all_subnets_acl_testing5",
			args: "report subnets -f acl_testing5_all_subnets.md -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o md",
		},
		{
			name: "json_all_subnets_acl_testing5",
			args: "report subnets -f acl_testing5_all_subnets.json -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o json",
		},

		// all_endpoints analysis_type
		{
			name: "txt_all_endpoints_acl_testing5",
			args: "report endpoints -f acl_testing5_all_endpoints.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o txt",
		},
		{
			name: "md_all_endpoints_acl_testing5",
			args: "report endpoints -f acl_testing5_all_endpoints.md -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o md",
		},
		{
			name: "json_all_endpoints_acl_testing5",
			args: "report endpoints -f acl_testing5_all_endpoints.json -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o json",
		},

		// single_subnet analysis_type
		{
			name: "txt_single_subnet_acl_testing5",
			args: "report single-subnet -f acl_testing5_single_subnet.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -o txt",
		},

		// explain_mode analysis_type
		{
			name: "txt_explain_acl_testing3",
			args: "explain -f acl_testing3_explain.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -o txt --src 10.240.10.4 --dst vsi2-ky",
		},
		{
			name: "detailed_explain_acl_testing3",
			args: "explain -f acl_testing3_explain_detailed.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -o txt --src vsi2-ky --dst 10.240.10.4",
		},
		{
			name: "txt_explain_acl_testing3_3rd",
			args: "explain -f acl_testing3_3rd_explain.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3_3rd.json -o txt --src vsi1-ky --dst 161.26.0.0/16 --protocol tcp --src-min-port 5 --src-max-port 4398",
		},

		// specific vpc
		{
			name: "txt_specific_vpc_acl_testing3_with_two_vpcs",
			args: "report endpoints -f specific_vpc_acl_testing3_with_two_vpcs.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3_with_two_vpcs.json -o txt --vpc crn:12",
		},

		// version
		{
			name: "version",
			args: "-f version.txt --version",
		},
		// help
		{
			name: "help",
			args: "report -h",
		},
		{
			name: "help-sub",
			args: "report endpoints -h",
		},
		// resource group and region filter
		{
			name: "txt_resource_group_filter_multi_resource_groups",
			args: "report endpoints -f multi_resource_groups_resource_group_filter.txt -c ../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json -o txt --resource-group ola",
		},
		{
			name: "txt_region_filter_multi_regions",
			args: "report endpoints -f multi_regions_region_filter.txt -c ../../pkg/ibmvpc/examples/input/input_multi_regions.json -o txt --region us-east",
		},
		// multi vpc configs input
		{
			name: "multi_vpc_configs",
			args: "report endpoints -f multi_vpc_configs.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -c ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
		},
		{
			name: "diff_with_different_uid",
			args: "diff endpoints --quiet --config ../../pkg/ibmvpc/examples/input/input_sg_testing_default.json --config-second ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
		},
		{
			name: "test_routing_cmd",
			args: "report routing --config ../../pkg/ibmvpc/examples/input/input_hub_n_spoke_1.json",
		},

		// read from account // need to export api-key first
		/*{
			name: "read_from_account_mode",
			args: "report endpoints -f account.txt --provider ibm --resource-group ola",
		},
		{
			name: "read_from_account_mode_dump_resources",
			args: "report endpoints -f account.txt --provider ibm --dump-resources account_resources_file.json",
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
		args    string // must include filename arg
		outFile string // must be as in the command line arg filename
	}{
		// multi vpc configs input
		{
			name:    "multi_vpc_configs",
			args:    "report endpoints -f multi_vpc_configs.txt --config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json --config ../../pkg/ibmvpc/examples/input/input_sg_testing_3.json",
			outFile: "multi_vpc_configs.txt",
		},
		// non abstracted load balancer
		{
			name:    "non_abstracted_load_balancer",
			args:    "report endpoints -f non_abstracted_load_balancer.txt --load-balancer-abstraction=false --config ../../pkg/ibmvpc/examples/input/input_load_balancer.json --grouping",
			outFile: "non_abstracted_load_balancer.txt",
		},
		// detail explanation
		{
			name:    "txt_explain_acl_testing3",
			args:    "explain -f acl_testing3_detailed_explain.txt -c ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -o txt --src 10.240.10.4 --dst vsi2-ky --detail",
			outFile: "acl_testing3_detailed_explain.txt",
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
			args:                  []string{"report", "endpoints", "-f", "out.txt", "config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "unknown command",
		},
		{
			name:                  "missing_arg_flag",
			args:                  []string{"report", "endpoints", "-f", "out.txt", "--config"},
			expectedErrorContains: "flag needs an argument",
		},
		{
			name:                  "vpc_config_or_provider_not_specified",
			args:                  []string{"report", "endpoints", "-f", "out.txt"},
			expectedErrorContains: "at least one of the flags in the group",
		},
		{
			name:                  "wrong_analysis_type_format",
			args:                  []string{"report", "single-subnet", "--config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json", "-o", "md"},
			expectedErrorContains: "output format for single-subnet must be one of [txt]",
		},
		{
			name:                  "src_and_dst_not_specified_for_explain_mode",
			args:                  []string{"explain", "--config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "required flag(s) \"src\", \"dst\" not set",
		},
		{
			name:                  "missing_sec_vpc_config_for_diff_analysis",
			args:                  []string{"diff", "subnets", "--config", "../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json"},
			expectedErrorContains: "required flag(s) \"config-second\" not set",
		},
		{
			name:                  "nacls_split_subnets",
			args:                  []string{"report", "subnets", "--config", "../../pkg/ibmvpc/examples/input/input_split_subnet.json"},
			expectedErrorContains: "partial subnet ranges",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := _main(tt.args)
			require.Contains(t, err.Error(), tt.expectedErrorContains,
				"error mismatch for test %q, actual: %q, expected contains: %q", tt.name, err.Error(), tt.expectedErrorContains)
		})
	}
}
