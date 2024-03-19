//nolint:lll // styles are too long and can not be split
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TODO: this file need to be rewritten
func TestMain(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{"drawio_multi_vpc_all_subnets", "-output-file multi_vpc.drawio -vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -format drawio -analysis-type all_subnets"},
		{"drawio_multi_vpc_all_subnets_grouped", "-output-file multi_vpc_grouped.drawio -vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -format drawio -analysis-type all_subnets -grouping"},
		{"txt_multi_vpc", "-output-file multi_vpc.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_multiple_vpcs.json -format txt -analysis-type all_subnets"},
		// {"json_diff_acl_testing5", "-output-file acl_testing5_diff.json -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing5_2nd.json -format json -analysis-type diff_all_subnets"},

		// diff analysis_type
		{"txt_diff_acl_testing5", "-output-file acl_testing5_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json -format txt -analysis-type diff_all_subnets"},
		{"txt_diff_acl_testing3", "-output-file acl_testing3_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json -format txt -analysis-type diff_all_endpoints"},
		{"md_diff_acl_testing5", "-output-file acl_testing5_diff.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing5_2nd.json -format md -analysis-type diff_all_subnets"},
		{"md_diff_acl_testing3", "-output-file acl_testing3_diff.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -vpc-config-second ../../pkg/ibmvpc/examples/input/input_acl_testing3_2nd.json -format md -analysis-type diff_all_endpoints"},

		// all_subnets analysis_type
		{"txt_all_subnets_342", "-output-file 342_all_subnets.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_obj_from_issue_342.json -format txt -analysis-type all_subnets"},
		{"txt_all_subnets_acl_testing5", "-output-file acl_testing5_all_subnets.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format txt -analysis-type all_subnets"},
		{"md_all_subnets_acl_testing5", "-output-file acl_testing5_all_subnets.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format md -analysis-type all_subnets"},
		{"json_all_subnets_acl_testing5", "-output-file acl_testing5_all_subnets.json -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format json -analysis-type all_subnets"},

		// all_endpoints analysis_type
		{"txt_all_endpoints_acl_testing5", "-output-file acl_testing5_all_endpoints.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format txt -analysis-type all_endpoints"},
		{"md_all_endpoints_acl_testing5", "-output-file acl_testing5_all_endpoints.md -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format md -analysis-type all_endpoints"},
		{"json_all_endpoints_acl_testing5", "-output-file acl_testing5_all_endpoints.json -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format json -analysis-type all_endpoints"},
		{"debug_all_endpoints_acl_testing5", "-output-file acl_testing5_all_endpoints.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format debug -analysis-type all_endpoints"},

		// single_subnet analysis_type
		{"txt_single_subnet_acl_testing5", "-output-file acl_testing5_single_subnet.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing5.json -format txt -analysis-type single_subnet"},

		// explain_mode analysis_type
		{"txt_explain_acl_testing3", "-output-file acl_testing3_explain.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -format txt -analysis-type explain -src 10.240.10.4 -dst vsi2-ky"},
		{"debug_explain_acl_testing3", "-output-file acl_testing3_explain_debug.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3.json -format txt -analysis-type explain -src vsi2-ky -dst 10.240.10.4"},
		{"txt_explain_acl_testing3_3rd", "-output-file acl_testing3_3rd_explain.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3_3rd.json -format txt -analysis-type explain -src vsi1-ky -dst 161.26.0.0/16 -protocol tcp -src-min-port 5 -src-max-port 4398"},

		// specific vpc
		{"txt_specific_vpc_acl_testing3_with_two_vpcs", "-output-file specific_vpc_acl_testing3_with_two_vpcs.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_acl_testing3_with_two_vpcs.json -format txt -vpc crn:12"},

		// version
		{"version", "-output-file version.txt -version"},

		// read from account // need to export api-key first
		// {"read_from_account_mode", "-output-file account.txt -provider ibm -resource-group ola"},
		// {"read_from_account_mode_dump_resources", "-output-file account.txt -provider ibm -dump-resources account_resources_file.json"},

		// resource group and region filter
		{"txt_resource_group_filter_multi_resource_groups", "-output-file multi_resource_groups_resource_group_filter.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_multi_resource_groups.json -format txt -resource-group ola"},
		{"txt_region_filter_multi_regions", "-output-file multi_regions_region_filter.txt -vpc-config ../../pkg/ibmvpc/examples/input/input_multi_regions.json -format txt -region us-east"},
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
