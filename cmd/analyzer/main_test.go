package main

import (
	"strings"
	"testing"
)

func Test_main(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{"drawio_multi_vpc_all_subnets", "-output-file multi_vpc.drawio -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format drawio -analysis-type all_subnets"},
		{"drawio_multi_vpc_all_subnets_grouped", "-output-file multi_vpc_grouped.drawio -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format drawio -analysis-type all_subnets -grouping"},
		{"txt_multi_vpc", "-output-file multi_vpc.txt -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format txt -analysis-type all_subnets"},
		{"json_diff_acl_testing5", "-output-file acl_testing5_diff.json -vpc-config ../../pkg/ibmvpc/examples/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing5_2nd.json -format json -analysis-type diff_all_subnets"},
		{"txt_diff_acl_testing5", "-output-file acl_testing5_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing5_2nd.json -format txt -analysis-type diff_all_subnets"},
		{"txt_diff_acl_testing3", "-output-file acl_testing3_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input_acl_testing3.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing3_2nd.json -format txt -analysis-type diff_all_endpoints"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := _main(strings.Split(tt.args, " ")); err != nil {
				t.Errorf("_main(), name %s, error = %v", tt.name, err)
			}
		})
	}
}
