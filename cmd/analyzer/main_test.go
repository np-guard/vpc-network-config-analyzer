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
		{"drawio_multi_vpc_all_subnets", "-output-file multi_vpc.drawio -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format drawio -analysis-type all_subnets"},
		{"drawio_multi_vpc_all_subnets_grouped", "-output-file multi_vpc_grouped.drawio -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format drawio -analysis-type all_subnets -grouping"},
		{"txt_multi_vpc", "-output-file multi_vpc.txt -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format txt -analysis-type all_subnets"},
		// {"json_diff_acl_testing5", "-output-file acl_testing5_diff.json -vpc-config ../../pkg/ibmvpc/examples/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing5_2nd.json -format json -analysis-type diff_all_subnets"},
		{"txt_diff_acl_testing5", "-output-file acl_testing5_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input_acl_testing5.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing5_2nd.json -format txt -analysis-type diff_all_subnets"},
		{"txt_diff_acl_testing3", "-output-file acl_testing3_diff.txt -vpc-config ../../pkg/ibmvpc/examples/input_acl_testing3.json -vpc-config-second ../../pkg/ibmvpc/examples/input_acl_testing3_2nd.json -format txt -analysis-type diff_all_endpoints"},
		{"txt_all_subnets_342", "-output-file 342_all_subnets.txt -vpc-config ../../pkg/ibmvpc/examples/input_obj_from_issue_342.json -format txt -analysis-type all_subnets"},
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
	if err1 != nil || err2 != nil {
		panic(errors.Join(err1, err2))
	}
	for _, f := range append(files1, files2...) {
		if err := os.Remove(f); err != nil {
			panic(err)
		}
	}
}
