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
		{"drawio_multi_vpc", "-output-file aaa.drawio -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format drawio"},
		{"txt_multi_vpc", "-output-file aaa.txt -vpc-config ../../pkg/ibmvpc/examples/input_multiple_vpcs.json -format txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := _main(strings.Split(tt.args, " ")); err != nil {
				t.Errorf("_main(), name %s, error = %v", tt.name, err)
			}
		})
	}
}
