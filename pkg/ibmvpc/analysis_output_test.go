/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	_ "embed"
	"errors"
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

/*
tests for the entire flow:
	- input from config json file
	- output comparison, for the possible output use-cases
	- currently comparing only txt output formats
*/

const analysisOut = "analysis_out"

var tests = []*commonvpc.VpcGeneralTest{
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "acl_testing5_old",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "acl_testing5_old",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	// batch1: cover all use-cases, with text output Format , no Grouping
	{
		InputConfig: "acl_testing3",
		// TODO: currently skipping uc3 since it is not supported with partial subnet connectivity
		UseCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet},
		Format:   vpcmodel.Text,
	},
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig: "tg-prefix-filters",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "sg_testing_3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "sg_testing_3_with_empty_remote",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
	},

	// batch2: only vsi-level use-case, with Grouping , text Format
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	// respond enabled only on part of the TCP connection
	{
		InputConfig: "sg_testing1_new_respond_partly",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},

	// batch2.5: only vsi-level use-case, with Grouping , drawio Format
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "iks_config_object",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "mult_NIs_single_VSI",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},

	//batch3: only vsi-level use-case, no Grouping, with md output formats
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.DRAWIO,
	},

	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.ARCHDRAWIO,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.ARCHDRAWIO,
	},
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.ARCHDRAWIO,
	},
	{
		InputConfig: "sg_testing1_new_grouping",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	// iks-nodes example
	// iks_config_object example has three SG, one of them two targets - a pgw and a LB.
	// this SG has four rules, which are reflected at the connectivity map:
	// 1. outbound, tcp, ports 30000-32767
	// 2. outbound, udp, ports 30000-32767
	// 3. inbound, udp, ports 1-65535
	// 4. inbound, udp, ports 1-65535

	{
		InputConfig: "iks_config_object",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig:  "iks_config_object",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:     true,
		NoLbAbstract: true,
		Format:       vpcmodel.Text,
	},
	// json examples
	{
		InputConfig: "demo_with_instances",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.JSON,
	},
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.JSON,
	},
	// multi-vpc config example
	{
		InputConfig: "acl_testing3_with_two_vpcs",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
		VpcList:     []string{"crn:12"}, // specify the vpc to analyze
	},
	// vpe example
	{
		InputConfig: "demo_with_instances_vpes",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
	},
	// multi-vpc config examples
	{
		InputConfig: "experiments_env",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "experiments_env",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
		VpcList:     []string{"crn:1", "crn:17"},
	},
	{
		InputConfig: "experiments_env",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.JSON,
	},
	{
		InputConfig: "multiple_vpcs",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	// diff examples:
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "acl_testing5",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.SubnetsDiff},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "acl_testing3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.MD,
	},
	{
		InputConfig: "sg_testing1_new",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.Text,
	},
	{ // example with diff with partial TCP respond
		InputConfig: "sg_testing1_copy",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.Text,
	},
	{ // example with diff in which the diff is in the amount of TCP respond enabled
		InputConfig: "sg_testing1_new_respond_partly",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.Text,
	},
	{
		// diff between VPCs of different UIDs
		InputConfig: "sg_testing_3",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.Text,
	},
	{
		// diff between identical VPCs
		InputConfig: "sg_testing_default",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.EndpointsDiff},
		Format:      vpcmodel.Text,
	},
	// tgw examples
	{
		InputConfig: "tgw_basic_example",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "tgw_basic_example_multiple_regions",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "tgw_basic_example_with_some_default_deny",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "tgw_larger_example",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "tgw_larger_example",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
		Grouping:    true,
	},

	{
		InputConfig: "tg-prefix-filters",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.Text,
	},
	// tgw examples with drawio
	{
		InputConfig: "tgw_larger_example",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "tgw_larger_example",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Format:      vpcmodel.DRAWIO,
		Grouping:    true,
	},
	// multivpc drawio:
	{
		InputConfig: "multiple_vpcs",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "multiple_vpcs",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "experiments_env",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.ARCHDRAWIO,
	},
	{
		InputConfig: "experiments_env",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	// resource group filtering example
	// ete-storage-project and ete-backup-and-storage vpcs expected to be filtered out
	// global-tg-ky and local-tg-ky tgws expected to be filtered out
	{
		InputConfig:   "multi_resource_groups",
		UseCases:      []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:        vpcmodel.Text,
		ResourceGroup: "ola",
	},
	// region filtering example
	// zn-vpc1, zn-vpc2, zn-vpc3 expected to be filtered out
	// global-tg-zn and local-tg-zn tgws expected to be filtered out
	{
		InputConfig: "multi_regions",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
		Regions:     []string{"us-east"},
	},
	{
		InputConfig: "iks_workers_large",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "iks_workers_large",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Grouping:    false,
		Format:      vpcmodel.DRAWIO,
	},
	{
		InputConfig: "iks_workers_large",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Grouping:    true,
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig: "iks_workers_large",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.ARCHSVG,
	},
	{
		InputConfig: "iks_workers_large",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.DRAWIO,
	},
	// Grouping test of identical names different resources and thus different UIDs that should not be merged
	{
		InputConfig: "sg_testing1_new_dup_subnets_names",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig:  "iks_workers_large",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:     true,
		NoLbAbstract: true,
		Format:       vpcmodel.HTML,
	},
	// todo: before merge - this fails sometimes in git. understand why and have fixed (seems in Haim's areas).
	{
		InputConfig:  "iks_workers_large",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:     true,
		NoLbAbstract: true,
		Format:       vpcmodel.DRAWIO,
	},
	// LB examples:
	{
		InputConfig: "lb_bad_practice",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "lb_bad_practice",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
	},
	{
		InputConfig: "iks_w_lb",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig: "lb_policies",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.HTML,
	},
	{
		InputConfig:  "load_balancer",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
		Grouping:     true,
		NoLbAbstract: true,
		Format:       vpcmodel.HTML,
	},
	{
		InputConfig: "load_balancer",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig:  "load_balancer",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:     true,
		NoLbAbstract: true,
		Format:       vpcmodel.Text,
	},
	{
		InputConfig: "nacl_split_subnet",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
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
		InputConfig:  "filters_split_lb_subnet",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:       vpcmodel.Text,
		Grouping:     false,
		NoLbAbstract: true,
	},
	{
		InputConfig: "filters_split_lb_subnet",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:      vpcmodel.Text,
		Grouping:    false,
	},
	{
		InputConfig:  "filters_split_lb_subnet",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:       vpcmodel.HTML,
		Grouping:     true,
		NoLbAbstract: true,
	},
	{
		InputConfig: "hub_n_spoke_1",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Grouping:    true,
		Format:      vpcmodel.Text,
	},
	{
		InputConfig:  "hub_n_spoke_1",
		UseCases:     []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
		Format:       vpcmodel.HTML,
		Grouping:     true,
		NoLbAbstract: true,
	},
	{
		InputConfig: "fabricated",
		UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
		Format:      vpcmodel.HTML,
		Grouping:    true,
	},
}

// uncomment the function below to run for updating the expected output
/*
func TestAllWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		commonvpc.TestAll(tt, t, commonvpc.OutputGeneration, &IBMresourcesContainer{}, analysisOut, tt.InputConfig)
	}
	fmt.Println("done")
}
*/
func TestAllWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		commonvpc.TestAll(tt, t, commonvpc.OutputComparison, &IBMresourcesContainer{}, analysisOut, tt.InputConfig)
	}
	fmt.Println("done")
}

// TestUnsupportedAnalysis demonstrates cases where analysis is not supported
func TestUnsupportedAnalysis(t *testing.T) {
	tests := []*commonvpc.VpcGeneralTest{
		{
			// here the connectivity per subnet is getting split to few parts by various local ranges within the subnet cidr,
			// and the split is by the ACL's rules "local" part (e.g. "from" in egress rule / "to" in ingress rule)
			Name:        "unsupported_analysis_acl_testing3",
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
			ErrPerUseCase: map[vpcmodel.OutputUseCase]error{
				vpcmodel.AllSubnets: errors.New("unsupported connectivity map with partial subnet ranges per connectivity result"),
			},
			Mode: commonvpc.OutputGeneration,
		},
		{
			// here the split is by  ACL's rules "remote" part (e.g. "to" in egress rule / "from" in ingress rule)
			Name:        "unsupported_nacl_split_subnet",
			InputConfig: "nacl_split_subnet",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
			ErrPerUseCase: map[vpcmodel.OutputUseCase]error{
				vpcmodel.AllSubnets: errors.New("unsupported subnets connectivity analysis - no consistent connectivity for entire subnet sub1"),
			},
			Mode: commonvpc.OutputGeneration,
		},
	}
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		commonvpc.TestAll(tt, t, tt.Mode, &IBMresourcesContainer{}, analysisOut, tt.Name)
	}
	fmt.Println("done")
}
