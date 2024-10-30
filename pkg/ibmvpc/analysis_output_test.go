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

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc/testfunc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

/*
tests for the entire flow:
	- input from config json file
	- output comparison, for the possible output use-cases
	- currently comparing only txt output formats
*/

const analysisOut = "analysis_out"

var tests = []*testfunc.VpcAnalysisTest{
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5_old",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5_old",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing5",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	// batch1: cover all use-cases, with text output Format , no Grouping
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			// TODO: currently skipping uc3 since it is not supported with partial subnet connectivity
			UseCases: []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet},
			Format:   vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tg-prefix-filters",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.SingleSubnet, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing_3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing_3_with_empty_remote",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
	},

	// batch2: only vsi-level use-case, with Grouping , text Format
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	// respond enabled only on part of the TCP connection
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new_respond_partly",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},

	// batch2.5: only vsi-level use-case, with Grouping , drawio Format
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_config_object",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "mult_NIs_single_VSI",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},

	//batch3: only vsi-level use-case, no Grouping, with md output formats
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.MD,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
	},

	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.ARCHDRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.ARCHDRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.ARCHDRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new_grouping",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	// iks-nodes example
	// iks_config_object example has three SG, one of them two targets - a pgw and a LB.
	// this SG has four rules, which are reflected at the connectivity map:
	// 1. outbound, tcp, ports 30000-32767
	// 2. outbound, udp, ports 30000-32767
	// 3. inbound, udp, ports 1-65535
	// 4. inbound, udp, ports 1-65535

	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_config_object",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_config_object",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	// json examples
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.JSON,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.JSON,
		},
	},
	// multi-vpc config example
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "acl_testing3_with_two_vpcs",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
			VpcList:     []string{"crn:12"}, // specify the vpc to analyze
		},
	},
	// vpe example
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "demo_with_instances_vpes",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
	},
	// multi-vpc config examples
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "experiments_env",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "experiments_env",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
			VpcList:     []string{"crn:1", "crn:17"},
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "experiments_env",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.JSON,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "multiple_vpcs",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	// tgw examples
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_basic_example",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_basic_example_multiple_regions",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_basic_example_with_some_default_deny",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_larger_example",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_larger_example",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},

	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tg-prefix-filters",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
	},
	// tgw examples with drawio
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_larger_example",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.HTML,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "tgw_larger_example",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	// multivpc drawio:
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "multiple_vpcs",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.DRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "multiple_vpcs",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "experiments_env",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.ARCHDRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "experiments_env",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	// resource group filtering example
	// ete-storage-project and ete-backup-and-storage vpcs expected to be filtered out
	// global-tg-ky and local-tg-ky tgws expected to be filtered out
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig:   "multi_resource_groups",
			UseCases:      []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:        vpcmodel.Text,
			ResourceGroup: "ola",
		},
	},
	// region filtering example
	// zn-vpc1, zn-vpc2, zn-vpc3 expected to be filtered out
	// global-tg-zn and local-tg-zn tgws expected to be filtered out
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "multi_regions",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
			Regions:     []string{"us-east"},
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.DRAWIO,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.ARCHSVG,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},

	// Grouping test of identical names different resources and thus different UIDs that should not be merged
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new_dup_subnets_names",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_workers_large",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.DRAWIO,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	// LB examples:
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "lb_bad_practice",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "lb_bad_practice",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_w_lb",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "lb_policies",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "load_balancer",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints, vpcmodel.AllSubnets},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "load_balancer",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "load_balancer",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "nacl_split_subnet",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
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
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "filters_split_lb_subnet",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "filters_split_lb_subnet",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "filters_split_lb_subnet",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "hub_n_spoke_1",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "hub_n_spoke_1",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "fabricated",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "vni_basic",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "vni_basic",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingNoConsistencyEdges,
	},
	// tests for AddConsistencyEdgesExternal
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.NoGroupingWithConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.NoGroupingWithConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingWithConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "sg_testing1_new",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingWithConsistencyEdges,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_config_object",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.Text,
		},
		GroupingType: vpcmodel.GroupingWithConsistencyEdges,
		NoLbAbstract: true,
	},
	{
		VpcTestCommon: testfunc.VpcTestCommon{
			InputConfig: "iks_config_object",
			UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllEndpoints},
			Format:      vpcmodel.HTML,
		},
		GroupingType: vpcmodel.GroupingWithConsistencyEdges,
		NoLbAbstract: true,
	},
}

// uncomment the function below to run for updating the expected output

/*func TestReportWithGeneration(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		tt.TestAnalysisSingleTest(t, testfunc.OutputGeneration, &IBMresourcesContainer{}, analysisOut, tt.InputConfig)
	}
	fmt.Println("done")
}*/

func TestReportWithComparison(t *testing.T) {
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		tt.TestAnalysisSingleTest(t, testfunc.OutputComparison, &IBMresourcesContainer{}, analysisOut, tt.InputConfig)
	}
	fmt.Println("done")
}

// TestUnsupportedAnalysis demonstrates cases where analysis is not supported
func TestUnsupportedAnalysis(t *testing.T) {
	tests := []*testfunc.VpcAnalysisTest{
		{
			// here the connectivity per subnet is getting split to few parts by various local ranges within the subnet cidr,
			// and the split is by the ACL's rules "local" part (e.g. "from" in egress rule / "to" in ingress rule)
			VpcTestCommon: testfunc.VpcTestCommon{
				Name:        "unsupported_analysis_acl_testing3",
				InputConfig: "acl_testing3",
				UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
				Format:      vpcmodel.Text,
				ErrPerUseCase: map[vpcmodel.OutputUseCase]error{
					vpcmodel.AllSubnets: errors.New("unsupported connectivity map with partial subnet ranges per connectivity result"),
				},
				Mode: testfunc.OutputGeneration,
			},
		},
		{
			// here the split is by  ACL's rules "remote" part (e.g. "to" in egress rule / "from" in ingress rule)
			VpcTestCommon: testfunc.VpcTestCommon{
				Name:        "unsupported_nacl_split_subnet",
				InputConfig: "nacl_split_subnet",
				UseCases:    []vpcmodel.OutputUseCase{vpcmodel.AllSubnets},
				Format:      vpcmodel.Text,
				ErrPerUseCase: map[vpcmodel.OutputUseCase]error{
					vpcmodel.AllSubnets: errors.New("unsupported subnets connectivity analysis - no consistent connectivity for entire subnet sub1"),
				},
				Mode: testfunc.OutputGeneration,
			},
		},
	}
	// tests is the list of tests to run
	for testIdx := range tests {
		tt := tests[testIdx]
		tt.TestAnalysisSingleTest(t, tt.Mode, &IBMresourcesContainer{}, analysisOut, tt.Name)
	}
	fmt.Println("done")
}
