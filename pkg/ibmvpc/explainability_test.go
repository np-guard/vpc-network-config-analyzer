/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const explainOut = "explain_out"

// getConfigs returns  *vpcmodel.MultipleVPCConfigs obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) *vpcmodel.MultipleVPCConfigs {
	inputConfigFile := filepath.Join(getTestsDirInput(), inputFilePrefix+fileName+jsonOutSuffix)
	rc := IBMresourcesContainer{}
	err := rc.ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := rc.VPCConfigsFromResources("", "", nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return vpcConfigs
}

var explainTests = []*vpcGeneralTest{
	{
		name:          "VsiToVsi1",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi2-ky",
		EDst:          "vsi3b-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "VsiToVsi2",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi2-ky",
		EDst:          "10.240.10.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "VsiToVsi3",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi3a-ky",
		EDst:          "10.240.10.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "VsiToVsi4",
		inputConfig:   "sg_testing1_new",
		ESrc:          "10.240.10.4",
		EDst:          "10.240.20.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "VsiToVsi5",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi2-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "SimpleExternalSG1",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:        "SimpleExternalSG2",
		inputConfig: "sg_testing1_new",
		ESrc:        "161.26.0.0/16",
		EDst:        "vsi1-ky",
		format:      vpcmodel.Text,
	},
	{
		name:          "SimpleExternalSG3",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/32",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:        "SimpleExternalSG4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3b-ky",
		EDst:        "161.26.0.0/32",
		format:      vpcmodel.Text,
	},
	{
		name:          "GroupingExternalSG1",
		inputConfig:   "sg_testing1_new",
		ESrc:          "10.240.10.4",
		EDst:          "161.26.0.0/8",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:        "GroupingExternalSG1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/8",
		format:      vpcmodel.Text,
	},
	{
		// the existing connection is exactly the one required by the query
		name:          "QueryConnectionSGBasic1",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// the required connection is contained in the existing one per connection
	{
		name:          "QueryConnectionSGBasic2",
		inputConfig:   "sg_testing1_new",
		ESrc:          "10.240.10.4",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   10,
		ESrcMaxPort:   100,
		EDstMinPort:   443,
		EDstMaxPort:   443,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	//  the required connection is contained in the existing one per ip of src/dst
	{
		name:          "QueryConnectionSGBasic3",
		inputConfig:   "sg_testing1_new",
		ESrc:          "crn:v1:staging:public:is:us-south:a/6527::vpc:a456", // crn:v1:staging:public:is:us-south:a/6527::vpc:a456 is vsi1-ky
		EDst:          "161.26.0.0/20",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   10,
		ESrcMaxPort:   100,
		EDstMinPort:   443,
		EDstMaxPort:   443,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// the required connection exists for part of the dst ip
	{
		name:          "QueryConnectionSGBasic4",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/12",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   10,
		ESrcMaxPort:   100,
		EDstMinPort:   443,
		EDstMaxPort:   443,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// a connection does not exist regardless of the query
	{
		name:          "QueryConnectionSGBasic5",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi1-ky",
		EDst:          "vsi3a-ky",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   10,
		ESrcMaxPort:   100,
		EDstMinPort:   443,
		EDstMaxPort:   443,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// a subset of the required ports exists
	{
		name:          "QueryConnectionSGSubsetPorts",
		inputConfig:   "sg_testing1_new",
		ESrc:          "147.235.219.206/32",
		EDst:          "vsi2-ky",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   10,
		EDstMaxPort:   30,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	//  all rules are relevant (for comparison)
	{
		name:          "QueryConnectionSGRules1",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// only a subset of the rules are relevant, protocol wise
	{
		name:          "QueryConnectionSGRules2",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// only a subset of the rules are relevant, port wise and protocol wise
	{
		name:          "QueryConnectionSGRules3",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   50,
		EDstMaxPort:   54,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	//  all rules are relevant, with specified port wise protocol
	{
		name:          "QueryConnectionSGRules4",
		inputConfig:   "sg_testing1_new",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   120,
		EDstMaxPort:   230,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// connection exists to external
	{
		name:          "NACLExternal1",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// connection does not exist to external, blocked by egress
	{
		name:          "NACLExternal2",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi1-ky",
		EDst:          "100.128.0.0/32",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// connection does not exist to external, no fip router
	{
		name:        "NACLExternal3",
		inputConfig: "acl_testing3",
		ESrc:        "100.128.0.0/32",
		EDst:        "vsi1-ky",
		format:      vpcmodel.Text,
	},
	{
		name:          "NACLInternal1",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi1-ky",
		EDst:          "10.240.20.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:        "NACLInternal1",
		inputConfig: "acl_testing3",
		ESrc:        "10.240.10.4",
		EDst:        "vsi2-ky",
		format:      vpcmodel.Text,
	},
	{
		name:          "NACLInternal2",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi2-ky",
		EDst:          "10.240.10.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "NACLInternal3",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi1-ky",
		EDst:          "vsi3a-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		// same subnet: no actual rules in nacl, but connection enabled
		name:          "NACLInternal4",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi3b-ky",
		EDst:          "vsi3a-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "NACLGrouping",
		inputConfig:   "acl_testing3",
		ESrc:          "10.240.10.4",
		EDst:          "161.26.0.0/15",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "NACLQueryConnection1",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "NACLQueryConnection2",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// src: one of these network interfaces, dst: internal address of 4 network interfaces
	{
		name:          "NACLInternalSrcTo4DstInternal",
		inputConfig:   "acl_testing3",
		ESrc:          "vsi3b-ky",
		EDst:          "10.240.30.4/26",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// src: internal address of 5 network interfaces, dst: external address that spans rules
	// "many to many"
	{
		name:          "SGInternal3SrcToExternalGroup",
		inputConfig:   "sg_testing1_new",
		ESrc:          "10.240.30.4/24",
		EDst:          "161.26.0.0/8",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// all rules
	{
		name:          "NACLQueryConnectionRules2",
		inputConfig:   "acl_testing3_3rd",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// without the udp rule
	{
		name:          "NACLQueryConnectionRules3",
		inputConfig:   "acl_testing3_3rd",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// without the "all" rule since udp rule has higher priority
	{
		name:          "NACLQueryConnectionRules4",
		inputConfig:   "acl_testing3_3rd",
		ESrc:          "10.240.10.4/32",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "NACLOnlyDenyNoConnQuery",
		inputConfig:   "acl_testing3_3rd",
		ESrc:          "vsi1-ky",
		EDst:          "vsi2-ky",
		EProtocol:     netp.ProtocolStringICMP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// allow connection subset of the queried one
	{
		name:          "NACLQueryAllowSubset",
		inputConfig:   "acl_testing3_4th",
		ESrc:          "vsi1-ky",
		EDst:          "161.26.0.0/16",
		EProtocol:     netp.ProtocolStringUDP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// two SGs attached to one VSI
	{
		name:          "VsiWithTwoSgs",
		inputConfig:   "sg_testing1_new_2SGs",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// respond enabled only on part of the TCP connection
	{
		name:          "PartialTCPRespond",
		inputConfig:   "sg_testing1_new_respond_partly",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// original path as well as respond enabled only on part of the TCP connection
	{
		name:          "PartialTCPAndRespond",
		inputConfig:   "sg_testing1_new_partly_TCP_and_respond",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// respond w.r.t. specific ports query
	{
		name:          "TCPRespondPortsQuery",
		inputConfig:   "sg_testing1_new_respond_partly",
		ESrc:          "vsi3a-ky",
		EDst:          "vsi1-ky",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   90,
		ESrcMaxPort:   180,
		EDstMinPort:   20,
		EDstMaxPort:   60,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// the following three tests are within a single VPC in a multiVPC context
	// 2 vsi connection
	{
		name:          "multiVPCVsiToVsi",
		inputConfig:   "tgw_larger_example",
		ESrc:          "vsi31-ky",
		EDst:          "vsi32-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// vsi to external connection
	{
		name:          "multiVPCVsiToExternal",
		inputConfig:   "tgw_larger_example",
		ESrc:          "test-vpc0-ky/vsi1-ky",
		EDst:          "172.217.22.46/32",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// vsi to external missing router
	{
		name:          "multiVPCVsiToExternalMissingRouter",
		inputConfig:   "tgw_larger_example",
		ESrc:          "vsi11-ky",
		EDst:          "172.217.22.46/32",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// tests for routing between vpcs:
	// connection enabled by specific allow prefix
	{
		name:          "tgwEnabledSpecificFilter",
		inputConfig:   "tg-prefix-filters",
		ESrc:          "ky-vsi1-subnet20",
		EDst:          "ky-vsi0-subnet2",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// connection enabled by default tgw definition (2 examples from 2 different input files, one detailed format)
	{
		name:          "tgwEnableDefaultFilter",
		inputConfig:   "tg-prefix-filters",
		ESrc:          "ky-vsi0-subnet5",
		EDst:          "ky-vsi0-subnet11",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:        "tgwAnotherEnableDefaultDifFile",
		inputConfig: "tgw_larger_example",
		ESrc:        "vsi11-ky",
		EDst:        "vsi21a-ky",
		format:      vpcmodel.Text,
	},
	// connection disabled by specific deny prefix
	{
		name:          "tgwDisabledDenyPrefix",
		inputConfig:   "tg-prefix-filters",
		ESrc:          "ky-vsi1-subnet20", // test-vpc2-ky
		EDst:          "ky-vsi0-subnet0",  // test-vpc0-ky
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:        "tgwDisabledDenyPrefix",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi1-subnet20", // test-vpc2-ky
		EDst:        "ky-vsi0-subnet0",  // test-vpc0-ky
		format:      vpcmodel.Text,
	},
	{
		name:        "tgwAnotherExampleEnabledConn",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi0-subnet5",
		EDst:        "ky-vsi0-subnet11",
		format:      vpcmodel.Text,
	},
	{
		name:          "tgwExampleCidr",
		inputConfig:   "tg-prefix-filters",
		ESrc:          "ky-vsi1-subnet20",
		EDst:          "10.240.0.0/21",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// connection disabled by lack of cross-vpc router (tgw)
	{
		name:          "multiVPCNoCrossVPCRouter",
		inputConfig:   "multiVpc_larger_example_dup_names",
		ESrc:          "vsi1-ky",  // test-vpc0-ky
		EDst:          "vsi31-ky", // test-vpc3-ky
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "multiVPCSameNamesCrossVPCNoTgw",
		inputConfig:   "multiVpc_larger_example_dup_names",
		ESrc:          "test-vpc0-ky/vsi1-ky",
		EDst:          "test-vpc1-ky/vsi1-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	{
		name:          "multiVPCSameNamesCrossVPCByAddrNoTgw",
		inputConfig:   "multiVpc_larger_example_dup_names",
		ESrc:          "10.240.3.5",  // vsi3a of test-vpc0-ky
		EDst:          "10.240.12.4", // vsi2 of test-vpc1-ky
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// TCP respond disabled by the tgw
	{
		name:          "tgwDisablesTCPRespond",
		inputConfig:   "tg-prefix-filters",
		ESrc:          "ky-vsi0-subnet0",
		EDst:          "ky-vsi0-subnet10",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// iks-node to iks-node
	{
		name:          "IksNodeToIksNode",
		inputConfig:   "iks_config_object",
		ESrc:          "192.168.8.4",
		EDst:          "192.168.4.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// vpe to iks-node, not all rules relevant
	{
		name:          "vpeToIksNodeSubsetRules",
		inputConfig:   "iks_config_object",
		ESrc:          "192.168.40.5",
		EDst:          "192.168.0.4",
		EProtocol:     netp.ProtocolStringTCP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// iks-node no connection (specific protocol)
	{
		name:          "vpeToIksNodeNoProtocolConn",
		inputConfig:   "iks_config_object",
		ESrc:          "192.168.40.5",
		EDst:          "192.168.0.4",
		EProtocol:     netp.ProtocolStringICMP,
		ESrcMinPort:   connection.MinPort,
		ESrcMaxPort:   connection.MaxPort,
		EDstMinPort:   connection.MinPort,
		EDstMaxPort:   connection.MaxPort,
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// load_balancer to iks-node, which is a pool member, should be allowed
	{
		name:          "LBToIksNode",
		inputConfig:   "iks_config_object",
		ESrc:          "kube-clusterid:1-8fdd1d0a2ce34deba99d0f885451b1ca",
		EDst:          "192.168.4.4",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// load_balancer to resIP, should be blocked by LB rule
	{
		name:          "LBToResIPNode",
		inputConfig:   "iks_config_object",
		ESrc:          "kube-clusterid:1-8fdd1d0a2ce34deba99d0f885451b1ca",
		EDst:          "192.168.32.5",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
	// multiNI to single NI
	{
		name:          "multiNIsToSingleNI",
		inputConfig:   "mult_NIs_single_VSI",
		ESrc:          "vsi3-ky",
		EDst:          "vsi1-ky",
		format:        vpcmodel.Text,
		detailExplain: true,
	},
}

func TestAll(t *testing.T) {
	// explainTests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runExplainTest(t)
		})
	}
	fmt.Println("done")
}

// uncomment the function below for generating the expected output files instead of comparing
/*
func TestAllWithGeneration(t *testing.T) {
// tests is the list of tests to run
for testIdx := range explainTests {
tt := explainTests[testIdx]
tt.mode = outputGeneration
t.Run(tt.name, func(t *testing.T) {
t.Parallel()
tt.runExplainTest(t)
})
}
fmt.Println("done")
}*/

func (tt *vpcGeneralTest) runExplainTest(t *testing.T) {
	// all tests in explain mode
	tt.useCases = []vpcmodel.OutputUseCase{vpcmodel.Explain}
	// init test - set the input/output file names according to test name
	tt.initTest()

	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfigs := getVPCConfigs(t, tt, true)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort, tt.detailExplain)

	// generate actual output for all use cases specified for this test
	err := runTestPerUseCase(t, tt, vpcConfigs, vpcmodel.Explain, tt.mode, explainOut, explanationArgs)
	require.Equal(t, tt.errPerUseCase[vpcmodel.Explain], err, "comparing actual err to expected err")
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

func TestInputValiditySingleVPCContext(t *testing.T) {
	vpcConfigSg1 := getConfig(t, "sg_testing1_new")
	require.NotNil(t, vpcConfigSg1, "vpcConfigSg1 equals nil")

	cidr1 := "169.255.0.0"
	cidr2 := "161.26.0.0/16"
	cidrInternalNoEP := "10.240.40.0/24"
	internalIPNotVsi := "10.240.10.5"
	cidrAll := "0.0.0.0/0"
	existingVsi := "vsi3a-ky"
	nonExistingVsi := "vsi3a"
	// should fail since two external addresses
	_, err1 := vpcConfigSg1.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	require.NotNil(t, err1, "the test should fail since both src and dst are external")
	require.Equal(t, "both src 169.255.0.0 and dst 161.26.0.0/16 are external IP addresses", err1.Error())
	fmt.Println()

	// should fail due to a cidr containing both public internet and internal address
	_, err2 := vpcConfigSg1.ExplainConnectivity(cidrAll, existingVsi, nil)
	fmt.Println(err2.Error())
	require.NotNil(t, err2, "the test should fail since src is cidr containing both public "+
		"internet and internal address")
	require.Equal(t, "illegal src: 0.0.0.0/0 contains both external and internal IP addresses, "+
		"which is not supported. src, dst should be external *or* internal address", err2.Error())
	fmt.Println()

	// should fail due to cidr containing internal address not within vpc's address prefix
	_, err3 := vpcConfigSg1.ExplainConnectivity(existingVsi, cidrInternalNoEP, nil)
	fmt.Println(err3.Error())
	require.NotNil(t, err3, "the test should fail since src is cidr with no ep connected to it")
	require.Equal(t, "illegal dst: no network interfaces are connected to 10.240.40.0/24", err3.Error())
	fmt.Println()

	// should fail since internal address not connected to vsi
	_, err4 := vpcConfigSg1.ExplainConnectivity(internalIPNotVsi, existingVsi, nil)
	fmt.Println(err4.Error())
	require.NotNil(t, err4, "the test should fail since dst is an internal address  not connected to any ep")
	require.Equal(t, "illegal src: no network interfaces are connected to 10.240.10.5", err4.Error())
	fmt.Println()

	// should fail since vsi's name has a typo
	_, err5 := vpcConfigSg1.ExplainConnectivity(existingVsi, nonExistingVsi, nil)
	fmt.Println(err5.Error())
	require.NotNil(t, err5, "the test should fail since dst non existing vsi")
	require.Equal(t, "illegal dst: vsi3a is not a legal IP address, CIDR, or endpoint name", err5.Error())

	// should fail since src and dst are identical
	_, err6 := vpcConfigSg1.ExplainConnectivity("10.240.10.4/32", "10.240.10.4", nil)
	fmt.Println(err6.Error())
	require.NotNil(t, err6, "the test should fail src and dst are equal")
	require.Equal(t, "specified src and dst are equal", err6.Error())
}

func TestInputValidityMultipleVPCContext(t *testing.T) {
	vpcConfigMultiVpc := getConfig(t, "tgw_larger_example")
	require.NotNil(t, vpcConfigMultiVpc, "vpcConfigMultiVpc equals nil")

	cidr1 := "169.255.0.0"
	cidr2 := "161.26.0.0/16"
	cidrAll := "0.0.0.0/0"
	existingVsi := "vsi11-ky"
	cidrInternalNoEP := "10.240.40.0/24"
	internalIPNotVsi := "10.240.64.7"
	nonExistingVsi := "vsi3a"
	// should fail since two external addresses
	_, err1 := vpcConfigMultiVpc.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	require.NotNil(t, err1, "the test should fail since both src and dst are external")
	require.Equal(t, "both src 169.255.0.0 and dst 161.26.0.0/16 are external IP addresses", err1.Error())
	fmt.Println()

	// should fail due to a cidr containing both public internet and internal address
	_, err2 := vpcConfigMultiVpc.ExplainConnectivity(cidrAll, existingVsi, nil)
	fmt.Println(err2.Error())
	require.NotNil(t, err2, "the test should fail since src is cidr containing both public "+
		"internet and internal address")
	require.Equal(t, "illegal src: 0.0.0.0/0 contains both external and internal IP addresses, "+
		"which is not supported. src, dst should be external *or* internal address", err2.Error())
	fmt.Println()

	// should fail due to src cidr containing internal address not within vpc's address prefix
	_, err3 := vpcConfigMultiVpc.ExplainConnectivity(existingVsi, cidrInternalNoEP, nil)
	fmt.Println(err3.Error())
	require.NotNil(t, err3, "the test should fail since src is cidr with no EP within it")
	require.Equal(t, "illegal dst: no network interfaces are connected to 10.240.40.0/24", err3.Error())
	fmt.Println()

	// should fail since internal address not connected to vsi
	_, err4 := vpcConfigMultiVpc.ExplainConnectivity(internalIPNotVsi, existingVsi, nil)
	fmt.Println(err4.Error())
	require.NotNil(t, err4, "the test should fail since dst is an internal address not connected to a VSI"+
		"address range not connected to a VSI")
	require.Equal(t, "illegal src: no network interfaces are connected to 10.240.64.7", err4.Error())
	fmt.Println()

	// should fail since dst vsi's name has a typo
	_, err5 := vpcConfigMultiVpc.ExplainConnectivity(existingVsi, nonExistingVsi, nil)
	fmt.Println(err5.Error())
	require.NotNil(t, err5, "the test should fail since dst non existing vsi")
	require.Equal(t, "illegal dst: vsi3a is not a legal IP address, CIDR, or endpoint name", err5.Error())
	fmt.Println()

	// should fail since src vsi's name has a typo
	_, err6 := vpcConfigMultiVpc.ExplainConnectivity(nonExistingVsi, existingVsi, nil)
	fmt.Println(err6.Error())
	require.NotNil(t, err6, "the test should fail since src non existing vsi")
	require.Equal(t, "illegal src: vsi3a is not a legal IP address, CIDR, or endpoint name", err6.Error())
	fmt.Println()

	// should fail since src and dst vsi's name has a typo - err msg should be about src
	_, err7 := vpcConfigMultiVpc.ExplainConnectivity(nonExistingVsi, existingVsi, nil)
	fmt.Println(err7.Error())
	require.NotNil(t, err7, "the test should fail since src and dst non existing vsi")
	require.Equal(t, "illegal src: vsi3a is not a legal IP address, CIDR, or endpoint name", err7.Error())
	fmt.Println()

	// src does not exist, dst is an internal address not connected to a vsi. should prioritize the dst error
	_, err8 := vpcConfigMultiVpc.ExplainConnectivity(nonExistingVsi, internalIPNotVsi, nil)
	fmt.Println(err8.Error())
	require.NotNil(t, err8, "the test should fail since dst non existing to vsi; src not found general error")
	require.Equal(t, "illegal dst: no network interfaces are connected to 10.240.64.7", err8.Error())
	fmt.Println()

	// should fail since vsi's name prefixed with the wrong vpc
	existingVsiWrongVpc := "test-vpc1-ky/vsi3a-ky"
	_, err9 := vpcConfigMultiVpc.ExplainConnectivity(cidr1, existingVsiWrongVpc, nil)
	fmt.Println(err9.Error())
	require.NotNil(t, err9, "the test should fail since the src vsi given with wrong vpc")
	require.Equal(t, "illegal dst: test-vpc1-ky/vsi3a-ky is not a legal IP address, CIDR, or endpoint name", err9.Error())

	vpcConfigTgwDupNames := getConfig(t, "tgw_larger_example_dup_names")
	dupSrcVsi := "vsi1-ky"
	dupDstVsi := "vsi2-ky"
	// should fail since vsi name exists for two different resources in one vpcConfig
	_, err10 := vpcConfigTgwDupNames.ExplainConnectivity(dupSrcVsi, dupDstVsi, nil)
	fmt.Println(err10.Error())
	require.NotNil(t, err10, "the test should fail since the src name exists twice")
	require.Equal(t, "illegal src: ambiguity - the configuration contains multiple resources named vsi1-ky, "+
		"try using CRNs or the VPC name to scope resources: vpc-name/instance-name"+
		"\nCRNs of matching resources:\n\tcrn:551\n\tcrn:488",
		err10.Error())
	vpcConfigMultiVpcDupNames := getConfig(t, "multiVpc_larger_example_dup_names")
	// should fail since these vsis exists in two vpcs configs
	_, err11 := vpcConfigMultiVpcDupNames.ExplainConnectivity(dupSrcVsi, dupDstVsi, nil)
	fmt.Println(err11.Error())
	require.NotNil(t, err11, "the test should fail since the src and dst vsis exists in two vpcs configs")
	require.Equal(t, "vsi1-ky and vsi2-ky found in more than one vpc config - test-vpc0-ky, test-vpc1-ky - "+
		"please add the name of the vpc to the src/dst name in case of name ambiguity, and avoid cidrs that spams more than one vpc",
		err11.Error())
}

// sanity check: no error and expected number of explanation elements
func TestMultiExplainSanity1(t *testing.T) {
	vpcsConfig := getConfig(t, "tgw_larger_example")
	require.NotNil(t, vpcsConfig, "vpcsConfig equals nil")
	groupedConns := make(map[string]*vpcmodel.GroupConnLines)
	nodesConn := make(map[string]*vpcmodel.VPCConnectivity)
	for i, vpcConfig := range vpcsConfig.Configs() {
		thisConn, err := vpcConfig.GetVPCNetworkConnectivity(false, false)
		if err != nil {
			fmt.Printf("%v. %s", i, err.Error())
		}
		require.Nil(t, err)
		groupedConns[i] = thisConn.GroupedConnectivity
		nodesConn[i] = thisConn
	}
	inputMultiExplain := vpcmodel.CreateMultiExplanationsInput(vpcsConfig, nodesConn, groupedConns)
	multiExplain := vpcmodel.MultiExplain(inputMultiExplain, nodesConn)
	i := 0
	for _, explain := range multiExplain {
		require.Equal(t, "", explain.EntryError())
		i++
	}
	require.Equal(t, i, len(inputMultiExplain))
}

func TestMultiExplainSanity2(t *testing.T) {
	vpcsConfig := getConfig(t, "acl_testing3")
	require.NotNil(t, vpcsConfig, "vpcsConfig equals nil")
	groupedConns := make(map[string]*vpcmodel.GroupConnLines)
	nodesConn := make(map[string]*vpcmodel.VPCConnectivity)
	for i, vpcConfig := range vpcsConfig.Configs() {
		thisConn, err := vpcConfig.GetVPCNetworkConnectivity(false, false)
		if err != nil {
			fmt.Printf("%v. %s", i, err.Error())
		}
		require.Nil(t, err)
		groupedConns[i] = thisConn.GroupedConnectivity
		nodesConn[i] = thisConn
	}
	inputMultiExplain := vpcmodel.CreateMultiExplanationsInput(vpcsConfig, nodesConn, groupedConns)
	multiExplain := vpcmodel.MultiExplain(inputMultiExplain, nodesConn)
	i := 0
	for _, explain := range multiExplain {
		require.Equal(t, "", explain.EntryError())
		i++
	}
	require.Equal(t, i, len(inputMultiExplain))
}

func TestMultiExplainabilityOutput(t *testing.T) {
	vpcsConfig := getConfig(t, "tgw_basic_example")
	require.NotNil(t, vpcsConfig, "vpcsConfig equals nil")
	groupedConns := make(map[string]*vpcmodel.GroupConnLines)
	nodesConn := make(map[string]*vpcmodel.VPCConnectivity)
	for i, vpcConfig := range vpcsConfig.Configs() {
		thisConn, err := vpcConfig.GetVPCNetworkConnectivity(false, false)
		if err != nil {
			fmt.Printf("%v. %s", i, err.Error())
		}
		require.Nil(t, err)
		groupedConns[i] = thisConn.GroupedConnectivity
		nodesConn[i] = thisConn
	}
	inputMultiExplain := vpcmodel.CreateMultiExplanationsInput(vpcsConfig, nodesConn, groupedConns)
	multiExplain := vpcmodel.MultiExplain(inputMultiExplain, nodesConn)
	outputSlice := make([]string, len(multiExplain))
	for i, explain := range multiExplain {
		require.Equal(t, "", explain.EntryError())
		outputSlice[i] = explain.String()
	}
	outputString := strings.Join(outputSlice, "")
	require.Contains(t, outputString, "No connections from Public Internet (all ranges) to ky-vpc2-vsi[10.240.64.5];\n"+
		"\tThere is no resource enabling inbound external connectivity", "no connection external src entry")
	require.Contains(t, outputString, "No connections from ky-vpc2-vsi[10.240.64.5] to Public Internet (all ranges);\n"+
		"\tThe dst is external but there is no resource enabling external connectivity", "no connection external dst entry")
	require.Contains(t, outputString, "ky-vpc1-vsi[10.240.0.5] -> security group ky-vpc1-sg -> ky-vpc1-net1 -> network ACL ky-vpc1-acl1 ->",
		"connection vsi to vsi")
	require.Contains(t, outputString, "ky-vpc1 -> TGW local-tg-ky -> ky-vpc2 ->", "connection vsi to vsi")
	require.Contains(t, outputString, "network ACL ky-vpc2-acl1 -> ky-vpc2-net1 -> security group ky-vpc2-sg -> ky-vpc2-vsi[10.240.64.5]",
		"connection vsi to vsi")
	fmt.Println("\n\n", outputString)
}

func TestInputLBPrivateIP(t *testing.T) {
	vpcConfigMultiVpc := getConfig(t, "iks_config_object")
	require.NotNil(t, vpcConfigMultiVpc, "vpcConfigMultiVpc equals nil")

	pipCidr := "192.168.36.6"
	cidr2 := "192.168.4.4"
	// should fail since pip address can not be an explainability input
	_, err1 := vpcConfigMultiVpc.ExplainConnectivity(pipCidr, cidr2, nil)
	fmt.Println(err1.Error())
	require.NotNil(t, err1, "the test should fail since "+pipCidr+" is a Private IP address")
	require.Equal(t, "illegal src: no network interfaces are connected to "+pipCidr, err1.Error())
	fmt.Println()
}
