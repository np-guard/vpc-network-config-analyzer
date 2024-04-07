package ibmvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const explainOut = "explain_out"

// getConfigs returns  vpcmodel.MultipleVPCConfigs obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) vpcmodel.MultipleVPCConfigs {
	inputConfigFile := filepath.Join(getTestsDirInput(), inputFilePrefix+fileName+jsonOutSuffix)
	rc, err := ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := VPCConfigsFromResources(rc, "", "", nil, false)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return vpcConfigs
}

var explainTests = []*vpcGeneralTest{
	{
		name:        "VsiToVsi1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi2-ky",
		EDst:        "vsi3b-ky",
		format:      vpcmodel.Debug,
	},
	{
		name:        "VsiToVsi2",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi2-ky",
		EDst:        "10.240.10.4",
		format:      vpcmodel.Debug,
	},
	{
		name:        "VsiToVsi3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "10.240.10.4",
		format:      vpcmodel.Debug,
	},
	{
		name:        "VsiToVsi4",
		inputConfig: "sg_testing1_new",
		ESrc:        "10.240.10.4",
		EDst:        "10.240.20.4",
		format:      vpcmodel.Debug,
	},
	{
		name:        "VsiToVsi5",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi2-ky",
		format:      vpcmodel.Debug,
	},
	{
		name:        "SimpleExternalSG1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		format:      vpcmodel.Debug,
	},
	{
		name:        "SimpleExternalSG2",
		inputConfig: "sg_testing1_new",
		ESrc:        "161.26.0.0/16",
		EDst:        "vsi1-ky",
		format:      vpcmodel.Text,
	},
	{
		name:        "SimpleExternalSG3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/32",
		format:      vpcmodel.Debug,
	},
	{
		name:        "SimpleExternalSG4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3b-ky",
		EDst:        "161.26.0.0/32",
		format:      vpcmodel.Text,
	},
	{
		name:        "GroupingExternalSG1",
		inputConfig: "sg_testing1_new",
		ESrc:        "10.240.10.4",
		EDst:        "161.26.0.0/8",
		format:      vpcmodel.Debug,
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
		name:        "QueryConnectionSGBasic1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	// the required connection is contained in the existing one per connection
	{
		name:        "QueryConnectionSGBasic2",
		inputConfig: "sg_testing1_new",
		ESrc:        "10.240.10.4",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		format:      vpcmodel.Debug,
	},
	//  the required connection is contained in the existing one per ip of src/dst
	{
		name:        "QueryConnectionSGBasic3",
		inputConfig: "sg_testing1_new",
		ESrc:        "crn:v1:staging:public:is:us-south:a/6527::vpc:a456", // crn:v1:staging:public:is:us-south:a/6527::vpc:a456 is vsi1-ky
		EDst:        "161.26.0.0/20",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		format:      vpcmodel.Debug,
	},
	// the required connection exists for part of the dst ip
	{
		name:        "QueryConnectionSGBasic4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/12",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		format:      vpcmodel.Debug,
	},
	// a connection does not exist regardless of the query
	{
		name:        "QueryConnectionSGBasic5",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "vsi3a-ky",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		format:      vpcmodel.Debug,
	},
	// a subset of the required ports exists
	{
		name:        "QueryConnectionSGSubsetPorts",
		inputConfig: "sg_testing1_new",
		ESrc:        "147.235.219.206/32",
		EDst:        "vsi2-ky",
		EProtocol:   netp.ProtocolStringTCP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: 10,
		EDstMaxPort: 30,
		format:      vpcmodel.Debug,
	},
	//  all rules are relevant (for comparison)
	{
		name:        "QueryConnectionSGRules1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi1-ky",
		format:      vpcmodel.Debug,
	},
	// only a subset of the rules are relevant, protocol wise
	{
		name:        "QueryConnectionSGRules2",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi1-ky",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	// only a subset of the rules are relevant, port wise and protocol wise
	{
		name:        "QueryConnectionSGRules3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi1-ky",
		EProtocol:   netp.ProtocolStringTCP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: 50,
		EDstMaxPort: 54,
		format:      vpcmodel.Debug,
	},
	//  all rules are relevant, with specified port wise protocol
	{
		name:        "QueryConnectionSGRules4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi1-ky",
		EProtocol:   netp.ProtocolStringTCP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: 120,
		EDstMaxPort: 230,
		format:      vpcmodel.Debug,
	},
	// connection exists to external
	{
		name:        "NACLExternal1",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		format:      vpcmodel.Debug,
	},
	// connection does not exist to external, blocked by egress
	{
		name:        "NACLExternal2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "100.128.0.0/32",
		format:      vpcmodel.Debug,
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
		name:        "NACLInternal1",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "10.240.20.4",
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLInternal1",
		inputConfig: "acl_testing3",
		ESrc:        "10.240.10.4",
		EDst:        "vsi2-ky",
		format:      vpcmodel.Text,
	},
	{
		name:        "NACLInternal2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi2-ky",
		EDst:        "10.240.10.4",
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLInternal3",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "vsi3a-ky",
		format:      vpcmodel.Debug,
	},
	{
		// same subnet: no actual rules in nacl, but connection enabled
		name:        "NACLInternal4",
		inputConfig: "acl_testing3",
		ESrc:        "vsi3b-ky",
		EDst:        "vsi3a-ky",
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLGrouping",
		inputConfig: "acl_testing3",
		ESrc:        "10.240.10.4",
		EDst:        "161.26.0.0/15",
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLQueryConnection1",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLQueryConnection2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringTCP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	// src: one of these network interfaces, dst: internal address of 4 network interfaces
	{
		name:        "NACLInternalSrcTo4DstInternal",
		inputConfig: "acl_testing3",
		ESrc:        "vsi3b-ky",
		EDst:        "10.240.30.4/26",
		format:      vpcmodel.Debug,
	},
	// src: internal address of 5 network interfaces, dst: external address that spans rules
	// "many to many"
	{
		name:        "SGInternal3SrcToExternalGroup",
		inputConfig: "sg_testing1_new",
		ESrc:        "10.240.30.4/24",
		EDst:        "161.26.0.0/8",
		format:      vpcmodel.Debug,
	},
	// all rules
	{
		name:        "NACLQueryConnectionRules2",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		format:      vpcmodel.Debug,
	},
	// without the udp rule
	{
		name:        "NACLQueryConnectionRules3",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringTCP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	// without the "all" rule since udp rule has higher priority
	{
		name:        "NACLQueryConnectionRules4",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "10.240.10.4/32",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLOnlyDenyNoConnQuery",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky",
		EDst:        "vsi2-ky",
		EProtocol:   netp.ProtocolStringICMP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	// allow connection subset of the queried one
	{
		name:        "NACLQueryAllowSubset",
		inputConfig: "acl_testing3_4th",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   netp.ProtocolStringUDP,
		ESrcMinPort: connection.MinPort,
		ESrcMaxPort: connection.MaxPort,
		EDstMinPort: connection.MinPort,
		EDstMaxPort: connection.MaxPort,
		format:      vpcmodel.Debug,
	},
	// two SGs attached to one VSI
	{
		name:        "VsiWithTwoSgs",
		inputConfig: "sg_testing1_new_2SGs",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi1-ky",
		format:      vpcmodel.Debug,
	},
	// the following three tests are within a single VPC in a multiVPC context
	// 2 vsi connection
	{
		name:        "multiVPCVsiToVsi",
		inputConfig: "tgw_larger_example",
		ESrc:        "vsi31-ky",
		EDst:        "vsi32-ky",
		format:      vpcmodel.Debug,
	},
	// vsi to external connection
	{
		name:        "multiVPCVsiToExternal",
		inputConfig: "tgw_larger_example",
		ESrc:        "test-vpc0-ky/vsi1-ky",
		EDst:        "172.217.22.46/32",
		format:      vpcmodel.Debug,
	},
	// vsi to external missing router
	{
		name:        "multiVPCVsiToExternalMissingRouter",
		inputConfig: "tgw_larger_example",
		ESrc:        "vsi11-ky",
		EDst:        "172.217.22.46/32",
		format:      vpcmodel.Debug,
	},
	// tests for routing between vpcs:
	// connection enabled by specific allow prefix
	{
		name:        "tgwEnabledSpecificFilter",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi1-subnet20",
		EDst:        "ky-vsi0-subnet2",
		format:      vpcmodel.Debug,
	},
	// connection enabled by default tgw definition (2 examples from 2 different input files, one debug format)
	{
		name:        "tgwEnableDefaultFilter",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi0-subnet5",
		EDst:        "ky-vsi0-subnet11",
		format:      vpcmodel.Debug,
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
		name:        "tgwDisabledDenyPrefix",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi1-subnet20", // test-vpc2-ky
		EDst:        "ky-vsi0-subnet0",  // test-vpc0-ky
		format:      vpcmodel.Debug,
	},
	{
		name:        "tgwDisabledDenyPrefix",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi1-subnet20", // test-vpc2-ky
		EDst:        "ky-vsi0-subnet0",  // test-vpc0-ky
		format:      vpcmodel.Text,
	},
	// todo: add the above example wo debug
	{
		name:        "tgwAnotherExampleEnabledConn",
		inputConfig: "tg-prefix-filters",
		ESrc:        "ky-vsi0-subnet5",
		EDst:        "ky-vsi0-subnet11",
		format:      vpcmodel.Text,
	},
	// connection disabled by lack of cross-vpc router (tgw)
	{
		name:        "multiVPCNoCrossVPCRouter",
		inputConfig: "multiVpc_larger_example_dup_names",
		ESrc:        "vsi1-ky",  // test-vpc0-ky
		EDst:        "vsi31-ky", // test-vpc3-ky
		format:      vpcmodel.Debug,
	},
	{
		name:        "multiVPCSameNamesCrossVPC",
		inputConfig: "multiVpc_larger_example_dup_names",
		ESrc:        "test-vpc0-ky/vsi1-ky",
		EDst:        "test-vpc1-ky/vsi1-ky",
		format:      vpcmodel.Debug,
	},
	// todo: fix and uncomment
	//{
	//	name:        "multiVPCSameNamesCrossVPC",
	//	inputConfig: "multiVpc_larger_example_dup_names",
	//	ESrc:        "10.240.3.5",  // vsi3a of test-vpc0-ky
	//	EDst:        "10.240.12.4", // vsi2 of test-vpc1-ky
	//	format:      vpcmodel.Debug,
	//},
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
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort)

	// generate actual output for all use cases specified for this test
	err := runTestPerUseCase(t, tt, vpcConfigs, nil, vpcmodel.Explain, tt.mode, explainOut, explanationArgs)
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
	cidrInternalNonAP := "10.240.10.4/16"
	internalIPNotVsi := "10.240.10.5"
	cidrAll := "0.0.0.0/0"
	existingVsi := "vsi3a-ky"
	nonExistingVsi := "vsi3a"
	// should fail since two external addresses
	_, err1 := vpcConfigSg1.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	require.NotNil(t, err1, "the test should fail since both src and dst are external")
	require.Equal(t, "both src 169.255.0.0 and dst 161.26.0.0/16 are external", err1.Error())
	fmt.Println()

	// should fail due to a cidr containing both public internet and internal address
	_, err2 := vpcConfigSg1.ExplainConnectivity(cidrAll, existingVsi, nil)
	fmt.Println(err2.Error())
	require.NotNil(t, err2, "the test should fail since src is cidr containing both public "+
		"internet and internal address")
	require.Equal(t, "illegal src: 0.0.0.0/0 contains both external and internal addresses "+
		"which is not supported. src, dst should be external *or* internal address", err2.Error())
	fmt.Println()

	// should fail due to cidr containing internal address not within vpc's address prefix
	_, err3 := vpcConfigSg1.ExplainConnectivity(existingVsi, cidrInternalNonAP, nil)
	fmt.Println(err3.Error())
	require.NotNil(t, err3, "the test should fail since src is cidr containing internal address "+
		"not within vpc's subnets address range")
	require.Equal(t, "illegal dst: internal address 10.240.10.4/16 not within the vpc "+
		"test-vpc1-ky subnets' address range 10.240.10.0-10.240.10.255, 10.240.20.0-10.240.20.255, 10.240.30.0-10.240.30.255",
		err3.Error())
	fmt.Println()

	// should fail since internal address not connected to vsi
	_, err4 := vpcConfigSg1.ExplainConnectivity(internalIPNotVsi, existingVsi, nil)
	fmt.Println(err4.Error())
	require.NotNil(t, err4, "the test should fail since dst is an internal address within subnet's "+
		"address range not connected to a VSI")
	require.Equal(t, "illegal src: no network interfaces are connected to 10.240.10.5 in test-vpc1-ky", err4.Error())
	fmt.Println()

	// should fail since vsi's name has a typo
	_, err5 := vpcConfigSg1.ExplainConnectivity(existingVsi, nonExistingVsi, nil)
	fmt.Println(err5.Error())
	require.NotNil(t, err5, "the test should fail since dst non existing vsi")
	require.Equal(t, "illegal dst: vsi3a does not represent a legal IP address, a legal CIDR or a VSI name", err5.Error())
}

func TestInputValidityMultipleVPCContext(t *testing.T) {
	vpcConfigMultiVpc := getConfig(t, "tgw_larger_example")
	require.NotNil(t, vpcConfigMultiVpc, "vpcConfigMultiVpc equals nil")

	cidr1 := "169.255.0.0"
	cidr2 := "161.26.0.0/16"
	cidrAll := "0.0.0.0/0"
	existingVsi := "vsi11-ky"
	cidrInternalNonAP := "10.240.10.4/16"
	internalIPNotVsi := "10.240.64.7"
	nonExistingVsi := "vsi3a"
	// should fail since two external addresses
	_, err1 := vpcConfigMultiVpc.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	require.NotNil(t, err1, "the test should fail since both src and dst are external")
	require.Equal(t, "both src 169.255.0.0 and dst 161.26.0.0/16 are external", err1.Error())
	fmt.Println()

	// should fail due to a cidr containing both public internet and internal address
	_, err2 := vpcConfigMultiVpc.ExplainConnectivity(cidrAll, existingVsi, nil)
	fmt.Println(err2.Error())
	require.NotNil(t, err2, "the test should fail since src is cidr containing both public "+
		"internet and internal address")
	require.Equal(t, "illegal src: 0.0.0.0/0 contains both external and internal addresses "+
		"which is not supported. src, dst should be external *or* internal address", err2.Error())
	fmt.Println()

	// should fail due to src cidr containing internal address not within vpc's address prefix
	_, err3 := vpcConfigMultiVpc.ExplainConnectivity(existingVsi, cidrInternalNonAP, nil)
	fmt.Println(err3.Error())
	require.NotNil(t, err3, "the test should fail since src is cidr containing internal address "+
		"not within vpc's subnets address range")
	require.Equal(t, "illegal dst: internal address 10.240.10.4/16 not within any of the VPC's subnets' address range",
		err3.Error())
	fmt.Println()

	// should fail since internal address not connected to vsi
	_, err4 := vpcConfigMultiVpc.ExplainConnectivity(internalIPNotVsi, existingVsi, nil)
	fmt.Println(err4.Error())
	require.NotNil(t, err4, "the test should fail since dst is an internal address within subnet's "+
		"address range not connected to a VSI")
	require.Equal(t, "illegal src: no network interfaces are connected to 10.240.64.7 in any of the VPCs", err4.Error())
	fmt.Println()

	// should fail since dst vsi's name has a typo
	_, err5 := vpcConfigMultiVpc.ExplainConnectivity(existingVsi, nonExistingVsi, nil)
	fmt.Println(err5.Error())
	require.NotNil(t, err5, "the test should fail since dst non existing vsi")
	require.Equal(t, "illegal dst: vsi3a does not represent a legal IP address, a legal CIDR or a VSI name", err5.Error())
	fmt.Println()

	// should fail since src vsi's name has a typo
	_, err6 := vpcConfigMultiVpc.ExplainConnectivity(nonExistingVsi, existingVsi, nil)
	fmt.Println(err6.Error())
	require.NotNil(t, err6, "the test should fail since src non existing vsi")
	require.Equal(t, "illegal src: vsi3a does not represent a legal IP address, a legal CIDR or a VSI name", err6.Error())
	fmt.Println()

	// should fail since src and dst vsi's name has a typo - err msg should be about src
	_, err7 := vpcConfigMultiVpc.ExplainConnectivity(nonExistingVsi, nonExistingVsi, nil)
	fmt.Println(err7.Error())
	require.NotNil(t, err7, "the test should fail since src and dst non existing vsi")
	require.Equal(t, "illegal src: vsi3a does not represent a legal IP address, a legal CIDR or a VSI name", err7.Error())
	fmt.Println()

	// src does not exist, dst is an internal address not connected to a vsi. should prioritize the dst error
	_, err8 := vpcConfigMultiVpc.ExplainConnectivity(nonExistingVsi, internalIPNotVsi, nil)
	fmt.Println(err8.Error())
	require.NotNil(t, err8, "the test should fail since dst non connected to vsi; src not found general error")
	require.Equal(t, "illegal dst: no network interfaces are connected to 10.240.64.7 in any of the VPCs", err8.Error())
	fmt.Println()

	// should fail since vsi's name prefixed with the wrong vpc
	existingVsiWrongVpc := "test-vpc1-ky/vsi3a-ky"
	_, err9 := vpcConfigMultiVpc.ExplainConnectivity(cidr1, existingVsiWrongVpc, nil)
	fmt.Println(err9.Error())
	require.NotNil(t, err9, "the test should fail since the src vsi given with wrong vpc")
	require.Equal(t, "illegal dst: test-vpc1-ky/vsi3a-ky does not represent a legal IP address, a legal CIDR or a VSI name", err9.Error())

	vpcConfigTgwDupNames := getConfig(t, "tgw_larger_example_dup_names")
	dupSrcVsi := "vsi1-ky"
	dupDstVsi := "vsi2-ky"
	// should fail since vsi name exists for two different resources in one vpcConfig
	_, err10 := vpcConfigTgwDupNames.ExplainConnectivity(dupSrcVsi, dupDstVsi, nil)
	fmt.Println(err10.Error())
	require.NotNil(t, err10, "the test should fail since the src name exists twice")
	require.Equal(t, "illegal src: in combined-vpc-local-tg-ky there is more than one resource "+
		"(crn:551, crn:488) with the given input string vsi1-ky. "+
		"can not determine which resource to analyze. consider using unique names or use input UID instead",
		err10.Error())
	vpcConfigMultiVpcDupNames := getConfig(t, "multiVpc_larger_example_dup_names")
	// should fail since these vsis exists in two vpcs configs
	_, err11 := vpcConfigMultiVpcDupNames.ExplainConnectivity(dupSrcVsi, dupDstVsi, nil)
	fmt.Println(err11.Error())
	require.NotNil(t, err11, "the test should fail since the src and dst vsis exists in two vpcs configs")
	require.Equal(t, "vsis vsi1-ky and vsi2-ky found in more than one vpc config "+
		"- test-vpc0-ky, test-vpc1-ky - please add the name of the config to the src/dst name",
		err11.Error())
}
