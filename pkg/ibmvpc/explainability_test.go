package ibmvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const explainOut = "explain_out"

// getConfigs returns  map[string]*vpcmodel.VPCConfig obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) vpcmodel.VpcsConfigsMap {
	inputConfigFile := filepath.Join(getTestsDirInput(), inputFilePrefix+fileName+jsonOutSuffix)
	rc, err := ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := VPCConfigsFromResources(rc, "", false)
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
	//todo: now that external and internal IPs are treated differently, deffer cidrAll test to the time we properly support internal IP #305
	/*{
		name:        "GroupingExternalSG2",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "0.0.0.0/0",
	},
	{
		name:        "GroupingExternalSG3",
		inputConfig: "sg_testing1_new",
		ESrc:        "0.0.0.0/0",
		EDst:        "vsi2-ky[10.240.20.4]",
	},*/
	{
		// the existing connection is exactly the one required by the query
		name:        "QueryConnectionSGBasic1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
	},
	// the required connection is contained in the existing one per connection
	{
		name:        "QueryConnectionSGBasic2",
		inputConfig: "sg_testing1_new",
		ESrc:        "10.240.10.4",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
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
		EProtocol:   string(common.ProtocolUDP),
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
		EProtocol:   string(common.ProtocolUDP),
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
		EProtocol:   string(common.ProtocolUDP),
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
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
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
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
	},
	// only a subset of the rules are relevant, port wise and protocol wise
	{
		name:        "QueryConnectionSGRules3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky",
		EDst:        "vsi1-ky",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
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
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
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
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLQueryConnection2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
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
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
	},
	// without the "all" rule since udp rule has higher priority
	{
		name:        "NACLQueryConnectionRules4",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "10.240.10.4/32",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
	},
	{
		name:        "NACLOnlyDenyNoConnQuery",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky",
		EDst:        "vsi2-ky",
		EProtocol:   string(common.ProtocolICMP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
	},
	// allow connection subset of the queried one
	{
		name:        "NACLQueryAllowSubset",
		inputConfig: "acl_testing3_4th",
		ESrc:        "vsi1-ky",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		format:      vpcmodel.Debug,
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
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, tt.EProtocol,
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort)

	// generate actual output for all use cases specified for this test
	err := runTestPerUseCase(t, tt, vpcConfigs, nil, vpcmodel.Explain, tt.mode, explainOut, explanationArgs)
	require.Equal(t, tt.errPerUseCase[vpcmodel.Explain], err, "comparing actual err to expected err")
	for uc, outFile := range tt.actualOutput {
		fmt.Printf("test %s use-case %d - generated output file: %s\n", tt.name, uc, outFile)
	}
}

func TestInputValidity(t *testing.T) {
	vpcConfig := getConfig(t, "sg_testing1_new")
	require.NotNil(t, vpcConfig, "vpcConfig equals nil")

	cidr1 := "169.255.0.0"
	cidr2 := "161.26.0.0/16"
	cidrInternalNonAP := "10.240.10.4/16"
	internalIPNotVsi := "10.240.10.5"
	cidrAll := "0.0.0.0/0"
	existingVsi := "vsi3a-ky"
	nonExistingVsi := "vsi3a"
	// should fail since two external addresses
	_, err1 := vpcConfig.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	require.NotNil(t, err1, "the test should fail since both src and dst are external")
	require.Equal(t, "both src 169.255.0.0 and dst 161.26.0.0/16 are external", err1.Error())
	fmt.Println()

	// should fail due to a cidr containing both public internet and internal address
	_, err2 := vpcConfig.ExplainConnectivity(cidrAll, existingVsi, nil)
	fmt.Println(err2.Error())
	require.NotNil(t, err2, "the test should fail since src is cidr containing both public "+
		"internet and internal address")
	require.Equal(t, "illegal src: 0.0.0.0/0 contains both external and internal addresses "+
		"which is not supported. src, dst should be external *or* internal address", err2.Error())
	fmt.Println()

	// should fail due to cidr containing internal address not within vpc's address prefix
	_, err3 := vpcConfig.ExplainConnectivity(existingVsi, cidrInternalNonAP, nil)
	fmt.Println(err3.Error())
	require.NotNil(t, err3, "the test should fail since src is cidr containing internal address "+
		"not within vpc's subnets address range")
	require.Equal(t, "illegal dst: internal address 10.240.0.0-10.240.255.255 not within the vpc "+
		"test-vpc1-ky subnets' address range 10.240.10.0-10.240.10.255, 10.240.20.0-10.240.20.255, 10.240.30.0-10.240.30.255",
		err3.Error())
	fmt.Println()

	// should fail since internal address not connected to vsi
	_, err4 := vpcConfig.ExplainConnectivity(internalIPNotVsi, existingVsi, nil)
	fmt.Println(err4.Error())
	require.NotNil(t, err4, "the test should fail since dst is an internal address within subnet's "+
		"address range not connected to a VSI")
	require.Equal(t, "illegal src: no network interfaces are connected to 10.240.10.5 in test-vpc1-ky", err4.Error())
	fmt.Println()

	// should fail since vsi's name has a typo
	_, err5 := vpcConfig.ExplainConnectivity(existingVsi, nonExistingVsi, nil)
	fmt.Println(err5.Error())
	require.NotNil(t, err5, "the test should fail since src non existing vsi")
	require.Equal(t, "illegal dst: does not represent an internal interface, "+
		"an internal IP with network interface or a valid external IP", err5.Error())
}
