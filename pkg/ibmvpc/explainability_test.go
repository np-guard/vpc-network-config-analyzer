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
func getConfig(t *testing.T, fileName string) *vpcmodel.VPCConfig {
	inputConfigFile := filepath.Join(getTestsDirInput(), inputFilePrefix+fileName+jsonOutSuffix)
	rc, err := ParseResourcesFromFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	vpcConfigs, err := VPCConfigsFromResources(rc, "", false)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	for _, vpcConfig := range vpcConfigs {
		return vpcConfig
	}
	return nil
}

var explainTests = []*vpcGeneralTest{
	{
		name:        "VsiToVsi1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi3b-ky[10.240.30.4]",
	},
	{
		name:        "VsiToVsi2",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi1-ky[10.240.10.4]",
	},
	{
		name:        "VsiToVsi3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
	},
	{
		name:        "VsiToVsi4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi2-ky[10.240.20.4]",
	},
	{
		name:        "VsiToVsi5",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi2-ky[10.240.20.4]",
	},
	{
		name:        "SimpleExternalSG1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
	},
	{
		name:        "SimpleExternalSG2",
		inputConfig: "sg_testing1_new",
		ESrc:        "161.26.0.0/16",
		EDst:        "vsi1-ky[10.240.10.4]",
	},
	{
		name:        "SimpleExternalSG3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/32",
	},
	{
		name:        "SimpleExternalSG4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3b-ky[10.240.30.4]",
		EDst:        "161.26.0.0/32",
	},
	{
		name:        "GroupingExternalSG1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/8",
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
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
	},
	// the required connection is contained in the existing one per connection
	{
		name:        "QueryConnectionSGBasic2",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
	},
	//  the required connection is contained in the existing one per ip of src/dst
	{
		name:        "QueryConnectionSGBasic3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/20",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
	},
	// the required connection exists for part of the dst ip
	{
		name:        "QueryConnectionSGBasic4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/12",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
	},
	// a connection does not exist regardless of the query
	{
		name:        "QueryConnectionSGBasic5",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi3a-ky[10.240.30.5]",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
	},
	// a subset of the required ports exists
	{
		name:        "QueryConnectionSGSubsetPorts",
		inputConfig: "sg_testing1_new",
		ESrc:        "147.235.219.206/32",
		EDst:        "vsi2-ky[10.240.20.4]",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 10,
		EDstMaxPort: 30,
	},
	//  all rules are relevant (for comparison)
	{
		name:        "QueryConnectionSGRules1",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
	},
	// only a subset of the rules are relevant, protocol wise
	{
		name:        "QueryConnectionSGRules2",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
	},
	// only a subset of the rules are relevant, port wise and protocol wise
	{
		name:        "QueryConnectionSGRules3",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 50,
		EDstMaxPort: 54,
	},
	//  all rules are relevant, with specified port wise protocol
	{
		name:        "QueryConnectionSGRules4",
		inputConfig: "sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 120,
		EDstMaxPort: 230,
	},
	// connection exists to external
	{
		name:        "NACLExternal1",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
	},
	// connection does not exist to external, blocked by egress
	{
		name:        "NACLExternal2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "100.128.0.0/32",
	},
	// connection does not exist to external, no fip router
	{
		name:        "NACLExternal3",
		inputConfig: "acl_testing3",
		ESrc:        "100.128.0.0/32",
		EDst:        "vsi1-ky[10.240.10.4]",
	},
	{
		// todo: misleading since deny not supported yet
		name:        "NACLInternal1",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi2-ky[10.240.20.4]",
	},
	{
		name:        "NACLInternal2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi1-ky[10.240.10.4]",
	},
	{
		name:        "NACLInternal3",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi3a-ky[10.240.30.5]",
	},
	{
		// same subnet: no actual rules in nacl, but connection enabled
		name:        "NACLInternal4",
		inputConfig: "acl_testing3",
		ESrc:        "vsi3b-ky[10.240.30.6]",
		EDst:        "vsi3a-ky[10.240.30.5]",
	},
	{
		name:        "NACLGrouping",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/15",
	},
	{
		name:        "NACLQueryConnection1",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
	},
	{
		name:        "NACLQueryConnection2",
		inputConfig: "acl_testing3",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
	},
	// all rules
	{
		name:        "NACLQueryConnectionRules2",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
	},
	// without the udp rule
	{
		name:        "NACLQueryConnectionRules3",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolTCP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
	},
	// without the "all" rule since udp rule has higher priority
	{
		name:        "NACLQueryConnectionRules4",
		inputConfig: "acl_testing3_3rd",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   string(common.ProtocolUDP),
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
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
	tt.format = vpcmodel.Text
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
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	cidr1 := "0.0.0.0/0"
	cidr2 := "161.26.0.0/16"
	nonExistingVSI := "vsi2-ky[10.240.10.4]"
	_, err1 := vpcConfig.ExplainConnectivity(cidr1, cidr2, nil)
	fmt.Println(err1.Error())
	if err1 == nil {
		require.Fail(t, err1.Error())
	}
	_, err2 := vpcConfig.ExplainConnectivity(cidr1, nonExistingVSI, nil)
	fmt.Println(err2.Error())
	if err2 == nil {
		require.Fail(t, err1.Error())
	}
}
