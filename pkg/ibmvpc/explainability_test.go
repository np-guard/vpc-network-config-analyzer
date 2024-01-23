package ibmvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
	"github.com/stretchr/testify/require"
)

// getConfigs returns  map[string]*vpcmodel.VPCConfig obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) *vpcmodel.VPCConfig {
	inputConfigFile := filepath.Join(getTestsDir(), fileName+".json")
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

type explainGeneralTest struct {
	name        string // test name
	inputConfig string // name (relative path) of input config file (json)
	ESrc        string
	EDst        string
	EProtocol   common.ProtocolStr
	ESrcMinPort int64
	ESrcMaxPort int64
	EDstMinPort int64
	EDstMaxPort int64
	out         string
}

var explainTests = []*explainGeneralTest{
	{
		name:        "VsiToVsi1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi3b-ky[10.240.30.4]",
		out: "The following connection exists between vsi2-ky[10.240.20.4] and vsi3b-ky[10.240.30.4]: " +
			"protocol: TCP; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:" +
			"\n\tindex: 5, direction: outbound, protocol: all, cidr: 10.240.30.0/24" +
			"\n\tindex: 6, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32" +
			"\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:" +
			"\n\tindex: 7, direction: inbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n",
	},
	{
		name:        "VsiToVsi2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "The following connection exists between vsi2-ky[10.240.20.4] and vsi1-ky[10.240.10.4]: " +
			"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n" +
			"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:" +
			"\n\tindex: 1, direction: outbound, protocol: all, cidr: 10.240.10.0/24\nIngress Rules:" +
			"\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\t" +
			"index: 3, direction: inbound, protocol: all, cidr: 10.240.20.4/32,10.240.30.4/32\n\n",
	},
	{
		name:        "VsiToVsi3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "The following connection exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]: " +
			"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n" +
			"Ingress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	{
		name:        "VsiToVsi4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "No connection between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]; " +
			"connection blocked by egress\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg2-ky:\n\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.10.4/32\n\n",
	},
	{
		name:        "VsiToVsi5",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "No connection between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]; " +
			"connection blocked by ingress\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n\n",
	},
	{
		name:        "SimpleExternalSG1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		out: "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: " +
			"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\t" +
			"index: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "SimpleExternalSG2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "161.26.0.0/16",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "No connection between Public Internet 161.26.0.0/16 and vsi1-ky[10.240.10.4]; " +
			"no fip router and src is external (fip is required for outbound external connection)\n\n",
	},
	{
		name:        "SimpleExternalSG3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/32",
		out: "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/32: " +
			"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\t" +
			"index: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "SimpleExternalSG4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3b-ky[10.240.30.4]",
		EDst:        "161.26.0.0/32",
		out: "No connection between vsi3b-ky[10.240.30.4] and Public Internet 161.26.0.0/32; " +
			"no router (fip/pgw) and dst is external\n\n",
	},
	{
		name:        "GroupingExternalSG1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/8",
		out: "No connection between vsi1-ky[10.240.10.4] and Public Internet 161.0.0.0-161.25.255.255,161.27.0.0-161.255.255.255; " +
			"connection blocked by egress\n\n" +
			"The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: protocol: UDP; its enabled by\n" +
			"External Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	// todo: now that external and internal IPs are treated differently, deffer cidrAll test to the time we properly support internal IP #305
	/*{
		name:        "GroupingExternalSG2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi2-ky[10.240.20.4]",
		EDst:        "0.0.0.0/0",
		out: "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; " +
			"connection blocked by egress\n\n" +
			"The following connection exists between vsi2-ky[10.240.20.4] and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
	},
	{
		name:        "GroupingExternalSG3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "0.0.0.0/0",
		EDst:        "vsi2-ky[10.240.20.4]",
		out: "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; " +
			"connection blocked by egress\n\nThe following connection exists between vsi2-ky[10.240.20.4] " +
			"and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\nEgress Rules:\n" +
			"~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n\t" +
			"index: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
	},*/
	{
		name:        "QueryConnectionSGBasic1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		out: "Connection protocol: UDP exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; its enabled by\n" +
			"External Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "QueryConnectionSGBasic2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/16",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] " +
			"and Public Internet 161.26.0.0/16; its enabled by\nExternal Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "QueryConnectionSGBasic3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/20",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] " +
			"and Public Internet 161.26.0.0/20; its enabled by\nExternal Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
	},
	{
		name:        "QueryConnectionSGBasic4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "161.26.0.0/12",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "Connection protocol: UDP src-ports: 10-100 dst-ports: " +
			"443 exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; its enabled by\n" +
			"External Router PublicGateway: public-gw-ky\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n" +
			"There is no connection \"protocol: UDP src-ports: 10-100 dst-ports: 443\" " +
			"between vsi1-ky[10.240.10.4] and Public Internet 161.16.0.0-161.25.255.255,161.27.0.0-161.31.255.255; " +
			"connection blocked by egress\n\n",
	},
	{
		name:        "QueryConnectionSGBasic5",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi1-ky[10.240.10.4]",
		EDst:        "vsi3a-ky[10.240.30.5]",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: 10,
		ESrcMaxPort: 100,
		EDstMinPort: 443,
		EDstMaxPort: 443,
		out: "There is no connection \"protocol: UDP src-ports: 10-100 dst-ports: 443\" " +
			"between vsi1-ky[10.240.10.4] and vsi3a-ky[10.240.30.5]; " +
			"connection blocked both by ingress and egress\n\n",
	},
	{
		name:        "QueryConnectionSGRules1",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		out: "The following connection exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]: " +
			"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n" +
			"Ingress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	{
		name:        "QueryConnectionSGRules2",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   common.ProtocolUDP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: common.MinPort,
		EDstMaxPort: common.MaxPort,
		out: "Connection protocol: UDP exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]; its enabled by\n" +
			"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n" +
			"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n" +
			"------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	{
		name:        "QueryConnectionSGRules3",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   common.ProtocolTCP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 50,
		EDstMaxPort: 54,
		out: "Connection protocol: TCP dst-ports: 50-54 exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]; " +
			"its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n" +
			"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n" +
			"Ingress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules" +
			"\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
	{
		name:        "QueryConnectionSGRules4",
		inputConfig: "input_sg_testing1_new",
		ESrc:        "vsi3a-ky[10.240.30.5]",
		EDst:        "vsi1-ky[10.240.10.4]",
		EProtocol:   common.ProtocolTCP,
		ESrcMinPort: common.MinPort,
		ESrcMaxPort: common.MaxPort,
		EDstMinPort: 120,
		EDstMaxPort: 230,
		out: "Connection protocol: TCP dst-ports: 120-230 exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]; " +
			"its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n" +
			"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n" +
			"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n\t" +
			"index: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\nIngress Rules:\n" +
			"~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n" +
			"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n",
	},
}

func TestAll(t *testing.T) {
	// explainTests is the list of tests to run
	for testIdx := range explainTests {
		tt := explainTests[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}

func (tt *explainGeneralTest) runTest(t *testing.T) {
	// get vpcConfigs obj from parsing + analyzing input config file
	vpcConfig := getConfig(t, tt.inputConfig)
	explanationArgs := vpcmodel.NewExplanationArgs(tt.ESrc, tt.EDst, string(tt.EProtocol),
		tt.ESrcMinPort, tt.ESrcMaxPort, tt.EDstMinPort, tt.EDstMaxPort)
	connQuery := explanationArgs.GetConnectionSet()
	explanation, err := vpcConfig.ExplainConnectivity(explanationArgs.GetSrc(), explanationArgs.GetDst(), connQuery)
	if err != nil {
		require.Fail(t, err.Error())
	}
	require.Equal(t, tt.out, explanation.String())
}

func TestInputValidity(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new")
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

// this test can not be tested with cli main args
func TestQueryConnectionSGBasic(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	// test1: a connection exists, but it is not the required one by query
	explain1, err1 := vpcConfig.ExplainConnectivity("vsi2-ky[10.240.20.4]", "vsi3b-ky[10.240.30.4]", common.NewConnectionSet(true))
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "There is no connection \"All Connections\" between vsi2-ky[10.240.20.4] and vsi3b-ky[10.240.30.4]; "+
		"connection blocked by ingress\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 5, direction: outbound, protocol: all, cidr: 10.240.30.0/24\n"+
		"\tindex: 6, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n", explainStr1)
}
