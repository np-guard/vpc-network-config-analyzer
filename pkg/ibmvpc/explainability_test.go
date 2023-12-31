package ibmvpc

import (
	"fmt"
	"os"
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// todo: quick and dirty tmp until added to the cli, by which these will be added as end-to-end tests
func TestVsiToVsi(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new.json")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	explanbilityStr1, err1 := vpcConfig.ExplainConnectivity("vsi2-ky[10.240.20.4]", "vsi3b-ky[10.240.30.4]")
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	fmt.Println(explanbilityStr1)
	require.Equal(t, "The following connection exists between vsi2-ky[10.240.20.4] and vsi3b-ky[10.240.30.4]: "+
		"protocol: TCP; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:"+
		"\n\tindex: 5, direction: outbound, protocol: all, cidr: 10.240.30.0/24"+
		"\n\tindex: 6, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32"+
		"\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:"+
		"\n\tindex: 7, direction: inbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n",
		explanbilityStr1)
	explanbilityStr2, err2 := vpcConfig.ExplainConnectivity("vsi2-ky[10.240.20.4]", "vsi1-ky[10.240.10.4]")
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	fmt.Println(explanbilityStr2)
	require.Equal(t, "The following connection exists between vsi2-ky[10.240.20.4] and vsi1-ky[10.240.10.4]: "+
		"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:"+
		"\n\tindex: 1, direction: outbound, protocol: all, cidr: 10.240.10.0/24\nIngress Rules:"+
		"\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\t"+
		"index: 3, direction: inbound, protocol: all, cidr: 10.240.20.4/32,10.240.30.4/32\n\n", explanbilityStr2)
	explanbilityStr3, err3 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi1-ky[10.240.10.4]")
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	fmt.Println(explanbilityStr3)
	require.Equal(t, "The following connection exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]: "+
		"All Connections; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules"+
		"\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explanbilityStr3)
	explanbilityStr4, err4 := vpcConfig.ExplainConnectivity("vsi1-ky[10.240.10.4]", "vsi2-ky[10.240.20.4]")
	if err4 != nil {
		require.Fail(t, err4.Error())
	}
	fmt.Println(explanbilityStr4)
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]; "+
		"connection blocked by egress\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.10.4/32\n\n", explanbilityStr4)
	explanbilityStr5, err5 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi2-ky[10.240.20.4]")
	if err5 != nil {
		require.Fail(t, err5.Error())
	}
	fmt.Println(explanbilityStr5)
	require.Equal(t, "No connection between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]; connection blocked by ingress\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:"+
		"\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n", explanbilityStr5)
	fmt.Println("done")
}

// sg1-ky: vsi1-ky
// sg2-ky: vsi2-ky, vsi3b-ky
// sg3-ky: vsi3a-ky
// sg1-ky, sg3-ky: default
// sg2-ky: allow all
func TestSGDefaultRules(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing_default.json")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	// no connection, disabled by default rules
	explanbilityStr1, err1 := vpcConfig.ExplainConnectivity("vsi1-ky[10.240.10.4]", "vsi3a-ky[10.240.30.5]")
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	fmt.Println(explanbilityStr1)
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and vsi3a-ky[10.240.30.5]; "+
		"connection blocked by ingress\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n"+
		"------------------------\nrules in sg1-ky are the default, namely this is the enabling egress rule:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n", explanbilityStr1)
	// connection, egress (sg3-ky) is default
	explanbilityStr2, err2 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi2-ky[10.240.20.4]")
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	fmt.Println(explanbilityStr2)
	require.Equal(t, "The following connection exists between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]: All Connections; "+
		"its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"rules in sg3-ky are the default, namely this is the enabling egress rule:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n"+
		"Ingress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n", explanbilityStr2)
	fmt.Println("done")
}

func TestInputValidity(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new.json")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	cidr1 := "0.0.0.0/0"
	cidr2 := "161.26.0.0/16"
	nonExistingVSI := "vsi2-ky[10.240.10.4]"
	_, err1 := vpcConfig.ExplainConnectivity(cidr1, cidr2)
	fmt.Println(err1.Error())
	if err1 == nil {
		require.Fail(t, err1.Error())
	}
	_, err2 := vpcConfig.ExplainConnectivity(cidr1, nonExistingVSI)
	fmt.Println(err2.Error())
	if err2 == nil {
		require.Fail(t, err1.Error())
	}
}

func TestSimpleExternal(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new.json")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/16"
	cidr2 := "161.26.0.0/32"
	explanbilityStr1, err1 := vpcConfig.ExplainConnectivity(vsi1, cidr1)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	require.Equal(t, "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: "+
		"protocol: UDP; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\t"+
		"index: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n", explanbilityStr1)
	fmt.Println(explanbilityStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	explanbilityStr2, err2 := vpcConfig.ExplainConnectivity(cidr1, vsi1)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	fmt.Println(explanbilityStr2)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between Public Internet 161.26.0.0/16 and vsi1-ky[10.240.10.4]; "+
		"connection blocked by ingress\n\n", explanbilityStr2)
	explanbilityStr3, err3 := vpcConfig.ExplainConnectivity(vsi1, cidr2)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	require.Equal(t, "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/32: "+
		"protocol: UDP; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n\t"+
		"index: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n", explanbilityStr3)
	fmt.Println(explanbilityStr3)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
}

func TestGroupingExternal(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new.json")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/8"
	explanbilityStr1, err1 := vpcConfig.ExplainConnectivity(vsi1, cidr1)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and Public Internet 161.0.0.0-161.25.255.255,161.27.0.0-161.255.255.255; "+
		"connection blocked by egress\n\n"+
		"The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: protocol: UDP; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
		explanbilityStr1)
	fmt.Println(explanbilityStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	vsi2 := "vsi2-ky[10.240.20.4]"
	cidrAll := "0.0.0.0/0"
	explanbilityStr2, err2 := vpcConfig.ExplainConnectivity(vsi2, cidrAll)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	fmt.Println(explanbilityStr2)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; "+
		"connection blocked by egress\n\n"+
		"The following connection exists between vsi2-ky[10.240.20.4] and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n"+
		"\tindex: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
		explanbilityStr2)
	explanbilityStr3, err3 := vpcConfig.ExplainConnectivity(cidrAll, vsi2)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	fmt.Println(explanbilityStr3)
	require.Equal(t, "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; "+
		"connection blocked by egress\n\nThe following connection exists between vsi2-ky[10.240.20.4] "+
		"and Public Internet 142.0.0.0/8: protocol: ICMPits enabled by\nEgress Rules:\n"+
		"~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n\t"+
		"index: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
		explanbilityStr2)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
}

// getConfigs returns  map[string]*vpcmodel.VPCConfig obj for the input test (config json file)
func getConfig(t *testing.T, inputConfig string) *vpcmodel.VPCConfig {
	inputConfigFile := filepath.Join(getTestsDir(), inputConfig)
	inputConfigContent, err := os.ReadFile(inputConfigFile)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	rc, err := ParseResources(inputConfigContent)
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
