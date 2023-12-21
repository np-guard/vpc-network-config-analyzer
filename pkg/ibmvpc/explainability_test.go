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
func TestExplainability1(t *testing.T) {
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
		"\n\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:"+
		"\n\tindex: 7, direction: inbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n", explanbilityStr1)
	explanbilityStr2, err2 := vpcConfig.ExplainConnectivity("vsi2-ky[10.240.20.4]", "vsi1-ky[10.240.10.4]")
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	fmt.Println(explanbilityStr2)
	require.Equal(t, "The following connection exists between vsi2-ky[10.240.20.4] and vsi1-ky[10.240.10.4]: "+
		"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:"+
		"\n\tindex: 1, direction: outbound, protocol: all, cidr: 10.240.10.0/24\n\nIngress Rules:"+
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
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\nIngress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules"+
		"\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explanbilityStr3)
	explanbilityStr4, err4 := vpcConfig.ExplainConnectivity("vsi1-ky[10.240.10.4]", "vsi2-ky[10.240.20.4]")
	if err4 != nil {
		require.Fail(t, err4.Error())
	}
	fmt.Println(explanbilityStr4)
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]; "+
		"connection blocked by egress\nIngress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.10.4/32\n", explanbilityStr4)
	explanbilityStr5, err5 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi2-ky[10.240.20.4]")
	if err5 != nil {
		require.Fail(t, err5.Error())
	}
	fmt.Println(explanbilityStr5)
	require.Equal(t, "No connection between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]; connection blocked by ingress\n"+
		"Egress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:"+
		"\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n", explanbilityStr5)
	fmt.Println("done")
}

// sg1-ky: vsi1-ky
// sg2-ky: vsi2-ky, vsi3b-ky
// sg3-ky: vsi3a-ky
// sg1-ky, sg3-ky: default
// sg2-ky: allow all
func TestExplainability2(t *testing.T) {
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
		"connection blocked by ingress\nEgress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n"+
		"------------------------\nrules in sg1-ky are the default, namely this is the enabling egress rule:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n", explanbilityStr1)
	// connection, egress (sg3-ky) is default
	explanbilityStr2, err2 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi2-ky[10.240.20.4]")
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	fmt.Println(explanbilityStr2)
	require.Equal(t, "The following connection exists between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]: All Connections; "+
		"its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"rules in sg3-ky are the default, namely this is the enabling egress rule:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n"+
		"Ingress Rules:\n~~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n", explanbilityStr2)
	fmt.Println("done")
}

func TestExplainability3(t *testing.T) {
	vpcConfig := getConfig(t, "input_sg_testing1_new.json")
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	cidr := "0.0.0.0/0"
	myNodes := vpcConfig.TempToTestGetExternalNodes(cidr)
	if myNodes == nil {
		fmt.Println("myNodes is nil")
	} else {
		fmt.Printf("nodes of cidr %v are:\n", cidr)
		for _, node := range myNodes {
			fmt.Println(node.Name())
		}
	}
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
