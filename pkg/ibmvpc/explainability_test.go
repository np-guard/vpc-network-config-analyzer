package ibmvpc

import (
	"fmt"
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// getConfigs returns  map[string]*vpcmodel.VPCConfig obj for the input test (config json file)
func getConfig(t *testing.T, fileName string) *vpcmodel.VPCConfig {
	inputConfigFile := filepath.Join(getTestsDir(), fileName)
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

func getConfigSG(t *testing.T) *vpcmodel.VPCConfig {
	return getConfig(t, "input_sg_testing1_new.json")
}

func TestVsiToVsi(t *testing.T) {
	vpcConfig := getConfigSG(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	explain1, err1 := vpcConfig.ExplainConnectivity("vsi2-ky[10.240.20.4]", "vsi3b-ky[10.240.30.4]", nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	require.Equal(t,
		"The following connection exists between vsi2-ky[10.240.20.4] and vsi3b-ky[10.240.30.4]: protocol: TCP; "+
			"its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n"+
			"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
			"------------------------\nenabling rules from sg2-ky:\n\tindex: 5, direction: outbound, protocol: all, cidr: 10.240.30.0/24\n"+
			"\tindex: 6, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\nIngress Rules:\n"+
			"~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n"+
			"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
			"------------------------\nenabling rules from sg2-ky:\n"+
			"\tindex: 7, direction: inbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n", explainStr1)
	explain2, err2 := vpcConfig.ExplainConnectivity("vsi2-ky[10.240.20.4]", "vsi1-ky[10.240.10.4]", nil)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	explainStr2 := explain2.String()
	fmt.Println(explainStr2)
	require.Equal(t, "The following connection exists between vsi2-ky[10.240.20.4] and vsi1-ky[10.240.10.4]: "+
		"All Connections; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg2-ky:\n\tindex: 1, direction: outbound, protocol: all, cidr: 10.240.10.0/24\n"+
		"Ingress Rules:\n~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, "+
		"action: allow\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg1-ky:\n\tindex: 3, direction: inbound, protocol: all, cidr: 10.240.20.4/32,10.240.30.4/32\n\n", explainStr2)
	explain3, err3 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi1-ky[10.240.10.4]", nil)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	explainStr3 := explain3.String()
	fmt.Println(explainStr3)
	require.Equal(t, "The following connection exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]: "+
		"All Connections; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n"+
		"enabling rules from acl3-ky:\n\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n"+
		"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n"+
		"Ingress Rules:\n~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, "+
		"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explainStr3)
	explain4, err4 := vpcConfig.ExplainConnectivity("vsi1-ky[10.240.10.4]", "vsi2-ky[10.240.20.4]", nil)
	if err4 != nil {
		require.Fail(t, err4.Error())
	}
	explainStr4 := explain4.String()
	fmt.Println(explainStr4)
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]; connection blocked by egress\nIngress Rules:\n"+
		"~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.10.4/32\n\n", explainStr4)
	explain5, err5 := vpcConfig.ExplainConnectivity("vsi3a-ky[10.240.30.5]", "vsi2-ky[10.240.20.4]", nil)
	if err5 != nil {
		require.Fail(t, err5.Error())
	}
	explainStr5 := explain5.String()
	fmt.Println(explainStr5)
	require.Equal(t, "No connection between vsi3a-ky[10.240.30.5] and vsi2-ky[10.240.20.4]; "+
		"connection blocked by ingress\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n"+
		"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\n\n", explainStr5)
	fmt.Println("done")
}

func TestInputValidity(t *testing.T) {
	vpcConfig := getConfigSG(t)
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

func TestSimpleExternalSG(t *testing.T) {
	vpcConfig := getConfigSG(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/16"
	explain1, err1 := vpcConfig.ExplainConnectivity(vsi1, cidr1, nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: "+
		"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n"+
		"~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n", explainStr1)
	explain2, err2 := vpcConfig.ExplainConnectivity(cidr1, vsi1, nil)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	explainStr2 := explain2.String()
	fmt.Println(explainStr2)
	fmt.Println("-------------------------------------------------------------------------------------" +
		"--------------------------------------")
	require.Equal(t, "No connection between Public Internet 161.26.0.0/16 and vsi1-ky[10.240.10.4]; "+
		"no fip router and src is external (fip is required for outbound external connection)\n\n",
		explainStr2)
	cidr2 := "161.26.0.0/32"
	explain3, err3 := vpcConfig.ExplainConnectivity(vsi1, cidr2, nil)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	explainStr3 := explain3.String()
	fmt.Println(explainStr3)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/32: "+
		"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  "+
		"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n", explainStr3)
	vsi3b := "vsi3b-ky[10.240.30.4]"
	explain4, err4 := vpcConfig.ExplainConnectivity(vsi3b, cidr2, nil)
	if err4 != nil {
		require.Fail(t, err4.Error())
	}
	explainStr4 := explain4.String()
	fmt.Println(explainStr4)
	fmt.Println("--------------------------------------------------------------------------------------------------" +
		"-------------------------")
	require.Equal(t, "No connection between vsi3b-ky[10.240.30.4] and Public Internet 161.26.0.0/32; "+
		"no router (fip/pgw) and dst is external\n\n",
		explainStr4)
}

func TestGroupingExternalSG(t *testing.T) {
	vpcConfig := getConfigSG(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/8"
	explain1, err1 := vpcConfig.ExplainConnectivity(vsi1, cidr1, nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and Public Internet 161.0.0.0-161.25.255.255,161.27.0.0-161.255.255.255; "+
		"connection blocked by egress\n\nThe following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: "+
		"protocol: UDP; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n"+
		"------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n", explainStr1)
	// todo: now that external and internal IPs are treated differently, deffer cidrAll test to the time we properly support internal IP #305
	// vsi2 := "vsi2-ky[10.240.20.4]"
	// cidrAll := "0.0.0.0/0"
	// explainStr2, err2 := vpcConfig.ExplainConnectivity(vsi2, cidrAll, nil)
	// if err2 != nil {
	//	require.Fail(t, err2.Error())
	// }
	// fmt.Println(explainStr2)
	// fmt.Println("--------------------------------------------------------------------------
	// -------------------------------------------------")
	// require.Equal(t, "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; "+
	//	"connection blocked by egress\n\n"+
	//	"The following connection exists between vsi2-ky[10.240.20.4] and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\n"+
	//	"Egress Rules:\n~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n"+
	//	"\tindex: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
	//	explainStr2)
	// explainStr3, err3 := vpcConfig.ExplainConnectivity(cidrAll, vsi2, nil)
	// if err3 != nil {
	//	require.Fail(t, err3.Error())
	// }
	// fmt.Println(explainStr3)
	// require.Equal(t, "No connection between vsi2-ky[10.240.20.4] and Public Internet 0.0.0.0-141.255.255.255,143.0.0.0-255.255.255.255; "+
	//	"connection blocked by egress\n\nThe following connection exists between vsi2-ky[10.240.20.4] "+
	//	"and Public Internet 142.0.0.0/8: protocol: ICMP; its enabled by\nEgress Rules:\n"+
	//	"~~~~~~~~~~~~~\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg2-ky:\n\t"+
	//	"index: 3, direction: outbound,  conns: protocol: icmp,  icmpType: protocol: ICMP, cidr: 142.0.0.0/8\n\n",
	//	explainStr2)
	// fmt.Println("----------------------------------------------------------------------------------------------
	// -----------------------------")
}

func TestQueryConnectionSGBasic(t *testing.T) {
	vpcConfig := getConfigSG(t)
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
		"connection blocked by ingress\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg2-ky:\n\tindex: 5, direction: outbound, protocol: all, cidr: 10.240.30.0/24\n\t"+
		"index: 6, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 10.240.20.4/32,10.240.30.4/32\n\n",
		explainStr1)

	// test2: the existing connection is exactly the one required by the query
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/16"
	connectionUDP1 := common.NewConnectionSet(false)
	connectionUDP1.AddTCPorUDPConn(common.ProtocolUDP, common.MinPort, common.MaxPort, common.MinPort, common.MaxPort)
	explain2, err2 := vpcConfig.ExplainConnectivity(vsi1, cidr1, connectionUDP1)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	explainStr2 := explain2.String()
	fmt.Println(explainStr2)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "Connection protocol: UDP exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16; its enabled by\n"+
		"External Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n"+
		"enabling rules from acl1-ky:\n\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, "+
		"conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  "+
		"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
		explainStr2)

	//test3: the required connection is contained in the existing one per connection
	connectionUDP2 := common.NewConnectionSet(false)
	connectionUDP2.AddTCPorUDPConn(common.ProtocolUDP, 10, 100, 443, 443)
	explain3, err3 := vpcConfig.ExplainConnectivity(vsi1, cidr1, connectionUDP2)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	explainStr3 := explain3.String()
	fmt.Println(explainStr3)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] and "+
		"Public Internet 161.26.0.0/16; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  "+
		"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
		explainStr3)

	// test4: the required connection is contained in the existing one per ip of src/dst
	cidr2 := "161.26.0.0/20"
	explain4, err4 := vpcConfig.ExplainConnectivity(vsi1, cidr2, connectionUDP2)
	if err4 != nil {
		require.Fail(t, err4.Error())
	}
	explainStr4 := explain4.String()
	fmt.Println(explainStr4)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] and "+
		"Public Internet 161.26.0.0/20; its enabled by\nExternal Router PublicGateway: public-gw-ky\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 2, direction: outbound,  "+
		"conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\n",
		explainStr4)

	// test5: the required connection exists for part of the dst ip
	cidr3 := "161.26.0.0/12"
	explain5, err5 := vpcConfig.ExplainConnectivity(vsi1, cidr3, connectionUDP2)
	if err5 != nil {
		require.Fail(t, err5.Error())
	}
	explainStr5 := explain5.String()
	fmt.Println(explainStr5)
	fmt.Println("-------------------------------------------------------------------------------------" +
		"--------------------------------------")
	require.Equal(t, "Connection protocol: UDP src-ports: 10-100 dst-ports: 443 exists between vsi1-ky[10.240.10.4] and "+
		"Public Internet 161.26.0.0/16; its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n\t"+
		"index: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg1-ky:\n\t"+
		"index: 2, direction: outbound,  conns: protocol: udp,  dstPorts: 1-65535, cidr: 161.26.0.0/16\n\nThere is no connection \""+
		"protocol: UDP src-ports: 10-100 dst-ports: 443\" between vsi1-ky[10.240.10.4] and "+
		"Public Internet 161.16.0.0-161.25.255.255,161.27.0.0-161.31.255.255; "+
		"connection blocked by egress\n\n", explainStr5)

	// test6: a connection does not exist regardless of the query
	explain6, err6 := vpcConfig.ExplainConnectivity("vsi1-ky[10.240.10.4]", "vsi3a-ky[10.240.30.5]", connectionUDP2)
	if err6 != nil {
		require.Fail(t, err6.Error())
	}
	explainStr6 := explain6.String()
	fmt.Println(explainStr6)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "There is no connection \"protocol: UDP src-ports: 10-100 dst-ports: 443\" "+
		"between vsi1-ky[10.240.10.4] and vsi3a-ky[10.240.30.5]; "+
		"connection blocked both by ingress and egress\n\n", explainStr6)
}

func TestQueryConnectionSGRules(t *testing.T) {
	vpcConfig := getConfigSG(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	// test1: all rules are relevant (for comparison)
	vsi1 := "vsi1-ky[10.240.10.4]"
	vsi3a := "vsi3a-ky[10.240.30.5]"
	explain1, err1 := vpcConfig.ExplainConnectivity(vsi3a, vsi1, nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	require.Equal(t, "The following connection exists between vsi3a-ky[10.240.30.5] "+
		"and vsi1-ky[10.240.10.4]: All Connections; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n"+
		"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, "+
		"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explainStr1)
	// test 2: only a subset of the rules are relevant, protocol wise
	connectionUDP1 := common.NewConnectionSet(false)
	connectionUDP1.AddTCPorUDPConn(common.ProtocolUDP, common.MinPort, common.MaxPort, common.MinPort, common.MaxPort)
	explain2, err2 := vpcConfig.ExplainConnectivity(vsi3a, vsi1, connectionUDP1)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	explainStr2 := explain2.String()
	fmt.Println(explainStr2)
	require.Equal(t, "Connection protocol: UDP exists between vsi3a-ky[10.240.30.5] and vsi1-ky[10.240.10.4]; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, "+
		"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explainStr2)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")

	// test 3: only a subset of the rules are relevant, port wise and protocol wise
	connectionTCP1 := common.NewConnectionSet(false)
	connectionTCP1.AddTCPorUDPConn(common.ProtocolTCP, common.MinPort, common.MaxPort, 50, 54)
	explain3, err3 := vpcConfig.ExplainConnectivity(vsi3a, vsi1, connectionTCP1)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	explainStr3 := explain3.String()
	fmt.Println(explainStr3)
	require.Equal(t, "Connection protocol: TCP dst-ports: 50-54 exists between vsi3a-ky[10.240.30.5] "+
		"and vsi1-ky[10.240.10.4]; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n\t"+
		"index: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg3-ky:\n\t"+
		"index: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\t"+
		"index: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 4, direction: inbound, protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explainStr3)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")

	// test 4: all rules are relevant, with specified port wise protocol
	connectionTCP2 := common.NewConnectionSet(false)
	connectionTCP2.AddTCPorUDPConn(common.ProtocolTCP, common.MinPort, common.MaxPort, 120, 230)
	explain4, err4 := vpcConfig.ExplainConnectivity(vsi3a, vsi1, connectionTCP2)
	if err4 != nil {
		require.Fail(t, err4.Error())
	}
	explainStr4 := explain4.String()
	fmt.Println(explainStr4)
	require.Equal(t, "Connection protocol: TCP dst-ports: 120-230 exists between vsi3a-ky[10.240.30.5] "+
		"and vsi1-ky[10.240.10.4]; its enabled by\n"+
		"Egress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n"+
		"\tindex: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg3-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n"+
		"\tindex: 2, direction: outbound,  conns: protocol: tcp,  dstPorts: 1-65535, cidr: 0.0.0.0/0\n"+
		"\tindex: 3, direction: outbound,  conns: protocol: tcp,  dstPorts: 100-200, cidr: 0.0.0.0/0\nIngress Rules:\n~~~~~~~~~~~~~~\n"+
		"NaclLayer Rules\n------------------------\nenabling rules from acl1-ky:\n"+
		"\tindex: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 4, direction: inbound, "+
		"protocol: all, cidr: 10.240.30.5/32,10.240.30.6/32\n\n", explainStr4)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
}

func getConfigNACL(t *testing.T) *vpcmodel.VPCConfig {
	return getConfig(t, "input_acl_testing3.json")
}

func TestNACLExternal(t *testing.T) {
	vpcConfig := getConfigNACL(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	// connection exists to external
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/16"
	explain1, err1 := vpcConfig.ExplainConnectivity(vsi1, cidr1, nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: protocol: UDP; "+
		"its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n"+
		"enabling rules from acl1-ky:\n\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: protocol: udp, "+
		"srcPorts: 1-65535, dstPorts: 1-65535, action: allow\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n", explainStr1)
	// connection does not exist to external, blocked by egress
	cidr2 := "100.128.0.0/32"
	explain2, err2 := vpcConfig.ExplainConnectivity(vsi1, cidr2, nil)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	explainStr2 := explain2.String()
	fmt.Println(explainStr2)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and Public Internet 100.128.0.0/32;"+
		" connection blocked by egress\n\n", explainStr2)
	// connection does not exist to external, blocked by ingress
	explain3, err3 := vpcConfig.ExplainConnectivity(cidr2, vsi1, nil)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	explainStr3 := explain3.String()
	fmt.Println(explainStr3)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between Public Internet 100.128.0.0/32 and vsi1-ky[10.240.10.4]; no fip router and src is external"+
		" (fip is required for outbound external connection)\n\n", explainStr3)
}

func TestNACLInternal(t *testing.T) {
	vpcConfig := getConfigNACL(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	// connection between 2 vsis
	vsi1 := "vsi1-ky[10.240.10.4]"
	vsi2 := "vsi2-ky[10.240.20.4]"
	explain1, err1 := vpcConfig.ExplainConnectivity(vsi1, vsi2, nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "The following connection exists between vsi1-ky[10.240.10.4] and vsi2-ky[10.240.20.4]: "+
		"protocol: TCP,UDP; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n"+
		"enabling rules from acl1-ky:\n"+
		"\tindex: 2, direction: outbound , src: 10.240.10.0/24 , dst: 10.240.20.0/24, conn: all, action: allow\nSecurityGroupLayer Rules\n"+
		"------------------------\nenabling rules from sg1-ky:\n\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n"+
		"Ingress Rules:\n~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl2-ky:\n"+
		"\tindex: 6, direction: inbound , src: 10.240.10.0/24 , dst: 10.240.20.0/24, conn: all, action: allow\nSecurityGroupLayer Rules\n------------------------\n"+
		"enabling rules from sg1-ky:\n\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n", explainStr1)
	explain2, err2 := vpcConfig.ExplainConnectivity(vsi2, vsi1, nil)
	if err2 != nil {
		require.Fail(t, err2.Error())
	}
	explainStr2 := explain2.String()
	fmt.Println(explainStr2)
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------")
	vsi3a := "vsi3a-ky[10.240.30.5]"
	explain3, err3 := vpcConfig.ExplainConnectivity(vsi1, vsi3a, nil)
	if err3 != nil {
		require.Fail(t, err3.Error())
	}
	// connection blocked one way between 2 vsis
	explainStr3 := explain3.String()
	fmt.Println(explainStr3)
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and vsi3a-ky[10.240.30.5]; connection blocked by egress\nIngress Rules:\n"+
		"~~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\nenabling rules from acl3-ky:\n"+
		"\tindex: 2, direction: inbound , src: 10.240.10.0/24 , dst: 0.0.0.0/0, conn: all, action: allow\n"+
		"SecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 1, direction: inbound, protocol: all, cidr: 0.0.0.0/0\n\n", explainStr3)
}

func TestNACLGrouping(t *testing.T) {
	vpcConfig := getConfigNACL(t)
	if vpcConfig == nil {
		require.Fail(t, "vpcConfig equals nil")
	}
	// connection exists to external
	vsi1 := "vsi1-ky[10.240.10.4]"
	cidr1 := "161.26.0.0/15"
	explain1, err1 := vpcConfig.ExplainConnectivity(vsi1, cidr1, nil)
	if err1 != nil {
		require.Fail(t, err1.Error())
	}
	explainStr1 := explain1.String()
	fmt.Println(explainStr1)
	fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
	require.Equal(t, "No connection between vsi1-ky[10.240.10.4] and Public Internet 161.27.0.0/16; connection blocked by egress\n\n"+
		"The following connection exists between vsi1-ky[10.240.10.4] and Public Internet 161.26.0.0/16: protocol: UDP; "+
		"its enabled by\nExternal Router PublicGateway: public-gw-ky\nEgress Rules:\n~~~~~~~~~~~~~\nNaclLayer Rules\n------------------------\n"+
		"enabling rules from acl1-ky:\n\tindex: 1, direction: outbound , src: 10.240.10.0/24 , dst: 161.26.0.0/16, conn: protocol: udp, "+
		"srcPorts: 1-65535, dstPorts: 1-65535, action: allow\nSecurityGroupLayer Rules\n------------------------\nenabling rules from sg1-ky:\n"+
		"\tindex: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0\n\n", explainStr1)
}
