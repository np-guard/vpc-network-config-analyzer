/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

/* basic unit-tests  for vpc connectivity analysis
GetVPCNetworkConnectivity() of CloudConfig
computing connectivity between nodes (network interfaces and external addresses):
- ingress/egress (separately)
- combined (stateless)
- combined ad stateful
*/

// testNodesConfig contains basic config details: subnets and interfaces
type testNodesConfig struct {
	subnets       map[string]string   // subnet name to its cidr
	netInterfaces map[string][]string // subnet cidr to a list of interface address within it (names according to index and subnet name )
}

// naclConfig contains basic nacl config details, should refer to subnets in testNodesConfig object
type naclConfig struct {
	name         string
	ingressRules []*commonvpc.NACLRule
	egressRules  []*commonvpc.NACLRule
	subnets      []string // subnet cidrs
}

// test objects below

// tc1 : simple config, 2 subnets, one instance per subnet
var tc1 = &testNodesConfig{
	subnets: map[string]string{
		"subnet-1": "10.240.10.0/24",
		"subnet-2": "10.240.20.0/24",
	},
	netInterfaces: map[string][]string{
		"10.240.10.0/24": {"10.240.10.4"},
		"10.240.20.0/24": {"10.240.20.4"},
	},
}

// nc1: simple nacl config: allow-all applied to both subnets in tc1
var nc1 = &naclConfig{
	name:         "nacl-1",
	ingressRules: getAllowAllRules(),
	egressRules:  getAllowAllRules(),
	subnets:      []string{"10.240.10.0/24", "10.240.20.0/24"},
}

// nc2: allow-all applied to subnet-1 in tc1
var nc2 = &naclConfig{
	name:         "nacl-2",
	ingressRules: getAllowAllRules(),
	egressRules:  getAllowAllRules(),
	subnets:      []string{"10.240.10.0/24"},
}

var nc2a = &naclConfig{
	name:         "nacl-2-a",
	ingressRules: getDenyAllRules(),
	egressRules:  getAllowICMPRules(),
	subnets:      []string{"10.240.10.0/24"},
}

var nc3a = &naclConfig{
	name:         "nacl-3-a",
	ingressRules: getAllowICMPRules(),
	egressRules:  getDenyAllRules(),
	subnets:      []string{"10.240.20.0/24"},
}

// nc3: limited egress (cannot egress outside the subnet) applied to  subnet-2 in tc1
var nc3 = &naclConfig{
	name:         "nacl-3",
	ingressRules: getAllowAllRules(),
	egressRules: []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.240.20.0/24"),
			Connections: connection.All(),
			Action:      "allow",
		},
	},
	subnets: []string{"10.240.20.0/24"},
}

// nc4: limited egress (only TCP allowed to all destinations) applied to  subnet-2 in tc1
var nc4 = &naclConfig{
	name:         "nacl-4",
	ingressRules: getAllowAllRules(),
	egressRules: []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: connection.TCPorUDPConnection(netp.ProtocolStringTCP, netp.MinPort, netp.MaxPort, netp.MinPort, netp.MaxPort),
			Action:      "allow",
		},
	},
	subnets: []string{"10.240.20.0/24"},
}

func nc5Conn() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, 10, 100, 443, 443)
}

// nc5 - applied to subnet-1, limited egress (certain TCP ports allowed)
var nc5 = &naclConfig{
	name:         "nacl-5",
	ingressRules: getAllowAllRules(),
	egressRules: []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: nc5Conn(),
			Action:      "allow",
		},
	},
	subnets: []string{"10.240.10.0/24"},
}

func nc6Conn() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, 443, 443, 10, 100)
}

var nc6 = &naclConfig{
	name:         "nacl-6",
	ingressRules: getAllowAllRules(),
	egressRules: []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: nc6Conn(),
			Action:      "allow",
		},
	},
	subnets: []string{"10.240.20.0/24"},
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// tests below

var expectedConnStrTest1 = `vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : All Connections
`

func TestAnalyzeConnectivity1(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc1}, expectedConnStrTest1)
}

var expectedConnStrTest2 = `vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : TCP * ; ICMP,UDP
`

func TestAnalyzeConnectivity2(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc2, nc3}, expectedConnStrTest2)
}

var expectedConnStrTest2a = `vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : ICMP
` // ICMP is actually enabled only unidirectional in this case, but responsive analysis does not apply to ICMP

func TestAnalyzeConnectivity2a(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc2a, nc3a}, expectedConnStrTest2a)
}

var expectedConnStrTest3 = `vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : TCP
`

func TestAnalyzeConnectivity3(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc2, nc4}, expectedConnStrTest3)
}

var expectedConnStrTest4 = `vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : TCP src-ports: 10-100 dst-ports: 443
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : TCP src-ports: 443 dst-ports: 10-100
`

func TestAnalyzeConnectivity4(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc5, nc6}, expectedConnStrTest4)
}

func runConnectivityTest(t *testing.T, tc *testNodesConfig, ncList []*naclConfig, expectedStrResult string) {
	c := createConfigFromTestConfig(tc, ncList)
	connectivity, err := c.GetVPCNetworkConnectivity(false, false)
	require.Nil(t, err)
	connectivityStr := connectivity.String()
	fmt.Println(connectivityStr)
	fmt.Println("done")
	require.Equal(t, expectedStrResult, connectivityStr)
}

////////////////////////////////////////////////////////////////////////////////////////////////

func createConfigFromTestConfig(tc *testNodesConfig, ncList []*naclConfig) *vpcmodel.VPCConfig {
	config := &vpcmodel.VPCConfig{}
	for name, cidr := range tc.subnets {
		addSubnet(config, name, cidr, "z1")
		if subnetInterfaces, ok := tc.netInterfaces[cidr]; ok {
			for index, intfAddress := range subnetInterfaces {
				intfName := fmt.Sprintf("intf-%d-%s", index, name)
				vsiName := fmt.Sprintf("vsi-%d-%s", index, name)
				addInterfaceNode(config, intfName, intfAddress, vsiName, name)
			}
		}
	}
	for _, nc := range ncList {
		analyzer := &commonvpc.NACLAnalyzer{
			//naclResource:    nacl,
			AnalyzedSubnets: map[string]*commonvpc.AnalysisResultPerSubnet{},
			IngressRules:    nc.ingressRules,
			EgressRules:     nc.egressRules,
		}
		subnets := map[string]*commonvpc.Subnet{}
		for _, s := range nc.subnets {
			subnets[s] = nil // not required for the test
		}
		addNACL(config, nc.name, subnets, analyzer)
	}

	return config
}

func getAllowAllRules() []*commonvpc.NACLRule {
	return []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: connection.All(),
			Action:      "allow",
		},
	}
}

func getDenyAllRules() []*commonvpc.NACLRule {
	return []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: connection.All(),
			Action:      "deny",
		},
	}
}

func getAllowICMPRules() []*commonvpc.NACLRule {
	return []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: icmpConn(),
			Action:      "allow",
		},
	}
}

func icmpConn() *connection.Set {
	return connection.ICMPConnection(
		connection.MinICMPType, connection.MaxICMPType,
		connection.MinICMPCode, connection.MaxICMPCode)
}

func addInterfaceNode(config *vpcmodel.VPCConfig, name, address, vsiName, subnetName string) {
	intfNode := &commonvpc.NetworkInterface{
		VPCResource:  vpcmodel.VPCResource{ResourceName: name, ResourceUID: name, ResourceType: commonvpc.ResourceTypeNetworkInterface},
		InternalNode: vpcmodel.InternalNode{AddressStr: address, IPBlockObj: newIPBlockFromCIDROrAddressWithoutValidation(address)},
		Vsi:          vsiName,
	}
	// add references between subnet to interface (both directions)
	for _, subnet := range config.Subnets {
		if subnet.Name() == subnetName {
			subnetActual := subnet.(*commonvpc.Subnet)
			intfNode.SubnetResource = subnetActual
			subnetActual.VPCnodes = append(subnetActual.VPCnodes, intfNode)
		}
	}

	config.Nodes = append(config.Nodes, intfNode)
}

func addSubnet(config *vpcmodel.VPCConfig, name, cidr, zone string) *commonvpc.Subnet {
	subnetNode := &commonvpc.Subnet{
		VPCResource: vpcmodel.VPCResource{ResourceName: name, ResourceUID: name, Zone: zone, ResourceType: commonvpc.ResourceTypeSubnet},
		Cidr:        cidr,
		IPblock:     newIPBlockFromCIDROrAddressWithoutValidation(cidr),
	}
	config.Subnets = append(config.Subnets, subnetNode)
	return subnetNode
}

func addNACL(config *vpcmodel.VPCConfig, name string, subnets map[string]*commonvpc.Subnet, analyzer *commonvpc.NACLAnalyzer) {
	var layer *commonvpc.NaclLayer
	for _, fr := range config.FilterResources {
		if fr.Kind() == "NaclLayer" {
			layer = fr.(*commonvpc.NaclLayer)
			break
		}
	}
	if layer == nil {
		layer = &commonvpc.NaclLayer{
			VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.NaclLayer},
			NaclList:    []*commonvpc.NACL{}}
		config.FilterResources = append(config.FilterResources, layer)
	}

	// create the new nacl
	naclResource := &commonvpc.NACL{
		VPCResource: vpcmodel.VPCResource{ResourceName: name, ResourceUID: name, ResourceType: commonvpc.ResourceTypeNACL},
		Analyzer:    analyzer, /*&commonvpc.NACLAnalyzer{
			//naclResource:    nacl,
			analyzedSubnets: map[string]*commonvpc.AnalysisResultPerSubnet{},
		},*/
		Subnets: subnets,
	}

	// add the nacl to the layer
	layer.NaclList = append(layer.NaclList, naclResource)
}

func newSimpleNACLAnalyzer() *commonvpc.NACLAnalyzer {
	analyzer := &commonvpc.NACLAnalyzer{
		//naclResource:    nacl,
		AnalyzedSubnets: map[string]*commonvpc.AnalysisResultPerSubnet{},
	}

	analyzer.IngressRules = getAllowAllRules()
	analyzer.EgressRules = getAllowAllRules()

	return analyzer
}

// simple config : 2 vsis in different subnets, nacl that allows all (for the 2 subnets), no SG layer
func NewSimpleVPCConfig() *vpcmodel.VPCConfig {
	config := &vpcmodel.VPCConfig{}
	s1 := addSubnet(config, "subnet-1", "10.240.10.0/24", "z1")
	s2 := addSubnet(config, "subnet-2", "10.240.20.0/24", "z1")
	addInterfaceNode(config, "intf-1", "10.240.10.4", "vsi-1", "subnet-1")
	addInterfaceNode(config, "intf-1", "10.240.20.4", "vsi-2", "subnet-2")
	addNACL(config, "nacl-1", map[string]*commonvpc.Subnet{"10.240.10.0/24": s1, "10.240.20.0/24": s2}, newSimpleNACLAnalyzer())
	return config
}

/*
=================================== distributed inbound/outbound connections:
10.240.10.4 => 10.240.20.4 : All Connections [inbound]
10.240.10.4 => 10.240.20.4 : All Connections [outbound]
10.240.20.4 => 10.240.10.4 : All Connections [inbound]
10.240.20.4 => 10.240.10.4 : All Connections [outbound]
=================================== combined connections:
10.240.10.4 => 10.240.20.4 : All Connections
10.240.20.4 => 10.240.10.4 : All Connections
=================================== combined connections - short version:
vsi-1[10.240.10.4] => vsi-2[10.240.20.4] : All Connections
vsi-2[10.240.20.4] => vsi-1[10.240.10.4] : All Connections
=================================== responsive combined connections - short version:
vsi-1[10.240.10.4] => vsi-2[10.240.20.4] : All Connections
vsi-2[10.240.20.4] => vsi-1[10.240.10.4] : All Connections
*/
func TestAnalyzeConnectivity(t *testing.T) {
	c := NewSimpleVPCConfig()
	connectivity, err := c.GetVPCNetworkConnectivity(false, false)
	require.Nil(t, err)
	connectivityStr := connectivity.String()
	fmt.Println(connectivityStr)
	fmt.Println("done")
}
