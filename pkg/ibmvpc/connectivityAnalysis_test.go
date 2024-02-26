package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
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
	ingressRules []*NACLRule
	egressRules  []*NACLRule
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
	egressRules: []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.240.20.0/24"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	},
	subnets: []string{"10.240.20.0/24"},
}

// nc4: limited egress (only TCP allowed to all destinations) applied to  subnet-2 in tc1
var nc4 = &naclConfig{
	name:         "nacl-4",
	ingressRules: getAllowAllRules(),
	egressRules: []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: common.NewTCPConnectionSet(),
			action:      "allow",
		},
	},
	subnets: []string{"10.240.20.0/24"},
}

func nc5Conn() *common.ConnectionSet {
	res := common.NewConnectionSet(false)
	res.AddTCPorUDPConn(common.ProtocolTCP, 10, 100, 443, 443)
	return res
}

// nc5 - applied to subnet-1, limited egress (certain TCP ports allowed)
var nc5 = &naclConfig{
	name:         "nacl-5",
	ingressRules: getAllowAllRules(),
	egressRules: []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: nc5Conn(),
			action:      "allow",
		},
	},
	subnets: []string{"10.240.10.0/24"},
}

func nc6Conn() *common.ConnectionSet {
	res := common.NewConnectionSet(false)
	res.AddTCPorUDPConn(common.ProtocolTCP, 443, 443, 10, 100)
	return res
}

var nc6 = &naclConfig{
	name:         "nacl-6",
	ingressRules: getAllowAllRules(),
	egressRules: []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: nc6Conn(),
			action:      "allow",
		},
	},
	subnets: []string{"10.240.20.0/24"},
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// tests below

var expectedConnStrTest1 = `=================================== distributed inbound/outbound connections:
10.240.10.4 => 10.240.20.4 : All Connections [inbound]
10.240.10.4 => 10.240.20.4 : All Connections [outbound]
10.240.20.4 => 10.240.10.4 : All Connections [inbound]
10.240.20.4 => 10.240.10.4 : All Connections [outbound]
=================================== combined connections:
10.240.10.4 => 10.240.20.4 : All Connections
10.240.20.4 => 10.240.10.4 : All Connections
=================================== combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : All Connections
=================================== stateful combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : All Connections
`

func TestAnalyzeConnectivity1(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc1}, expectedConnStrTest1)
}

var expectedConnStrTest2 = `=================================== distributed inbound/outbound connections:
10.240.10.4 => 10.240.20.4 : All Connections [inbound]
10.240.10.4 => 10.240.20.4 : All Connections [outbound]
10.240.20.4 => 10.240.10.4 : All Connections [inbound]
10.240.20.4 => 10.240.10.4 : No Connections [outbound]
=================================== combined connections:
10.240.10.4 => 10.240.20.4 : All Connections
10.240.20.4 => 10.240.10.4 : No Connections
=================================== combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections *
=================================== stateful combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : protocol: UDP,ICMP
`

func TestAnalyzeConnectivity2(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc2, nc3}, expectedConnStrTest2)
}

var expectedConnStrTest2a = `=================================== distributed inbound/outbound connections:
10.240.10.4 => 10.240.20.4 : protocol: ICMP [inbound]
10.240.10.4 => 10.240.20.4 : protocol: ICMP [outbound]
10.240.20.4 => 10.240.10.4 : No Connections [inbound]
10.240.20.4 => 10.240.10.4 : No Connections [outbound]
=================================== combined connections:
10.240.10.4 => 10.240.20.4 : protocol: ICMP
10.240.20.4 => 10.240.10.4 : No Connections
=================================== combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : protocol: ICMP
=================================== stateful combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : protocol: ICMP
` // ICMP is actually enabled only unidirectional in this case, but stateful analysis does not apply to ICMP

func TestAnalyzeConnectivity2a(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc2a, nc3a}, expectedConnStrTest2a)
}

var expectedConnStrTest3 = `=================================== distributed inbound/outbound connections:
10.240.10.4 => 10.240.20.4 : All Connections [inbound]
10.240.10.4 => 10.240.20.4 : All Connections [outbound]
10.240.20.4 => 10.240.10.4 : All Connections [inbound]
10.240.20.4 => 10.240.10.4 : protocol: TCP [outbound]
=================================== combined connections:
10.240.10.4 => 10.240.20.4 : All Connections
10.240.20.4 => 10.240.10.4 : protocol: TCP
=================================== combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : protocol: TCP
=================================== stateful combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : All Connections
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : protocol: TCP
`

func TestAnalyzeConnectivity3(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc2, nc4}, expectedConnStrTest3)
}

var expectedConnStrTest4 = `=================================== distributed inbound/outbound connections:
10.240.10.4 => 10.240.20.4 : All Connections [inbound]
10.240.10.4 => 10.240.20.4 : protocol: TCP src-ports: 10-100 dst-ports: 443 [outbound]
10.240.20.4 => 10.240.10.4 : All Connections [inbound]
10.240.20.4 => 10.240.10.4 : protocol: TCP src-ports: 443 dst-ports: 10-100 [outbound]
=================================== combined connections:
10.240.10.4 => 10.240.20.4 : protocol: TCP src-ports: 10-100 dst-ports: 443
10.240.20.4 => 10.240.10.4 : protocol: TCP src-ports: 443 dst-ports: 10-100
=================================== combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : protocol: TCP src-ports: 10-100 dst-ports: 443
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : protocol: TCP src-ports: 443 dst-ports: 10-100
=================================== stateful combined connections - short version:
vsi-0-subnet-1[10.240.10.4] => vsi-0-subnet-2[10.240.20.4] : protocol: TCP src-ports: 10-100 dst-ports: 443
vsi-0-subnet-2[10.240.20.4] => vsi-0-subnet-1[10.240.10.4] : protocol: TCP src-ports: 443 dst-ports: 10-100
`

func TestAnalyzeConnectivity4(t *testing.T) {
	runConnectivityTest(t, tc1, []*naclConfig{nc5, nc6}, expectedConnStrTest4)
}

func runConnectivityTest(t *testing.T, tc *testNodesConfig, ncList []*naclConfig, expectedStrResult string) {
	c := createConfigFromTestConfig(tc, ncList)
	connectivity, err := c.GetVPCNetworkConnectivity(false)
	require.Nil(t, err)
	connectivityStr := connectivity.DetailedString()
	fmt.Println(connectivityStr)
	fmt.Println("done")
	require.Equal(t, expectedStrResult, connectivityStr)
}

////////////////////////////////////////////////////////////////////////////////////////////////

func createConfigFromTestConfig(tc *testNodesConfig, ncList []*naclConfig) *vpcmodel.VPCConfig {
	config := &vpcmodel.VPCConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
	}
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
		analyzer := &NACLAnalyzer{
			//naclResource:    nacl,
			analyzedSubnets: map[string]*AnalysisResultPerSubnet{},
			ingressRules:    nc.ingressRules,
			egressRules:     nc.egressRules,
		}
		subnets := map[string]*Subnet{}
		for _, s := range nc.subnets {
			subnets[s] = nil // not required for the test
		}
		addNACL(config, nc.name, subnets, analyzer)
	}

	return config
}

func getAllowAllRules() []*NACLRule {
	return []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}
}

func getDenyAllRules() []*NACLRule {
	return []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "deny",
		},
	}
}

func getAllowICMPRules() []*NACLRule {
	return []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: icmpConn(),
			action:      "allow",
		},
	}
}

func icmpConn() *common.ConnectionSet {
	res := common.NewConnectionSet(false)
	res.AddICMPConnection(common.MinICMPtype, common.MaxICMPtype, common.MinICMPcode, common.MaxICMPcode)
	return res
}

func addInterfaceNode(config *vpcmodel.VPCConfig, name, address, vsiName, subnetName string) {
	intfNode := &NetworkInterface{
		VPCResource:  vpcmodel.VPCResource{ResourceName: name, ResourceUID: name, ResourceType: ResourceTypeNetworkInterface},
		InternalNode: vpcmodel.InternalNode{AddressStr: address, IPBlockObj: newIPBlockFromCIDROrAddressWithoutValidation(address)},
		vsi:          vsiName,
	}
	// add references between subnet to interface (both directions)
	for _, subnet := range config.NodeSets {
		if subnet.Name() == subnetName {
			subnetActual := subnet.(*Subnet)
			intfNode.subnet = subnetActual
			subnetActual.nodes = append(subnetActual.nodes, intfNode)
		}
	}

	config.Nodes = append(config.Nodes, intfNode)
}

func addSubnet(config *vpcmodel.VPCConfig, name, cidr, zone string) *Subnet {
	subnetNode := &Subnet{
		VPCResource: vpcmodel.VPCResource{ResourceName: name, ResourceUID: name, Zone: zone, ResourceType: ResourceTypeSubnet},
		cidr:        cidr,
		ipblock:     newIPBlockFromCIDROrAddressWithoutValidation(cidr),
	}
	config.NodeSets = append(config.NodeSets, subnetNode)
	return subnetNode
}

func addNACL(config *vpcmodel.VPCConfig, name string, subnets map[string]*Subnet, analyzer *NACLAnalyzer) {
	var layer *NaclLayer
	for _, fr := range config.FilterResources {
		if fr.Kind() == "NaclLayer" {
			layer = fr.(*NaclLayer)
			break
		}
	}
	if layer == nil {
		layer = &NaclLayer{
			VPCResource: vpcmodel.VPCResource{ResourceType: vpcmodel.NaclLayer},
			naclList:    []*NACL{}}
		config.FilterResources = append(config.FilterResources, layer)
	}

	// create the new nacl
	naclResource := &NACL{
		VPCResource: vpcmodel.VPCResource{ResourceName: name, ResourceUID: name, ResourceType: ResourceTypeNACL},
		analyzer:    analyzer, /*&NACLAnalyzer{
			//naclResource:    nacl,
			analyzedSubnets: map[string]*AnalysisResultPerSubnet{},
		},*/
		subnets: subnets,
	}

	// add the nacl to the layer
	layer.naclList = append(layer.naclList, naclResource)
}

func newSimpleNACLAnalyzer() *NACLAnalyzer {
	analyzer := &NACLAnalyzer{
		//naclResource:    nacl,
		analyzedSubnets: map[string]*AnalysisResultPerSubnet{},
	}

	analyzer.ingressRules = getAllowAllRules()
	analyzer.egressRules = getAllowAllRules()

	return analyzer
}

// simple config : 2 vsis in different subnets, nacl that allows all (for the 2 subnets), no SG layer
func NewSimpleVPCConfig() *vpcmodel.VPCConfig {
	config := &vpcmodel.VPCConfig{
		Nodes:            []vpcmodel.Node{},
		NodeSets:         []vpcmodel.NodeSet{},
		FilterResources:  []vpcmodel.FilterTrafficResource{},
		RoutingResources: []vpcmodel.RoutingResource{},
	}
	s1 := addSubnet(config, "subnet-1", "10.240.10.0/24", "z1")
	s2 := addSubnet(config, "subnet-2", "10.240.20.0/24", "z1")
	addInterfaceNode(config, "intf-1", "10.240.10.4", "vsi-1", "subnet-1")
	addInterfaceNode(config, "intf-1", "10.240.20.4", "vsi-2", "subnet-2")
	addNACL(config, "nacl-1", map[string]*Subnet{"10.240.10.0/24": s1, "10.240.20.0/24": s2}, newSimpleNACLAnalyzer())
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
=================================== stateful combined connections - short version:
vsi-1[10.240.10.4] => vsi-2[10.240.20.4] : All Connections
vsi-2[10.240.20.4] => vsi-1[10.240.10.4] : All Connections
*/
func TestAnalyzeConnectivity(t *testing.T) {
	c := NewSimpleVPCConfig()
	connectivity, err := c.GetVPCNetworkConnectivity(false)
	require.Nil(t, err)
	connectivityStr := connectivity.DetailedString()
	fmt.Println(connectivityStr)
	fmt.Println("done")
}

func newIPBlockFromCIDROrAddressWithoutValidation(cidr string) *ipblocks.IPBlock {
	res, _ := ipblocks.NewIPBlockFromCidrOrAddress(cidr)
	return res
}
