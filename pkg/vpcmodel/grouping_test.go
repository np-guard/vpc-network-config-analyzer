package vpcmodel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type mockVPCIntf struct {
	VPCResource
}

func (mockVPC *mockVPCIntf) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}

func (mockVPC *mockVPCIntf) ShowOnSubnetMode() bool { return true }

type mockNetIntf struct {
	cidr     string
	isPublic bool
	name     string
	subnet   Subnet
}

func (m *mockNetIntf) CidrOrAddress() string {
	return m.cidr
}
func (m *mockNetIntf) IPBlock() *ipblock.IPBlock {
	res, _ := ipblock.FromCidrOrAddress(m.cidr)
	return res
}
func (m *mockNetIntf) Address() string {
	return ""
}
func (m *mockNetIntf) Subnet() Subnet {
	return m.subnet
}

func (m *mockNetIntf) IsInternal() bool {
	return !m.isPublic
}
func (m *mockNetIntf) IsPublicInternet() bool {
	return m.isPublic
}
func (m *mockNetIntf) Kind() string {
	return "NetworkInterface"
}
func (m *mockNetIntf) UID() string {
	return m.name
}
func (m *mockNetIntf) Name() string {
	return m.name
}
func (m *mockNetIntf) ZoneName() string {
	return ""
}
func (m *mockNetIntf) RegionName() string {
	return ""
}
func (m *mockNetIntf) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}
func (m *mockNetIntf) IsExternal() bool       { return m.isPublic }
func (m *mockNetIntf) ShowOnSubnetMode() bool { return false }

func (m *mockNetIntf) VPC() VPCResourceIntf {
	return nil
}

func (m *mockNetIntf) AppliedFiltersKinds(otherNode InternalNodeIntf) map[string]bool {
	return nil
}

type mockSubnet struct {
	vpc   VPCResourceIntf
	cidr  string
	name  string
	nodes []Node
}

func (m *mockSubnet) UID() string {
	return m.name
}
func (m *mockSubnet) Name() string {
	return m.name
}
func (m *mockSubnet) Nodes() []Node {
	return m.nodes
}
func (m *mockSubnet) AddressRange() *ipblock.IPBlock {
	return nil
}
func (m *mockSubnet) CIDR() string {
	return m.cidr
}
func (m *mockSubnet) Connectivity() *ConnectivityResult {
	return nil
}

func (m *mockSubnet) Kind() string {
	return "Subnet"
}
func (m *mockSubnet) ZoneName() string {
	return ""
}
func (m *mockSubnet) RegionName() string {
	return ""
}
func (m *mockSubnet) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}
func (m *mockSubnet) IsExternal() bool       { return false }
func (m *mockSubnet) ShowOnSubnetMode() bool { return true }
func (m *mockSubnet) VPC() VPCResourceIntf {
	return m.vpc
}

func newAllConnectionsWithStateful(isStateful connection.StatefulState) *connection.Set {
	res := connection.All()
	res.IsStateful = isStateful
	return res
}

func newVPCConfigTest1() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&ExternalNetwork{CidrStr: "1.2.3.4/22", isPublicInternet: true},
		&ExternalNetwork{CidrStr: "8.8.8.8/32", isPublicInternet: true})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	return res, res1
}

func newVPCConfigTest2() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&ExternalNetwork{CidrStr: "1.2.3.4/22", isPublicInternet: true},
		&ExternalNetwork{CidrStr: "8.8.8.8/32", isPublicInternet: true},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[3]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[3].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[2], connection.All())

	return res, res1
}

// Test simple grouping of 2 conn lines with common src+conn, with dest as external ip ranges
// thus, expecting to be merged to one line with dest element of both ranges together
func TestGroupingPhase1(t *testing.T) {
	c, v := newVPCConfigTest1()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)

	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Test simple grouping of 1 conn line with netInterface, grouped into subnet element.
func TestGroupingPhase2(t *testing.T) {
	c, v := newVPCConfigTest2()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	// phase 1
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n"+
		"vsi2 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n", groupingStr)
	// phase 2
	res.groupInternalSrcOrDst(true, true)
	groupingStr = res.String()
	require.Equal(t, "vsi1,vsi2 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// connections from vsi1 should be grouped since both stateful
// connections from vsi2 should not be grouped since one stateful and one not
func configStatefulGrouping() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&ExternalNetwork{CidrStr: "1.2.3.4/22", isPublicInternet: true},
		&ExternalNetwork{CidrStr: "8.8.8.8/32", isPublicInternet: true},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[3]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[3].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], newAllConnectionsWithStateful(connection.StatefulTrue))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], newAllConnectionsWithStateful(connection.StatefulTrue))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[1], newAllConnectionsWithStateful(connection.StatefulTrue))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[2],
		newAllConnectionsWithStateful(connection.StatefulFalse))

	return res, res1
}

func TestStatefulGrouping(t *testing.T) {
	c, v := configStatefulGrouping()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n"+
		"vsi2 => Public Internet 1.2.0.0/22 : All Connections\n"+
		"vsi2 => Public Internet 8.8.8.8/32 : All Connections *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// grouping that results in cidrs presented as range and not as cidr
func configIPRange() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&ExternalNetwork{CidrStr: "1.2.3.0/24", isPublicInternet: true},
		&ExternalNetwork{CidrStr: "1.2.4.0/24", isPublicInternet: true})
	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	return res, res1
}

func TestIPRange(t *testing.T) {
	c, v := configIPRange()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.3.0-1.2.4.255 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Simple test of self loop (don't care): clique of the same subnet. Should end in a single line
func configSelfLoopClique() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi3"})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[1], res.Nodes[2]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[1].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[2].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[0], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[0], connection.All())

	return res, res1
}

func TestSelfLoopClique(t *testing.T) {
	c, v := configSelfLoopClique()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1,vsi2,vsi3 => vsi1,vsi2,vsi3 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Simple test of self loop (don't care): clique in which the vsis belongs to two subnets.
// Should end in three lines
func configSelfLoopCliqueDiffSubnets() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1-1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi1-2"},
		&mockNetIntf{cidr: "10.240.10.7/32", name: "vsi2-1"})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[1]}},
		&mockSubnet{nil, "10.240.10.0/22", "subnet2", []Node{res.Nodes[2]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[1].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[2].(*mockNetIntf).subnet = res.Subnets[1]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[0], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[0], connection.All())

	return res, res1
}

func TestSelfLoopCliqueDiffSubnets(t *testing.T) {
	c, v := configSelfLoopCliqueDiffSubnets()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(true, true)
	res.groupInternalSrcOrDst(false, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1-1,vsi1-2 => vsi1-1,vsi1-2 : All Connections\n"+
		"vsi1-1,vsi1-2 => vsi2-1 : All Connections\n"+
		"vsi2-1 => vsi1-1,vsi1-2 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Simple test of self loop: two lines with 3 vsis of the same subnet and same connection.
//
//	should end in a single line, where one of the vsis being added a self loop
func configSimpleSelfLoop() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi3"})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[1], res.Nodes[2]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[1].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[2].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], connection.All())

	return res, res1
}

func TestSimpleSelfLoop(t *testing.T) {
	c, v := configSimpleSelfLoop()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(false, true)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1,vsi2 => vsi2,vsi3 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Test of self loop (don't care): clique of the same subnet + a simple lace.
// todo: Should end in a single line for the clique and two more lines for the lace
//
//	but ends in another local minimal grouping. Do we want to optimize?
//	try source and then dest and vice versa and choose the one
//	with less lines?
func configSelfLoopCliqueLace() (*VPCConfig, *VPCConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi3"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi4"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi5"})

	res.Subnets = append(res.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet1",
		[]Node{res.Nodes[0], res.Nodes[1], res.Nodes[2], res.Nodes[3], res.Nodes[4]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[1].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[2].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[3].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[4].(*mockNetIntf).subnet = res.Subnets[0]

	res1 := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[0], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[0], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[3], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[4], connection.All())

	return res, res1
}

func TestConfigSelfLoopCliqueLace(t *testing.T) {
	c, v := configSelfLoopCliqueLace()
	res := &GroupConnLines{config: c, nodesConn: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(true)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(false, true)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1,vsi2 => vsi1,vsi2,vsi3 : All Connections\n"+
		"vsi3 => vsi1,vsi2,vsi4 : All Connections\n"+
		"vsi4 => vsi5 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}
func configSubnetSelfLoop() (*VPCConfig, *VPCsubnetConnectivity) {
	res := &VPCConfig{Nodes: []Node{}}
	myVPC := &mockVPCIntf{VPCResource{ResourceName: "myVpc",
		ResourceUID:  "myVpcUid",
		ResourceType: "VPC",
		Zone:         "myZone"}}

	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.3.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.7.20.7/32", name: "vsi3"})

	res.Subnets = append(res.Subnets, &mockSubnet{myVPC, "10.0.20.0/22", "subnet1", []Node{res.Nodes[0]}},
		&mockSubnet{myVPC, "10.3.20.0/22", "subnet2", []Node{res.Nodes[1]}},
		&mockSubnet{myVPC, "10.7.20.0/22", "subnet3", []Node{res.Nodes[2]}})
	res.Nodes[0].(*mockNetIntf).subnet = res.Subnets[0]
	res.Nodes[1].(*mockNetIntf).subnet = res.Subnets[1]
	res.Nodes[2].(*mockNetIntf).subnet = res.Subnets[2]

	res1 := &VPCsubnetConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Subnets[0], res.Subnets[1], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Subnets[0], res.Subnets[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Subnets[1], res.Subnets[0], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Subnets[1], res.Subnets[2], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Subnets[2], res.Subnets[0], connection.All())
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Subnets[2], res.Subnets[1], connection.All())

	return res, res1
}

func TestSubnetSelfLoop(t *testing.T) {
	c, s := configSubnetSelfLoop()
	res := &GroupConnLines{config: c, subnetsConn: s,
		srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err := res.groupExternalAddresses(false)
	require.Equal(t, err, nil)
	res.groupInternalSrcOrDst(false, false)
	res.groupInternalSrcOrDst(true, false)
	groupingStr := res.String()
	require.Equal(t, "subnet1,subnet2,subnet3 => subnet1,subnet2,subnet3 : All Connections\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}
