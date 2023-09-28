package vpcmodel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type mockNetIntf struct {
	cidr     string
	isPublic bool
	name     string
}

func (m *mockNetIntf) Cidr() string {
	return m.cidr
}
func (m *mockNetIntf) IsInternal() bool {
	return !m.isPublic
}
func (m *mockNetIntf) Details() []string {
	return []string{}
}
func (m *mockNetIntf) IsPublicInternet() bool {
	return m.isPublic
}
func (m *mockNetIntf) DetailsMap() []map[string]string {
	return nil
}
func (m *mockNetIntf) Kind() string {
	return "NetworkInterface"
}
func (m *mockNetIntf) UID() string {
	return ""
}
func (m *mockNetIntf) Name() string {
	return m.name
}
func (m *mockNetIntf) ZoneName() string {
	return ""
}
func (m *mockNetIntf) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}
func (m *mockNetIntf) IsExternal() bool { return false }

type mockSubnet struct {
	cidr  string
	name  string
	nodes []Node
}

func (m *mockSubnet) UID() string {
	return ""
}
func (m *mockSubnet) Name() string {
	return m.name
}
func (m *mockSubnet) Nodes() []Node {
	return m.nodes
}
func (m *mockSubnet) Connectivity() *ConnectivityResult {
	return nil
}
func (m *mockSubnet) Details() []string {
	return []string{}
}
func (m *mockSubnet) DetailsMap() []map[string]string {
	return nil
}
func (m *mockSubnet) Kind() string {
	return "Subnet"
}
func (m *mockSubnet) ZoneName() string {
	return ""
}
func (m *mockSubnet) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}
func (m *mockSubnet) IsExternal() bool { return false }

func newCloudConfigTest1() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "1.2.3.4/22", name: "public1", isPublic: true},
		&mockNetIntf{cidr: "8.8.8.8/32", name: "public2", isPublic: true})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	return res, res1
}

func newCloudConfigTest2() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "1.2.3.4/22", name: "public1", isPublic: true},
		&mockNetIntf{cidr: "8.8.8.8/32", name: "public2", isPublic: true},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[3]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[2], common.NewConnectionSet(true))

	return res, res1
}

// Test simple grouping of 2 conn lines with common src+conn, with dest as external ip ranges
// thus, expecting to be merged to one line with dest element of both ranges together
func TestGroupingPhase1(t *testing.T) {
	c, v := newCloudConfigTest1()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()

	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Test simple grouping of 1 conn line with netInterface, grouped into subnet element.
func TestGroupingPhase2(t *testing.T) {
	c, v := newCloudConfigTest2()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	// phase 1
	res.groupExternalAddresses()
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n"+
		"vsi2 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections"+
		"\n\nconnections are stateful unless marked with *\n", groupingStr)
	// phase 2
	res.groupInternalSrcOrDst(true, true)
	groupingStr = res.String()
	require.Equal(t, "vsi1,vsi2 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// connections from vsi1 should be grouped since both stateful
// connections from vsi2 should not be grouped since one stateful and one not
func configStatefulGrouping() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "1.2.3.4/22", name: "public1", isPublic: true},
		&mockNetIntf{cidr: "8.8.8.8/32", name: "public2", isPublic: true},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[3]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSetWithStateful(true, common.StatefulTrue))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSetWithStateful(true, common.StatefulTrue))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[1], common.NewConnectionSetWithStateful(true, common.StatefulTrue))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[2],
		common.NewConnectionSetWithStateful(true, common.StatefulFalse))

	return res, res1
}

func TestStatefulGrouping(t *testing.T) {
	c, v := configStatefulGrouping()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.0.0/22,8.8.8.8/32 : All Connections\n"+
		"vsi2 => Public Internet 1.2.0.0/22 : All Connections\n"+
		"vsi2 => Public Internet 8.8.8.8/32 : All Connections *\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// grouping that results in cidrs presented as range and not as cidr
func configIPRange() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "1.2.3.0/24", name: "public1", isPublic: true},
		&mockNetIntf{cidr: "1.2.4.0/24", name: "public2", isPublic: true})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	return res, res1
}

func TestIPRange(t *testing.T) {
	c, v := configIPRange()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.3.0-1.2.4.255 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Simple test of self loop (don't care): clique of the same subnet. Should end in a single line
func configSelfLoopClique() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi3"})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[1], res.Nodes[2]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[0], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[0], common.NewConnectionSet(true))

	return res, res1
}

func TestSelfLoopClique(t *testing.T) {
	c, v := configSelfLoopClique()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1,vsi2,vsi3 => vsi1,vsi2,vsi3 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Simple test of self loop (don't care): clique in which the vsis belongs to two subnets.
// Should end in three lines
func configSelfLoopCliqueDiffSubnets() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1-1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi1-2"},
		&mockNetIntf{cidr: "10.240.10.7/32", name: "vsi2-1"})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[1]}},
		&mockSubnet{"10.240.10.0/22", "subnet2", []Node{res.Nodes[2]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[0], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[0], common.NewConnectionSet(true))

	return res, res1
}

func TestSelfLoopCliqueDiffSubnets(t *testing.T) {
	c, v := configSelfLoopCliqueDiffSubnets()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(true, true)
	res.groupInternalSrcOrDst(false, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1-1,vsi1-2 => vsi1-1,vsi1-2 : All Connections\n"+
		"vsi1-1,vsi1-2 => vsi2-1 : All Connections\n"+
		"vsi2-1 => vsi1-1,vsi1-2 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Simple test of self loop: two lines with 3 vsis of the same subnet and same connection.
//
//	should end in a single line, where one of the vsis being added a self loop
func configSimpleSelfLoop() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi3"})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{res.Nodes[0], res.Nodes[1], res.Nodes[2]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], common.NewConnectionSet(true))

	return res, res1
}

func TestSimpleSelfLoop(t *testing.T) {
	c, v := configSimpleSelfLoop()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(false, true)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1,vsi2 => vsi2,vsi3 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}

// Test of self loop (don't care): clique of the same subnet + a simple lace.
// todo: Should end in a single line for the clique and two more lines for the lace
//
//	but ends in another local minimal grouping. Do we want to optimize?
//	try source and then dest and vice versa and choose the one
//	with less lines?
func configSelfLoopCliqueLace() (*CloudConfig, *VPCConnectivity) {
	res := &CloudConfig{Nodes: []Node{}}
	res.Nodes = append(res.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.0.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi3"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi4"},
		&mockNetIntf{cidr: "10.0.20.7/32", name: "vsi5"})

	res.NodeSets = append(res.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1",
		[]Node{res.Nodes[0], res.Nodes[1], res.Nodes[2], res.Nodes[3], res.Nodes[4]}})

	res1 := &VPCConnectivity{AllowedConnsCombined: NewNodesConnectionsMap()}
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[0], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[0], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[1], res.Nodes[2], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[1], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[0], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[2], res.Nodes[3], common.NewConnectionSet(true))
	res1.AllowedConnsCombined.updateAllowedConnsMap(res.Nodes[3], res.Nodes[4], common.NewConnectionSet(true))

	return res, res1
}

func TestConfigSelfLoopCliqueLace(t *testing.T) {
	c, v := configSelfLoopCliqueLace()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(false, true)
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1,vsi2 => vsi1,vsi2,vsi3 : All Connections\n"+
		"vsi3 => vsi1,vsi2,vsi4 : All Connections\n"+
		"vsi4 => vsi5 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}
