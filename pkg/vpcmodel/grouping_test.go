package vpcmodel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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
	return nwInterface
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
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
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
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
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

// todo: newCloudConfigTest7 since there are more tests in PR #152
//		delete comment after merges

// connections from vsi1 should be grouped since both stateful
// connections from vsi2 should not be grouped since one stateful and one not
func newCloudConfigTest7() (*CloudConfig, *VPCConnectivity) {
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

func TestGroupingPhase7(t *testing.T) {
	c, v := newCloudConfigTest7()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
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
func newCloudConfigTest8() (*CloudConfig, *VPCConnectivity) {
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

func TestGroupingPhase8(t *testing.T) {
	c, v := newCloudConfigTest8()
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
	res.groupExternalAddresses()
	res.groupInternalSrcOrDst(true, true)
	groupingStr := res.String()
	require.Equal(t, "vsi1 => Public Internet 1.2.3.0-1.2.4.255 : All Connections\n\n"+
		"connections are stateful unless marked with *\n", groupingStr)
	fmt.Println(groupingStr)
	fmt.Println("done")
}
