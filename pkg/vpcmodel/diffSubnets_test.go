package vpcmodel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// simple diff:
// cfg1 has subnet0, subnet1, subnet2, subnet3
//      subnet0 -> subnet1
//      subnet1 -> subnet2
//      subnet3 -> subnet1
//      subnet2 -> subnet3
//      subnet3 -> subnet2
// cfg2 has subnet2, subnet3, subnet4
//     subnet3 -> subnet2
//     subnet3 -> subnet4

//     expected diff cfg1 subtract cfg2:
//     cfg1 subtract cfg2
//     subnet0 -> subnet1 missing src and dst
//     subnet1 -> subnet2 missing src
//     subnet3 -> subnet1 missing dst
//     subnet2 -> subnet3 missing connection
//
//     cfg2 subtract cfg1
//     subnet1 subtract subnet2:
//     subnet3 -> subnet4 missing dst

func configSimpleSubnetSubtract() (subnetConfigConn1, subnetConfigConn2 *SubnetConfigConnectivity) {
	cfg1 := &CloudConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1-1"},
		&mockNetIntf{cidr: "10.3.20.6/32", name: "vsi1-2"},
		&mockNetIntf{cidr: "10.7.20.7/32", name: "vsi1-3"})

	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet0", []Node{cfg1.Nodes[0]}},
		&mockSubnet{"10.1.20.0/22", "subnet1", []Node{cfg1.Nodes[0]}},
		&mockSubnet{"10.2.20.0/22", "subnet2", []Node{cfg1.Nodes[1]}})
	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.3.20.0/22", "subnet3", []Node{cfg1.Nodes[2]}})

	cfg2 := &CloudConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{cidr: "10.3.20.5/32", name: "vsi2-1"},
		&mockNetIntf{cidr: "10.7.20.6/32", name: "vsi2-2"},
		&mockNetIntf{cidr: "10.9.20.7/32", name: "vsi2-3"})
	cfg2.NodeSets = append(cfg2.NodeSets, &mockSubnet{"10.2.20.0/22", "subnet2", []Node{cfg2.Nodes[0]}},
		&mockSubnet{"10.3.20.0/22", "subnet3", []Node{cfg2.Nodes[1]}},
		&mockSubnet{"10.4.20.0/22", "subnet4", []Node{cfg2.Nodes[2]}})

	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[2], cfg1.NodeSets[3], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[2], common.NewConnectionSet(true))

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[1], cfg2.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[1], cfg2.NodeSets[2], common.NewConnectionSet(true))

	subnetConfigConn1 = &SubnetConfigConnectivity{cfg1, subnetConnMap1.AllowedConnsCombined}
	subnetConfigConn2 = &SubnetConfigConnectivity{cfg2, subnetConnMap2.AllowedConnsCombined}

	return subnetConfigConn1, subnetConfigConn2
}

func TestSimpleSubnetSubtract(t *testing.T) {
	subnetConfigConn1, subnetConfigConn2 := configSimpleSubnetSubtract()
	subnet1Subtract2 := subnetConfigConn1.SubnetConnectivitySubtract(subnetConfigConn2)
	subnet1Subtract2Str := subnet1Subtract2.EnhancedString(true)
	fmt.Printf("subnet1Subtract2:\n%v\n", subnet1Subtract2Str)
	newLines := strings.Count(subnet1Subtract2Str, "\n")
	// there should be 4 lines in subnet1Subtract2Str
	require.Equal(t, 4, newLines)
	require.Contains(t, subnet1Subtract2Str, "-- subnet3 => subnet1 :  missing destination")
	require.Contains(t, subnet1Subtract2Str, "-- subnet2 => subnet3 :  missing connection")
	require.Contains(t, subnet1Subtract2Str, "-- subnet0 => subnet1 :  missing source and destination")
	require.Contains(t, subnet1Subtract2Str, "-- subnet1 => subnet2 :  missing source")

	subnet2Subtract1 := subnetConfigConn2.SubnetConnectivitySubtract(subnetConfigConn1)
	subnet2Subtract1Str := subnet2Subtract1.EnhancedString(false)
	fmt.Printf("subnet2Subtract1:\n%v\n", subnet2Subtract1Str)
	require.Equal(t, "++ subnet3 => subnet4 :  missing destination\n", subnet2Subtract1Str)
}
