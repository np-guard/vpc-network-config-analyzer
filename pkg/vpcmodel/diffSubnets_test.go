package vpcmodel

import (
	"fmt"
	"testing"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// simple diff:
// cfg1 has subnet1, subnet2, subnet3
//      subnet1 -> subnet2
//      subnet2 -> subnet3
//      subnet3 -> subnet2
// cfg2 has subnet2, subnet3, subnet4
//     subnet2 -> subnet3
//     subnet3 -> subnet4
//     subnet3 -> subnet2
//     expected diff:
//    + subnet1 -> subnet2  missing src
//    + subnet2 -> subnet3  missing connection
//    - subnet3 -> subnet4  missing dst

func configSimpleSubnetSubtract() (*SubnetConfigConnectivity, *SubnetConfigConnectivity) {
	cfg1 := &CloudConfig{Nodes: []Node{}}
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.3.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.7.20.7/32", name: "vsi3"})

	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet1", []Node{cfg1.Nodes[0]}})
	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.3.20.0/22", "subnet2", []Node{cfg1.Nodes[1]}})
	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.7.20.0/22", "subnet3", []Node{cfg1.Nodes[2]}})

	cfg2 := &CloudConfig{Nodes: []Node{}}
	cfg2.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1"},
		&mockNetIntf{cidr: "10.3.20.6/32", name: "vsi2"},
		&mockNetIntf{cidr: "10.9.20.7/32", name: "vsi4"})

	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[2], cfg1.NodeSets[1], common.NewConnectionSet(true))

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.NodeSets[0], common.NewConnectionSet(true))

	subnetConfigConn1 := &SubnetConfigConnectivity{cfg1, subnetConnMap1.AllowedConnsCombined}
	subnetConfigConn2 := &SubnetConfigConnectivity{cfg2, subnetConnMap2.AllowedConnsCombined}

	return subnetConfigConn1, subnetConfigConn2
}

func TestSimpleSubnetSubtract(t *testing.T) {
	subnetConfigConn1, subnetConfigConn2 := configSimpleSubnetSubtract()

	subnet1Subtract2 := subnetConfigConn1.SubnetConnectivitySubtract(subnetConfigConn2)
	subnet2Subtract1 := subnetConfigConn2.SubnetConnectivitySubtract(subnetConfigConn1)

	fmt.Printf("subnet1Subtract2 is %v\nsubnet2Subtract1 is %v\n", subnet1Subtract2, subnet2Subtract1)

}
