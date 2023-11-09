package vpcmodel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// simple diff:
// cfg1 has subnet0, subnet1, subnet2, subnet3, subnet4
//      subnet0 -> subnet1
//      subnet1 -> subnet2
//      subnet3 -> subnet1
//      subnet2 -> subnet3
//      subnet3 -> subnet2
//      subnet3 -> subnet4 not all connections
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
//     subnet3 -> subnet4 different connection

func configSimpleSubnetSubtract() (subnetConfigConn1, subnetConfigConn2 *SubnetConfigConnectivity) {
	cfg1 := &VPCConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1-1"},
		&mockNetIntf{cidr: "10.3.20.6/32", name: "vsi1-2"},
		&mockNetIntf{cidr: "10.7.20.7/32", name: "vsi1-3"})

	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet0", []Node{cfg1.Nodes[0]}},
		&mockSubnet{"10.1.20.0/22", "subnet1", []Node{cfg1.Nodes[0]}},
		&mockSubnet{"10.2.20.0/22", "subnet2", []Node{cfg1.Nodes[1]}})
	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.3.20.0/22", "subnet3", []Node{cfg1.Nodes[2]}},
		&mockSubnet{"10.4.20.0/22", "subnet4", []Node{cfg1.Nodes[2]}})

	cfg2 := &VPCConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{cidr: "10.3.20.5/32", name: "vsi2-1"},
		&mockNetIntf{cidr: "10.7.20.6/32", name: "vsi2-2"},
		&mockNetIntf{cidr: "10.9.20.7/32", name: "vsi2-3"},
		&mockNetIntf{cidr: "11.4.20.6/32", name: "vsi2-4"})
	cfg2.NodeSets = append(cfg2.NodeSets, &mockSubnet{"10.2.20.0/22", "subnet2", []Node{cfg2.Nodes[0]}},
		&mockSubnet{"10.3.20.0/22", "subnet3", []Node{cfg2.Nodes[1]}},
		&mockSubnet{"10.4.20.0/22", "subnet4", []Node{cfg2.Nodes[2]}},
		&mockSubnet{"11.4.20.0/22", "subnet5", []Node{cfg2.Nodes[3]}})

	connectionTCP := common.NewConnectionSet(false)
	connectionTCP.AddTCPorUDPConn(common.ProtocolTCP, 10, 100, 443, 443)
	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[2], cfg1.NodeSets[3], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[4], connectionTCP)

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[1], cfg2.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[1], cfg2.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[2], cfg2.NodeSets[3], common.NewConnectionSet(true))

	subnetConfigConn1 = &SubnetConfigConnectivity{cfg1, subnetConnMap1.AllowedConnsCombined}
	subnetConfigConn2 = &SubnetConfigConnectivity{cfg2, subnetConnMap2.AllowedConnsCombined}

	return subnetConfigConn1, subnetConfigConn2
}

func TestSimpleSubnetSubtract(t *testing.T) {
	subnetConfigConn1, subnetConfigConn2 := configSimpleSubnetSubtract()
	subnet1Subtract2, err := subnetConfigConn1.subtract(subnetConfigConn2)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	subnet1Subtract2Str := subnet1Subtract2.EnhancedString(true)
	fmt.Printf("subnet1Subtract2:\n%v\n", subnet1Subtract2Str)
	require.Equal(t, err, nil)
	newLines := strings.Count(subnet1Subtract2Str, "\n")
	require.Equal(t, 4, newLines)
	require.Contains(t, subnet1Subtract2Str, "diff-type: added source: subnet0 destination: subnet1 "+
		"dir1: All Connections dir2: No connection, workloads-diff-info: workloads subnet0 and subnet1 added")
	require.Contains(t, subnet1Subtract2Str, "diff-type: added source: subnet1 destination: subnet2 "+
		"dir1: All Connections dir2: No connection, workloads-diff-info: workload subnet1 added")
	require.Contains(t, subnet1Subtract2Str, "diff-type: added source: subnet2 destination: subnet3 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, subnet1Subtract2Str, "diff-type: added source: subnet3 destination: subnet1 "+
		"dir1: All Connections dir2: No connection, workloads-diff-info: workload subnet1 added")

	cfg2Subtract1, err := subnetConfigConn2.subtract(subnetConfigConn1)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	subnet2Subtract1Str := cfg2Subtract1.EnhancedString(false)
	fmt.Printf("cfg2Subtract1:\n%v", subnet2Subtract1Str)
	require.Contains(t, subnet2Subtract1Str, "diff-type: changed source: subnet3 destination: subnet4 dir1: "+
		"protocol: TCP src-ports: 10-100 dst-ports: 443 dir2: All Connections\n")
	require.Contains(t, subnet2Subtract1Str, "diff-type: removed source: subnet4 destination: subnet5 dir1: "+
		"No connection dir2: All Connections, workloads-diff-info: workload subnet5 removed\n")
}

func configSimpleIPAndSubnetSubtract() (subnetConfigConn1, subnetConfigConn2 *SubnetConfigConnectivity) {
	cfg1 := &VPCConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.1.20.0/22", "subnet1", nil},
		&mockSubnet{"10.2.20.0/22", "subnet2", nil})
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "1.2.3.0/30", name: "public1-1", isPublic: true},
		&mockNetIntf{cidr: "250.2.4.0/24", name: "public1-2", isPublic: true},
		&mockNetIntf{cidr: "200.2.4.0/24", name: "public1-3", isPublic: true})

	cfg2 := &VPCConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg2.NodeSets = append(cfg2.NodeSets, &mockSubnet{"10.1.20.0/22", "subnet1", nil},
		&mockSubnet{"10.2.20.0/22", "subnet2", nil})
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{cidr: "1.2.3.0/26", name: "public2-1", isPublic: true},
		&mockNetIntf{cidr: "250.2.4.0/30", name: "public2-2", isPublic: true},
		&mockNetIntf{cidr: "200.2.4.0/24", name: "public1-3", isPublic: true})

	//      cfg1                                            cfg2
	// <subnet2, public1-1>	    		 and		<subnet2, public2-1> are comparable
	// <public1-2, subnet2> 			 and 		<public2-2, subnet2> are comparable
	// <public1-1, subnet2> 			 and 		<public2-1, subnet2> are comparable
	// <public1-1, subnet1> 			 and 		<public2-1, subnet1> are comparable
	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.Nodes[0], cfg1.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.Nodes[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.Nodes[1], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.Nodes[0], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg1.NodeSets[1], cfg1.Nodes[2], common.NewConnectionSet(true))

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombined: NewSubnetConnectivityMap()}
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.Nodes[0], cfg2.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.Nodes[0], cfg2.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.Nodes[1], cfg2.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[1], cfg2.Nodes[0], common.NewConnectionSet(true))
	connectionTCP := common.NewConnectionSet(false)
	connectionTCP.AddTCPorUDPConn(common.ProtocolTCP, 0, 1000, 0, 443)
	subnetConnMap2.AllowedConnsCombined.updateAllowedSubnetConnsMap(cfg2.NodeSets[1], cfg2.Nodes[2], connectionTCP)

	subnetConfigConn1 = &SubnetConfigConnectivity{cfg1, subnetConnMap1.AllowedConnsCombined}
	subnetConfigConn2 = &SubnetConfigConnectivity{cfg2, subnetConnMap2.AllowedConnsCombined}

	return subnetConfigConn1, subnetConfigConn2
}

func TestSimpleIPAndSubnetSubtract(t *testing.T) {
	cfgConn1, cfgConn2 := configSimpleIPAndSubnetSubtract()
	alignedCfgConn1, alignedCfgConn2, err := cfgConn1.getConnectivesWithSameIPBlocks(cfgConn2)
	if err != nil {
		fmt.Printf("err: %v\n", err.Error())
		require.Equal(t, err, nil)
		return
	}

	// verified bit by bit :-)
	cfg1SubCfg2, err := alignedCfgConn1.subtract(alignedCfgConn2)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	cfg1SubtractCfg2Str := cfg1SubCfg2.EnhancedString(true)
	fmt.Printf("cfg1SubCfg2:\n%v\n", cfg1SubtractCfg2Str)
	newLines := strings.Count(cfg1SubtractCfg2Str, "\n")
	require.Equal(t, 7, newLines)
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: added source: Public Internet [250.2.4.128/25] destination: subnet2 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: added source: Public Internet [250.2.4.16/28] destination: subnet2 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: added source: Public Internet [250.2.4.32/27] destination: subnet2 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: added source: Public Internet [250.2.4.4/30] destination: subnet2 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: added source: Public Internet [250.2.4.64/26] destination: subnet2 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: added source: Public Internet [250.2.4.8/29] destination: subnet2 "+
		"dir1: All Connections dir2: No connection")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: changed source: subnet2 destination: Public Internet [200.2.4.0/24] "+
		"dir1: All Connections dir2: protocol: TCP src-ports: 0-1000 dst-ports: 0-443")
}
