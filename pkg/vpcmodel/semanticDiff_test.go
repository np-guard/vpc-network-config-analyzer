package vpcmodel

import (
	"fmt"
	"sort"
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

//     expected diff cfg1 connMissingOrChanged cfg2:
//     cfg1 connMissingOrChanged cfg2
//     subnet0 -> subnet1 missing src and dst
//     subnet1 -> subnet2 missing src
//     subnet3 -> subnet1 missing dst
//     subnet2 -> subnet3 missing connection
//
//     cfg2 connMissingOrChanged cfg1
//     subnet1 connMissingOrChanged subnet2:
//     subnet3 -> subnet4 different connection

func configSimpleSubnetDiff() (subnetConfigConn1, subnetConfigConn2 *configConnectivity) {
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
	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[1], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[2], cfg1.NodeSets[3], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[3], cfg1.NodeSets[4], connectionTCP)

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.NodeSets[1], cfg2.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.NodeSets[1], cfg2.NodeSets[2], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.NodeSets[2], cfg2.NodeSets[3], common.NewConnectionSet(true))

	subnetConfigConn1 = &configConnectivity{cfg1, subnetConnMap1.AllowedConnsCombined}
	subnetConfigConn2 = &configConnectivity{cfg2, subnetConnMap2.AllowedConnsCombined}

	return subnetConfigConn1, subnetConfigConn2
}

func TestSimpleSubnetDiff(t *testing.T) {
	subnetConfigConn1, subnetConfigConn2 := configSimpleSubnetDiff()
	subnet1Subtract2, err := subnetConfigConn1.connMissingOrChanged(subnetConfigConn2, Subnets, true)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	subnet1Subtract2Str := subnet1Subtract2.string(Subnets, true)
	fmt.Printf("cfg1ConnRemovedFrom2:\n%v\n", subnet1Subtract2Str)
	require.Equal(t, err, nil)
	newLines := strings.Count(subnet1Subtract2Str, "\n")
	require.Equal(t, 5, newLines)
	require.Contains(t, subnet1Subtract2Str, "diff-type: removed, source: subnet0, destination: subnet1, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet0 and subnet1 removed")
	require.Contains(t, subnet1Subtract2Str, "diff-type: removed, source: subnet1, destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet1 removed")
	require.Contains(t, subnet1Subtract2Str, "diff-type: removed, source: subnet2, destination: subnet3, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, subnet1Subtract2Str, "diff-type: removed, source: subnet3, destination: subnet1, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet1 removed")
	require.Contains(t, subnet1Subtract2Str, "diff-type: changed, source: subnet3, destination: subnet4, "+
		"config1: protocol: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections, subnets-diff-info:")

	cfg2Subtract1, err := subnetConfigConn2.connMissingOrChanged(subnetConfigConn1, Subnets, false)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	subnet2Subtract1Str := cfg2Subtract1.string(Subnets, false)
	fmt.Printf("cfg2ConnRemovedFrom1:\n%v", subnet2Subtract1Str)
	require.Equal(t, subnet2Subtract1Str, "diff-type: added, source: subnet4, destination: subnet5, config1: "+
		"No Connections, config2: All Connections, subnets-diff-info: subnet5 added\n")
}

func TestSimpleSubnetDiffGrouping(t *testing.T) {
	subnetConfigConn1, subnetConfigConn2 := configSimpleSubnetDiff()
	cfg1SubCfg2, err := subnetConfigConn1.connMissingOrChanged(subnetConfigConn2, Subnets, true)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	cfg2SubCfg1, err := subnetConfigConn2.connMissingOrChanged(subnetConfigConn1, Subnets, false)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	d := &diffBetweenCfgs{Subnets, cfg1SubCfg2, cfg2SubCfg1, nil}
	groupConnLines, _ := newGroupConnLinesDiff(d)
	d.groupedLines = groupConnLines.GroupedLines
	groupedPrinted := d.String()
	fmt.Println(groupedPrinted)
	newLines := strings.Count(groupedPrinted, "\n")
	require.Equal(t, 6, newLines)
	require.Contains(t, groupedPrinted, "diff-type: removed, source: subnet0, destination: subnet1, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet0 and subnet1 removed\n")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: subnet1, destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet1 removed\n")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: subnet2, destination: subnet3, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: \n")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: subnet3, destination: subnet1, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet1 removed\n")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: subnet3, destination: subnet4, "+
		"config1: protocol: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections, subnets-diff-info: \n")
	require.Contains(t, groupedPrinted, "diff-type: added, source: subnet4, destination: subnet5, config1: "+
		"No Connections, config2: All Connections, subnets-diff-info: subnet5 added\n")
}

func configSimpleIPAndSubnetDiff() (subnetConfigConn1, subnetConfigConn2 *configConnectivity) {
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
	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[0], cfg1.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[0], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[1], cfg1.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[1], cfg1.Nodes[0], common.NewConnectionSet(true))
	subnetConnMap1.AllowedConnsCombined.updateAllowedConnsMap(cfg1.NodeSets[1], cfg1.Nodes[2], common.NewConnectionSet(true))

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[0], cfg2.NodeSets[0], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[0], cfg2.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[1], cfg2.NodeSets[1], common.NewConnectionSet(true))
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.NodeSets[1], cfg2.Nodes[0], common.NewConnectionSet(true))
	connectionTCP := common.NewConnectionSet(false)
	connectionTCP.AddTCPorUDPConn(common.ProtocolTCP, 0, 1000, 0, 443)
	subnetConnMap2.AllowedConnsCombined.updateAllowedConnsMap(cfg2.NodeSets[1], cfg2.Nodes[2], connectionTCP)

	subnetConfigConn1 = &configConnectivity{cfg1, subnetConnMap1.AllowedConnsCombined}
	subnetConfigConn2 = &configConnectivity{cfg2, subnetConnMap2.AllowedConnsCombined}

	return subnetConfigConn1, subnetConfigConn2
}

func TestSimpleIPAndSubnetDiff(t *testing.T) {
	cfgConn1, cfgConn2 := configSimpleIPAndSubnetDiff()
	alignedCfgConn1, alignedCfgConn2, err := cfgConn1.getConnectivityWithSameIPBlocks(cfgConn2)
	if err != nil {
		fmt.Printf("err: %v\n", err.Error())
		require.Equal(t, err, nil)
		return
	}

	// verified bit by bit :-)
	cfg1SubCfg2, err := alignedCfgConn1.connMissingOrChanged(alignedCfgConn2, Subnets, true)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	cfg1SubtractCfg2Str := cfg1SubCfg2.string(Subnets, true)
	fmt.Printf("cfg1SubCfg2:\n%v\n", cfg1SubtractCfg2Str)
	newLines := strings.Count(cfg1SubtractCfg2Str, "\n")
	require.Equal(t, 7, newLines)
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.128/25], destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.16/28], destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.32/27], destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.4/30], destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.64/26], destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.8/29], destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info:")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: changed, source: subnet2, destination: Public Internet [200.2.4.0/24], "+
		"config1: All Connections, config2: protocol: TCP src-ports: 0-1000 dst-ports: 0-443, subnets-diff-info:")
}

func TestSimpleIPAndSubnetDiffGrouping(t *testing.T) {
	cfgConn1, cfgConn2 := configSimpleIPAndSubnetDiff()
	alignedCfgConn1, alignedCfgConn2, err := cfgConn1.getConnectivityWithSameIPBlocks(cfgConn2)
	if err != nil {
		fmt.Printf("err: %v\n", err.Error())
		require.Equal(t, err, nil)
		return
	}
	// verified bit by bit :-)
	cfg1SubCfg2, err := alignedCfgConn1.connMissingOrChanged(alignedCfgConn2, Subnets, true)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	cfg2SubCfg1, err := alignedCfgConn2.connMissingOrChanged(alignedCfgConn1, Subnets, false)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	d := &diffBetweenCfgs{Subnets, cfg1SubCfg2, cfg2SubCfg1, nil}
	groupConnLines, _ := newGroupConnLinesDiff(d)
	d.groupedLines = groupConnLines.GroupedLines
	groupedPrinted := d.String()
	fmt.Println(groupedPrinted)
	newLines := strings.Count(groupedPrinted, "\n")
	require.Equal(t, 5, newLines)
	require.Contains(t, groupedPrinted, "diff-type: added, source: Public Internet 1.2.3.4-1.2.3.63, "+
		"destination: subnet1, config1: No Connections, config2: All Connections, subnets-diff-info:")
	require.Contains(t, groupedPrinted, "diff-type: added, source: Public Internet 1.2.3.4-1.2.3.63, "+
		"destination: subnet2, config1: No Connections, config2: All Connections, subnets-diff-info:")
	require.Contains(t, groupedPrinted, "diff-type: added, source: subnet2, destination: Public Internet 1.2.3.4-1.2.3.63, "+
		"config1: No Connections, config2: All Connections, subnets-diff-info:")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: subnet2, destination: Public Internet 200.2.4.0/24, "+
		"config1: All Connections, config2: protocol: TCP src-ports: 0-1000 dst-ports: 0-443, subnets-diff-info: ")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: Public Internet 250.2.4.4-250.2.4.255, destination: subnet2, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info")
}

func configSimpleVsisDiff() (configConn1, configConn2 *configConnectivity) {
	cfg1 := &VPCConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{name: "vsi0", isPublic: false, cidr: ""},
		&mockNetIntf{name: "vsi1", isPublic: false, cidr: ""},
		&mockNetIntf{name: "vsi2", isPublic: false, cidr: ""},
		&mockNetIntf{name: "vsi3", isPublic: false, cidr: ""},
		&mockNetIntf{cidr: "1.2.3.0/30", name: "public1-1", isPublic: true})

	cfg1.NodeSets = append(cfg1.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet0", []Node{cfg1.Nodes[0], cfg1.Nodes[1],
		cfg1.Nodes[2], cfg1.Nodes[3]}})

	cfg2 := &VPCConfig{Nodes: []Node{}, NodeSets: []NodeSet{}}
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{name: "vsi1", isPublic: false, cidr: ""},
		&mockNetIntf{name: "vsi2", isPublic: false, cidr: ""},
		&mockNetIntf{name: "vsi3", isPublic: false, cidr: ""},
		&mockNetIntf{name: "vsi4", isPublic: false, cidr: ""},
		&mockNetIntf{cidr: "1.2.3.0/26", name: "public2-1", isPublic: true})

	cfg2.NodeSets = append(cfg2.NodeSets, &mockSubnet{"10.0.20.0/22", "subnet0", []Node{cfg2.Nodes[0], cfg2.Nodes[1],
		cfg2.Nodes[2], cfg2.Nodes[3]}})

	connectionTCP := common.NewConnectionSet(false)
	connectionTCP.AddTCPorUDPConn(common.ProtocolTCP, 10, 100, 443, 443)
	cfg1Conn := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	cfg1Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[0], cfg1.Nodes[1], common.NewConnectionSet(true))
	cfg1Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[1], cfg1.Nodes[2], common.NewConnectionSet(true))
	cfg1Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[1], cfg1.Nodes[3], common.NewConnectionSet(true))
	cfg1Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[2], cfg1.Nodes[3], connectionTCP)
	cfg1Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg1.Nodes[2], cfg1.Nodes[4], connectionTCP)

	cfg2Conn := &VPCConnectivity{AllowedConnsCombined: GeneralConnectivityMap{}}
	// 1st connections is identical to these in cfg1; the 2nd one differs in the conn type, the 3rd one has a dst that
	// does not exist in cfg1
	cfg2Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[0], cfg2.Nodes[1], common.NewConnectionSet(true))
	cfg2Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[1], cfg2.Nodes[2], common.NewConnectionSet(true))
	cfg2Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[2], cfg2.Nodes[3], common.NewConnectionSet(true))
	cfg2Conn.AllowedConnsCombined.updateAllowedConnsMap(cfg2.Nodes[1], cfg2.Nodes[4], common.NewConnectionSet(true))

	configConn1 = &configConnectivity{cfg1, cfg1Conn.AllowedConnsCombined}
	configConn2 = &configConnectivity{cfg2, cfg2Conn.AllowedConnsCombined}

	fmt.Printf("cfg1:\n%v\n", cfg1Conn.AllowedConnsCombined.getCombinedConnsStr())
	fmt.Printf("cfg2:\n%v\n", cfg2Conn.AllowedConnsCombined.getCombinedConnsStr())

	return configConn1, configConn2
}

func TestSimpleVsisDiff(t *testing.T) {
	cfgConn1, cfgConn2 := configSimpleVsisDiff()
	alignedCfgConn1, alignedCfgConn2, err := cfgConn1.getConnectivityWithSameIPBlocks(cfgConn2)
	if err != nil {
		fmt.Printf("err: %v\n", err.Error())
		require.Equal(t, err, nil)
		return
	}

	cfg1SubCfg2, err := alignedCfgConn1.connMissingOrChanged(alignedCfgConn2, Vsis, true)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	cfg1SubCfg2Str := cfg1SubCfg2.string(Vsis, true)
	fmt.Printf("cfg1SubCfg2Str:\n%v\n", cfg1SubCfg2Str)
	newLines := strings.Count(cfg1SubCfg2Str, "\n")
	require.Equal(t, 4, newLines)
	require.Contains(t, cfg1SubCfg2Str, "diff-type: changed, source: vsi2, destination: vsi3, config1: "+
		"protocol: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections, vsis-diff-info:")
	require.Contains(t, cfg1SubCfg2Str, "diff-type: removed, source: vsi0, destination: vsi1, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info: vsi0 removed")
	require.Contains(t, cfg1SubCfg2Str, "diff-type: removed, source: vsi1, destination: vsi3, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info:")

	cfg2SubCfg1, err := alignedCfgConn2.connMissingOrChanged(alignedCfgConn1, Vsis, false)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	cfg2SubCfg1Str := cfg2SubCfg1.string(Vsis, true)
	fmt.Printf("cfg2SubCfg1Str:\n%v\n", cfg2SubCfg1Str)
	newLines = strings.Count(cfg2SubCfg1Str, "\n")
	require.Equal(t, 5, newLines)
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, "+
		"destination: Public Internet [1.2.3.16/28], config1: All Connections, config2: No Connections, vsis-diff-info: \n")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, "+
		"destination: Public Internet [1.2.3.32/27], config1: All Connections, config2: No Connections, vsis-diff-info: \n")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, destination: Public Internet [1.2.3.4/30], "+
		"config1: All Connections, config2: No Connections, vsis-diff-info: \n")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, "+
		"destination: Public Internet [1.2.3.8/29], config1: All Connections, config2: No Connections, vsis-diff-info: \n")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi3, destination: vsi4, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info: vsi4 removed\n")
}

func TestSimpleVsisDiffGrouping(t *testing.T) {
	cfgConn1, cfgConn2 := configSimpleVsisDiff()
	alignedCfgConn1, alignedCfgConn2, err := cfgConn1.getConnectivityWithSameIPBlocks(cfgConn2)
	if err != nil {
		fmt.Printf("err: %v\n", err.Error())
		require.Equal(t, err, nil)
		return
	}
	cfg1SubCfg2, err := alignedCfgConn1.connMissingOrChanged(alignedCfgConn2, Vsis, true)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	cfg2SubCfg1, err := alignedCfgConn2.connMissingOrChanged(alignedCfgConn1, Vsis, false)
	if err != nil {
		fmt.Println("error:", err.Error())
	}
	require.Equal(t, err, nil)
	d := &diffBetweenCfgs{Vsis, cfg1SubCfg2, cfg2SubCfg1, nil}
	groupConnLines, _ := newGroupConnLinesDiff(d)
	d.groupedLines = groupConnLines.GroupedLines
	groupedPrinted := d.String()
	fmt.Println(groupedPrinted)
	newLines := strings.Count(groupedPrinted, "\n")
	require.Equal(t, 6, newLines)
	require.Contains(t, groupedPrinted, "diff-type: added, source: vsi2, destination: Public Internet 1.2.3.4-1.2.3.63, "+
		"config1: No Connections, config2: All Connections, vsis-diff-info: \n")
	require.Contains(t, groupedPrinted, "diff-type: added, source: vsi3, destination: vsi4, config1: No Connections, "+
		"config2: All Connections, vsis-diff-info: vsi4 added\n")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: vsi2, destination: Public Internet 1.2.3.0/30, "+
		"config1: protocol: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections, vsis-diff-info: \n")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: vsi2, destination: vsi3, "+
		"config1: protocol: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections, vsis-diff-info: \n")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: vsi0, destination: vsi1, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info: vsi0 removed\n")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: vsi1, destination: vsi3, "+
		"config1: All Connections, config2: No Connections, vsis-diff-info: \n")
}

func (connDiff *connectivityDiff) string(diffAnalysis diffAnalysisType, thisMinusOther bool) string {
	strList := []string{}
	for src, endpointConnDiff := range *connDiff {
		for dst, connDiff := range endpointConnDiff {
			connDiff.thisMinusOther = thisMinusOther
			conn1Str, conn2Str := conn1And2Str(connDiff)
			diffType, endpointsDiff := diffAndEndpointsDescription(connDiff.diff, src, dst, thisMinusOther)
			diffInfo := diffInfoStr(diffAnalysis)
			printDiff := fmt.Sprintf("%v %s, source: %s, destination: %s, ", diffTypeStr, diffType, src.Name(), dst.Name())
			printDiff += fmt.Sprintf(configsStr, conn1Str, conn2Str, diffInfo, endpointsDiff) + "\n"
			strList = append(strList, printDiff)
		}
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}
