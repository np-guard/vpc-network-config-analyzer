/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
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
	cfg1 := &VPCConfig{}
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "10.0.20.5/32", name: "vsi1-1"},
		&mockNetIntf{cidr: "10.3.20.6/32", name: "vsi1-2"},
		&mockNetIntf{cidr: "10.7.20.7/32", name: "vsi1-3"})

	cfg1.Subnets = append(cfg1.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet0", []Node{cfg1.Nodes[0]}},
		&mockSubnet{nil, "10.1.20.0/22", "subnet1", []Node{cfg1.Nodes[0]}},
		&mockSubnet{nil, "10.2.20.0/22", "subnet2", []Node{cfg1.Nodes[1]}})
	cfg1.Subnets = append(cfg1.Subnets, &mockSubnet{nil, "10.3.20.0/22", "subnet3", []Node{cfg1.Nodes[2]}},
		&mockSubnet{nil, "10.4.20.0/22", "subnet4", []Node{cfg1.Nodes[2]}})

	cfg2 := &VPCConfig{}
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{cidr: "10.3.20.5/32", name: "vsi2-1"},
		&mockNetIntf{cidr: "10.7.20.6/32", name: "vsi2-2"},
		&mockNetIntf{cidr: "10.9.20.7/32", name: "vsi2-3"},
		&mockNetIntf{cidr: "11.4.20.6/32", name: "vsi2-4"})
	cfg2.Subnets = append(cfg2.Subnets, &mockSubnet{nil, "10.2.20.0/22", "subnet2", []Node{cfg2.Nodes[0]}},
		&mockSubnet{nil, "10.3.20.0/22", "subnet3", []Node{cfg2.Nodes[1]}},
		&mockSubnet{nil, "10.4.20.0/22", "subnet4", []Node{cfg2.Nodes[2]}},
		&mockSubnet{nil, "11.4.20.0/22", "subnet5", []Node{cfg2.Nodes[3]}})

	connResponsiveAll := detailedConnForResponsive(connection.All())
	connectionTCP := connection.TCPorUDPConnection(netp.ProtocolStringTCP, 10, 100, 443, 443)
	connResponsiveTCP := detailedConnForResponsive(connectionTCP)
	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombinedResponsive: GeneralResponsiveConnectivityMap{}}
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[0], cfg1.Subnets[1], connResponsiveAll)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[1], cfg1.Subnets[2], connResponsiveAll)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[3], cfg1.Subnets[1], connResponsiveAll)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[2], cfg1.Subnets[3], connResponsiveAll)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[3], cfg1.Subnets[2], connResponsiveAll)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[3], cfg1.Subnets[4], connResponsiveTCP)

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombinedResponsive: GeneralResponsiveConnectivityMap{}}
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Subnets[1], cfg2.Subnets[0], connResponsiveAll)
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Subnets[1], cfg2.Subnets[2], connResponsiveAll)
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Subnets[2], cfg2.Subnets[3], connResponsiveAll)

	subnetConfigConn1 = &configConnectivity{cfg1, subnetConnMap1.AllowedConnsCombinedResponsive}
	subnetConfigConn2 = &configConnectivity{cfg2, subnetConnMap2.AllowedConnsCombinedResponsive}

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
		"config1: All Connections, config2: No Connections")
	require.Contains(t, subnet1Subtract2Str, "diff-type: removed, source: subnet3, destination: subnet1, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet1 removed")
	require.Contains(t, subnet1Subtract2Str, "diff-type: changed, source: subnet3, destination: subnet4, "+
		"config1: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections")

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
		"config1: All Connections, config2: No Connections")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: subnet3, destination: subnet1, "+
		"config1: All Connections, config2: No Connections, subnets-diff-info: subnet1 removed\n")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: subnet3, destination: subnet4, "+
		"config1: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: added, source: subnet4, destination: subnet5, config1: "+
		"No Connections, config2: All Connections, subnets-diff-info: subnet5 added\n")
}

func configSimpleIPAndSubnetDiff() (subnetConfigConn1, subnetConfigConn2 *configConnectivity) {
	cfg1 := &VPCConfig{}
	cfg1.Subnets = append(cfg1.Subnets, &mockSubnet{nil, "10.1.20.0/22", "subnet1", nil},
		&mockSubnet{nil, "10.2.20.0/22", "subnet2", nil})
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{cidr: "1.2.3.0/30", name: "public1-1", isExternal: true},
		&mockNetIntf{cidr: "250.2.4.0/24", name: "public1-2", isExternal: true},
		&mockNetIntf{cidr: "200.2.4.0/24", name: "public1-3", isExternal: true})

	cfg2 := &VPCConfig{}
	cfg2.Subnets = append(cfg2.Subnets, &mockSubnet{nil, "10.1.20.0/22", "subnet1", nil},
		&mockSubnet{nil, "10.2.20.0/22", "subnet2", nil})
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{cidr: "1.2.3.0/26", name: "public2-1", isExternal: true},
		&mockNetIntf{cidr: "250.2.4.0/30", name: "public2-2", isExternal: true},
		&mockNetIntf{cidr: "200.2.4.0/24", name: "public1-3", isExternal: true})

	//      cfg1                                            cfg2
	// <subnet2, public1-1>	    		 and		<subnet2, public2-1> are comparable
	// <public1-2, subnet2> 			 and 		<public2-2, subnet2> are comparable
	// <public1-1, subnet2> 			 and 		<public2-1, subnet2> are comparable
	// <public1-1, subnet1> 			 and 		<public2-1, subnet1> are comparable
	connResponsive := detailedConnForResponsive(connection.All())
	subnetConnMap1 := &VPCsubnetConnectivity{AllowedConnsCombinedResponsive: GeneralResponsiveConnectivityMap{}}
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[0], cfg1.Subnets[0], connResponsive)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[0], cfg1.Subnets[1], connResponsive)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[1], cfg1.Subnets[1], connResponsive)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[1], cfg1.Nodes[0], connResponsive)
	subnetConnMap1.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Subnets[1], cfg1.Nodes[2], connResponsive)

	subnetConnMap2 := &VPCsubnetConnectivity{AllowedConnsCombinedResponsive: GeneralResponsiveConnectivityMap{}}
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[0], cfg2.Subnets[0], connResponsive)
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[0], cfg2.Subnets[1], connResponsive)
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[1], cfg2.Subnets[1], connResponsive)
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Subnets[1], cfg2.Nodes[0], connResponsive)
	connectionTCP := connection.TCPorUDPConnection(netp.ProtocolStringTCP, 0, 1000, 0, 443)
	connTCP := detailedConnForResponsive(connectionTCP)
	subnetConnMap2.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Subnets[1], cfg2.Nodes[2], connTCP)

	subnetConfigConn1 = &configConnectivity{cfg1, subnetConnMap1.AllowedConnsCombinedResponsive}
	subnetConfigConn2 = &configConnectivity{cfg2, subnetConnMap2.AllowedConnsCombinedResponsive}

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
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.16/28], destination: subnet2, "+
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.32/27], destination: subnet2, "+
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.4/30], destination: subnet2, "+
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.64/26], destination: subnet2, "+
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: removed, source: Public Internet [250.2.4.8/29], destination: subnet2, "+
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg1SubtractCfg2Str, "diff-type: changed, source: subnet2, destination: Public Internet [200.2.4.0/24], "+
		"config1: All Connections, config2: TCP src-ports: 0-1000 dst-ports: 0-443")
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
		"destination: subnet1, config1: No Connections, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: added, source: Public Internet 1.2.3.4-1.2.3.63, "+
		"destination: subnet2, config1: No Connections, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: added, source: subnet2, destination: Public Internet 1.2.3.4-1.2.3.63, "+
		"config1: No Connections, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: subnet2, destination: Public Internet 200.2.4.0/24, "+
		"config1: All Connections, config2: TCP src-ports: 0-1000 dst-ports: 0-443")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: Public Internet 250.2.4.4-250.2.4.255, destination: subnet2, "+
		"config1: All Connections, config2: No Connections")
}

func configSimpleVsisDiff() (configConn1, configConn2 *configConnectivity) {
	cfg1 := &VPCConfig{}
	cfg1.Nodes = append(cfg1.Nodes,
		&mockNetIntf{name: "vsi0", isExternal: false, cidr: ""},
		&mockNetIntf{name: "vsi1", isExternal: false, cidr: ""},
		&mockNetIntf{name: "vsi2", isExternal: false, cidr: ""},
		&mockNetIntf{name: "vsi3", isExternal: false, cidr: ""},
		&mockNetIntf{cidr: "1.2.3.0/30", name: "public1-1", isExternal: true})

	cfg1.Subnets = append(cfg1.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet0", []Node{cfg1.Nodes[0], cfg1.Nodes[1],
		cfg1.Nodes[2], cfg1.Nodes[3]}})

	cfg2 := &VPCConfig{}
	cfg2.Nodes = append(cfg2.Nodes,
		&mockNetIntf{name: "vsi1", isExternal: false, cidr: ""},
		&mockNetIntf{name: "vsi2", isExternal: false, cidr: ""},
		&mockNetIntf{name: "vsi3", isExternal: false, cidr: ""},
		&mockNetIntf{name: "vsi4", isExternal: false, cidr: ""},
		&mockNetIntf{cidr: "1.2.3.0/26", name: "public2-1", isExternal: true})

	cfg2.Subnets = append(cfg2.Subnets, &mockSubnet{nil, "10.0.20.0/22", "subnet0", []Node{cfg2.Nodes[0], cfg2.Nodes[1],
		cfg2.Nodes[2], cfg2.Nodes[3]}})

	connAll := detailedConnForResponsive(connection.All())
	connectionTCP := connection.TCPorUDPConnection(netp.ProtocolStringTCP, 10, 100, 443, 443)
	connTCP := detailedConnForResponsive(connectionTCP)
	cfg1Conn := &VPCConnectivity{AllowedConnsCombinedResponsive: GeneralResponsiveConnectivityMap{}}
	cfg1Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[0], cfg1.Nodes[1], connAll)
	cfg1Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[1], cfg1.Nodes[2], connAll)
	cfg1Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[1], cfg1.Nodes[3], connAll)
	cfg1Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[2], cfg1.Nodes[3], connTCP)
	cfg1Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg1.Nodes[2], cfg1.Nodes[4], connTCP)

	cfg2Conn := &VPCConnectivity{AllowedConnsCombinedResponsive: GeneralResponsiveConnectivityMap{}}
	// 1st connections is identical to these in cfg1; the 2nd one differs in the conn type, the 3rd one has a dst that
	// does not exist in cfg1
	cfg2Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[0], cfg2.Nodes[1], connAll)
	cfg2Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[1], cfg2.Nodes[2], connAll)
	cfg2Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[2], cfg2.Nodes[3], connAll)
	cfg2Conn.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(cfg2.Nodes[1], cfg2.Nodes[4], connAll)

	configConn1 = &configConnectivity{cfg1, cfg1Conn.AllowedConnsCombinedResponsive}
	configConn2 = &configConnectivity{cfg2, cfg2Conn.AllowedConnsCombinedResponsive}

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
		"TCP src-ports: 10-100 dst-ports: 443, config2: All Connections")
	require.Contains(t, cfg1SubCfg2Str, "diff-type: removed, source: vsi0, destination: vsi1, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info: vsi0 removed")
	require.Contains(t, cfg1SubCfg2Str, "diff-type: removed, source: vsi1, destination: vsi3, config1: "+
		"All Connections, config2: No Connections")

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
		"destination: Public Internet [1.2.3.16/28], config1: All Connections, config2: No Connections")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, "+
		"destination: Public Internet [1.2.3.32/27], config1: All Connections, config2: No Connections")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, destination: Public Internet [1.2.3.4/30], "+
		"config1: All Connections, config2: No Connections")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi2, "+
		"destination: Public Internet [1.2.3.8/29], config1: All Connections, config2: No Connections")
	require.Contains(t, cfg2SubCfg1Str, "diff-type: removed, source: vsi3, destination: vsi4, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info: vsi4 removed")
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
		"config1: No Connections, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: added, source: vsi3, destination: vsi4, config1: No Connections, "+
		"config2: All Connections, vsis-diff-info: vsi4 added\n")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: vsi2, destination: Public Internet 1.2.3.0/30, "+
		"config1: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: changed, source: vsi2, destination: vsi3, "+
		"config1: TCP src-ports: 10-100 dst-ports: 443, config2: All Connections")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: vsi0, destination: vsi1, config1: "+
		"All Connections, config2: No Connections, vsis-diff-info: vsi0 removed\n")
	require.Contains(t, groupedPrinted, "diff-type: removed, source: vsi1, destination: vsi3, "+
		"config1: All Connections, config2: No Connections")
}

func (connDiff *connectivityDiff) string(diffAnalysis diffAnalysisType, thisMinusOther bool) string {
	strList := []string{}
	for src, endpointConnDiff := range *connDiff {
		for dst, connDiff := range endpointConnDiff {
			connDiff.thisMinusOther = thisMinusOther
			conn1Str, conn2Str := conn1And2Str(connDiff)
			diffType, diffInfoBody := diffAndEndpointsDescription(connDiff.diff, src, dst, thisMinusOther)
			diffInfo := getDiffInfo(diffAnalysis, diffInfoBody)
			printDiff := fmt.Sprintf("%v %s, source: %s, destination: %s, ", diffTypeStr, diffType,
				src.NameForAnalyzerOut(nil), dst.NameForAnalyzerOut(nil))
			printDiff += fmt.Sprintf(configsStr, conn1Str, conn2Str, diffInfo) + "\n"
			strList = append(strList, printDiff)
		}
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}
