/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	_ "embed"
	"fmt"
	"os"
	"testing"

	"github.com/np-guard/cloud-resource-collector/pkg/common"
)

func createFileFromNetwork(network SquareTreeNodeInterface, fileName string, subnetMode bool, format FileFormat, provider common.Provider) {
	res, err := CreateDrawioConnectivityMap(network, subnetMode, format, nil, provider)
	if err != nil {
		fmt.Printf("Error when calling CreateDrawioConnectivityMap() for file %s:\n%s\n", fileName, err)
	}
	err = os.WriteFile(fileName, []byte(res), 0o600)
	if err != nil {
		fmt.Printf("Error when calling WriteFile for file %s:\n%s\n", fileName, err)
	}
}
func TestWithParsing(t *testing.T) {
	var n SquareTreeNodeInterface
	n = createNetwork()
	createFileFromNetwork(n, "fake.drawio", false, FileDRAWIO, common.IBM)
	n = createNetworkSubnets()
	createFileFromNetwork(n, "fakeSubnets.drawio", true, FileDRAWIO, common.IBM)
	n = createNetwork2()
	createFileFromNetwork(n, "fake2.drawio", false, FileDRAWIO, common.IBM)
	n = createNetworkGrouping()
	createFileFromNetwork(n, "grouping.drawio", false, FileDRAWIO, common.IBM)
	n = createNetworkSubnetGrouping()
	createFileFromNetwork(n, "subnetGrouping.drawio", true, FileDRAWIO, common.IBM)
	n = createNetworkSubnetGroupingBug()
	createFileFromNetwork(n, "subnetGroupingBug.svg", true, FileSVG, common.IBM)
	n = createNetworkSubnetGroupingMultiVpc()
	createFileFromNetwork(n, "subnetGroupingMultiVpc.html", true, FileHTML, common.IBM)
	n = createNetworkSubnetGroupingOverlapping()
	createFileFromNetwork(n, "subnetGroupingOverlapping.drawio", true, FileDRAWIO, common.IBM)
	n = createNetworkSubnetGroupingGroupInGroup()
	createFileFromNetwork(n, "subnetGroupingGroupInGroup.html", true, FileHTML, common.IBM)
	n = createEmptySquaresNetwork()
	createFileFromNetwork(n, "empty.drawio", false, FileDRAWIO, common.IBM)
	n = createEmptySquaresNetwork()
	createFileFromNetwork(n, "emptySubnets.drawio", true, FileDRAWIO, common.IBM)

	n = createNetworkAllTypes()
	createFileFromNetwork(n, "all.drawio", false, FileDRAWIO, common.IBM)
	n = createNetworkTgw()
	createFileFromNetwork(n, "tgws.drawio", false, FileDRAWIO, common.IBM)
	n = createNetworkAws()
	createFileFromNetwork(n, "aws.drawio", false, FileDRAWIO, common.AWS)
	n = createNetworkAws()
	createFileFromNetwork(n, "aws.html", false, FileHTML, common.AWS)
	n = createNetworkMultiSG()
	createFileFromNetwork(n, "multiSG.html", false, FileHTML, common.IBM)
}

func createNetwork() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	cloud := NewCloudTreeNode(network, "IBM Cloud")
	publicNetwork := NewPublicNetworkTreeNode(network)
	i1 := NewInternetTreeNode(publicNetwork, "i1")
	i2 := NewInternetTreeNode(publicNetwork, "i2")
	i3 := NewInternetTreeNode(publicNetwork, "i3")
	i4 := NewUserTreeNode(publicNetwork, "i4")
	region := NewRegionTreeNode(cloud, "north")
	vpc1 := NewVpcTreeNode(region, "vpc1")
	zone11 := NewZoneTreeNode(vpc1, "zone1")

	gw11 := NewGatewayTreeNode(zone11, "gw11")
	is1a := NewInternetServiceTreeNode(vpc1, "is1a")
	is1b := NewInternetServiceTreeNode(vpc1, "is1b")
	is1c := NewInternetServiceTreeNode(vpc1, "is1c")
	is1d := NewInternetServiceTreeNode(vpc1, "is1d")
	is1e := NewInternetServiceTreeNode(vpc1, "is1e")

	sg11 := NewSGTreeNode(vpc1, "sg11")
	sg12 := NewSGTreeNode(vpc1, "sg12")

	subnet111 := NewSubnetTreeNode(zone11, "subnet111", "ip", "key")

	ni1 := NewNITreeNode(subnet111, "ni1")
	ni2 := NewNITreeNode(subnet111, "ni2")
	sg11.AddIcon(ni1)
	sg12.AddIcon(ni2)

	GroupNIsWithVSI(zone11, "vsi1", []TreeNodeInterface{ni1, ni2})

	zone12 := NewZoneTreeNode(vpc1, "zone12")
	gw12 := NewGatewayTreeNode(zone12, "gw12")
	subnet112 := NewSubnetTreeNode(zone11, "subnet112", "ip", "key")
	subnet121 := NewSubnetTreeNode(zone12, "subnet121", "ip", "key")
	ni4 := NewNITreeNode(subnet112, "ni4")
	sg12.AddIcon(ni4)
	ni4.setVsi("svi1")
	ni5 := NewNITreeNode(subnet121, "ni5")
	sg11.AddIcon(ni5)

	ni5.setVsi("svi2")
	ni5.SetFIP("fip")
	ni5b := NewNITreeNode(subnet121, "ni5b")
	sg11.AddIcon(ni5b)

	ni5b.setVsi("svi3")
	ni5b.SetFIP("fip2")

	region1 := NewRegionTreeNode(cloud, "north")
	region2 := NewRegionTreeNode(cloud, "south")
	NewVpcTreeNode(region1, "empty vpc")
	vpc2 := NewVpcTreeNode(region2, "vpc2")
	zone21 := NewZoneTreeNode(vpc2, "zone21")
	sg21 := NewSGTreeNode(vpc2, "sg21")

	subnet211 := NewSubnetTreeNode(zone21, "subnet211", "ip", "key")

	ni6 := NewNITreeNode(subnet211, "ni6")
	ni7 := NewNITreeNode(subnet211, "ni7")
	ni8 := NewNITreeNode(subnet211, "ni8")
	sg21.AddIcon(ni6)
	sg21.AddIcon(ni7)
	sg21.AddIcon(ni8)

	GroupNIsWithVSI(zone21, "vsi2", []TreeNodeInterface{ni6, ni7, ni8})

	zone22 := NewZoneTreeNode(vpc2, "zone22")
	NewZoneTreeNode(vpc2, "empty zone")
	zone23 := NewZoneTreeNode(vpc2, "zone23")
	subnet221 := NewSubnetTreeNode(zone22, "subnet221", "ip", "key")
	NewSubnetTreeNode(zone22, "empty subnet", "ip", "key")
	subnet222 := NewSubnetTreeNode(zone22, "subnet222", "ip", "key")
	subnet231 := NewSubnetTreeNode(zone23, "subnet231", "ip", "key")
	sg22 := NewSGTreeNode(vpc2, "sg22")

	ni10 := NewNITreeNode(subnet221, "ni10")
	ni11 := NewNITreeNode(subnet222, "ni11")
	ni12 := NewNITreeNode(subnet222, "ni12")
	ni13 := NewNITreeNode(subnet222, "ni13")
	ni14 := NewNITreeNode(subnet222, "ni14")
	sg22.AddIcon(ni10)
	sg22.AddIcon(ni11)
	sg22.AddIcon(ni12)
	sg22.AddIcon(ni13)
	sg22.AddIcon(ni14)

	resip1 := NewResIPTreeNode(subnet211, "resip1")
	resip2 := NewResIPTreeNode(subnet221, "resip2")
	resip3 := NewResIPTreeNode(subnet231, "resip2")
	sg22.AddIcon(resip1)
	sg22.AddIcon(resip2)
	sg22.AddIcon(resip3)

	NewConnectivityLineTreeNode(network, resip1, resip3, true, "c10")
	GroupResIPsWithVpe(vpc2, "vpe1", []TreeNodeInterface{resip1, resip2})
	GroupResIPsWithVpe(vpc2, "vpe2", []TreeNodeInterface{resip3})

	GroupNIsWithVSI(zone22, "vsi3", []TreeNodeInterface{ni10, ni13, ni14})

	GroupNIsWithVSI(zone22, "vsi4", []TreeNodeInterface{ni11, ni12})

	ni20 := NewNITreeNode(subnet231, "ni20")
	ni21 := NewNITreeNode(subnet231, "ni21")
	ni22 := NewNITreeNode(subnet231, "ni22")
	ni23 := NewNITreeNode(subnet231, "ni23")
	ni24 := NewNITreeNode(subnet231, "ni24")
	ni25 := NewNITreeNode(subnet231, "ni25")
	ni26 := NewNITreeNode(subnet231, "ni26")
	ni27 := NewNITreeNode(subnet231, "ni27")
	ni28 := NewNITreeNode(subnet231, "ni28")
	ni29 := NewNITreeNode(subnet231, "ni29")

	sg22.AddIcon(ni20)
	sg22.AddIcon(ni22)
	sg22.AddIcon(ni23)
	sg22.AddIcon(ni25)
	sg22.AddIcon(ni28)
	sg22.AddIcon(ni29)

	gw21 := NewGatewayTreeNode(zone21, "gw21")
	gw22 := NewGatewayTreeNode(zone22, "gw22")

	is2 := NewInternetServiceTreeNode(vpc2, "is2")

	c1 := NewConnectivityLineTreeNode(network, ni4, i4, false, "c1")
	c2a := NewConnectivityLineTreeNode(network, ni5, i2, false, "c2a")
	c2b := NewConnectivityLineTreeNode(network, ni5, i2, true, "c2b")
	c2c := NewConnectivityLineTreeNode(network, i2, ni5, true, "c2c")

	c3 := NewConnectivityLineTreeNode(network, ni8, i3, true, "c3")
	c4 := NewConnectivityLineTreeNode(network, ni11, i1, true, "c4")
	c5 := NewConnectivityLineTreeNode(network, ni12, i1, true, "c5")

	c6 := NewConnectivityLineTreeNode(network, ni5b, i3, false, "c6")
	c7 := NewConnectivityLineTreeNode(network, ni5b, i4, false, "c7")

	c1.SetRouter(gw11)
	c2a.SetRouter(ni5)
	c2b.SetRouter(ni5)
	c2c.SetRouter(ni5)
	c3.SetRouter(gw21)
	c4.SetRouter(gw22)
	c5.SetRouter(gw22)
	c6.SetRouter(gw12)
	c7.SetRouter(ni5b)

	NewConnectivityLineTreeNode(network, ni10, is2, true, "c10")
	NewConnectivityLineTreeNode(network, ni1, is1a, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1b, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1c, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1d, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1e, true, "c11")

	NewConnectivityLineTreeNode(network, ni8, ni14, true, "c12")

	NewConnectivityLineTreeNode(network, ni20, ni22, true, "c13")
	NewConnectivityLineTreeNode(network, ni21, ni24, true, "c14")
	NewConnectivityLineTreeNode(network, ni24, ni21, true, "c14op")
	NewConnectivityLineTreeNode(network, ni23, ni27, true, "c15")
	NewConnectivityLineTreeNode(network, ni25, ni29, true, "c16")
	NewConnectivityLineTreeNode(network, ni26, ni27, true, "c17")
	NewConnectivityLineTreeNode(network, ni28, ni26, true, "c18")
	NewConnectivityLineTreeNode(network, ni22, ni28, true, "c19")

	return network
}

func createNetworkSubnets() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	cloud := NewCloudTreeNode(network, "IBM Cloud")
	publicNetwork := NewPublicNetworkTreeNode(network)
	i1 := NewInternetTreeNode(publicNetwork, "i1")
	i2 := NewInternetTreeNode(publicNetwork, "i2")
	i3 := NewInternetTreeNode(publicNetwork, "i3")
	i4 := NewUserTreeNode(publicNetwork, "i4")
	region := NewRegionTreeNode(cloud, "north")
	vpc1 := NewVpcTreeNode(region, "vpc1")
	zone11 := NewZoneTreeNode(vpc1, "zone1")

	subnet111 := NewSubnetTreeNode(zone11, "subnet111", "ip", "key")

	zone12 := NewZoneTreeNode(vpc1, "zone12")
	subnet112 := NewSubnetTreeNode(zone11, "subnet112", "ip", "key")
	subnet121 := NewSubnetTreeNode(zone12, "subnet121", "ip", "key")
	region2 := NewRegionTreeNode(cloud, "south")
	vpc2 := NewVpcTreeNode(region2, "vpc2")
	zone21 := NewZoneTreeNode(vpc2, "zone21")
	subnet211 := NewSubnetTreeNode(zone21, "subnet211", "ip", "key")

	zone22 := NewZoneTreeNode(vpc2, "zone22")
	zone23 := NewZoneTreeNode(vpc2, "zone23")
	subnet221 := NewSubnetTreeNode(zone22, "subnet221", "ip", "key")
	NewSubnetTreeNode(zone22, "empty subnet", "ip", "key")
	subnet222 := NewSubnetTreeNode(zone22, "subnet222", "ip", "key")
	subnet231 := NewSubnetTreeNode(zone23, "subnet231", "ip", "key")

	is2 := NewInternetServiceTreeNode(vpc2, "is2")

	NewConnectivityLineTreeNode(network, subnet111, is2, true, "c10")
	NewConnectivityLineTreeNode(network, subnet112, i1, true, "c11")
	NewConnectivityLineTreeNode(network, subnet121, i1, true, "c11")
	NewConnectivityLineTreeNode(network, subnet211, i2, true, "c11")
	NewConnectivityLineTreeNode(network, subnet221, i3, true, "c11")
	NewConnectivityLineTreeNode(network, subnet222, i4, true, "c11")

	NewConnectivityLineTreeNode(network, subnet231, i4, true, "c12")

	return network
}

func createNetworkAllTypes() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	publicNetwork := NewPublicNetworkTreeNode(network)

	cloud1 := NewCloudTreeNode(network, "IBM Cloud")
	region := NewRegionTreeNode(cloud1, "north")
	vpc1 := NewVpcTreeNode(region, "vpc1")
	sg := NewSGTreeNode(vpc1, "sg33")
	zone1 := NewZoneTreeNode(vpc1, "zone1")
	subnet11 := NewSubnetTreeNode(zone1, "subnet1", "cidr1", "acl1")
	subnet13 := NewSubnetTreeNode(zone1, "subnet2", "cidr2", "acl2")

	nia := NewNITreeNode(subnet11, "ni1a")
	ripb := NewResIPTreeNode(subnet11, "ni1b")
	nic := NewNITreeNode(subnet13, "ni1c")
	nid := NewNITreeNode(subnet13, "ni1d")
	nie := NewNITreeNode(subnet13, "ni1e")
	sg.AddIcon(nia)
	sg.AddIcon(ripb)
	sg.AddIcon(nic)
	sg.AddIcon(nid)
	sg.AddIcon(nie)
	GroupNIsWithVSI(zone1, "vsi1", []TreeNodeInterface{nia, nid})
	GroupNIsWithVSI(zone1, "vsi3", []TreeNodeInterface{nic})
	GroupNIsWithVSI(zone1, "vsi4", []TreeNodeInterface{nie})
	groupedNis11 := []IconTreeNodeInterface{nia, ripb}
	groupedNis13 := []IconTreeNodeInterface{nic, nid}
	nie.SetFIP("fip")
	gs11 := NewGroupSquareTreeNode(subnet11, groupedNis11, "groupedNis11")
	gs13 := NewGroupSquareTreeNode(subnet13, groupedNis13, "groupedNis13")

	i1 := NewInternetTreeNode(publicNetwork, "Internet2")
	i2 := NewInternetTreeNode(publicNetwork, "Internet2")
	u2 := NewUserTreeNode(publicNetwork, "Internet2")

	zone3 := NewZoneTreeNode(vpc1, "zone1")
	subnet33 := NewSubnetTreeNode(zone3, "subnet2", "cidr2", "acl2")
	ni33a := NewNITreeNode(subnet33, "ni1a")
	rip33b := NewResIPTreeNode(subnet33, "ni1b")
	ni33c := NewNITreeNode(subnet33, "ni1c")
	rip33d := NewResIPTreeNode(subnet33, "ni1d")
	ni33e := NewNITreeNode(subnet33, "ni1e")
	sg.AddIcon(ni33a)
	sg.AddIcon(rip33b)
	sg.AddIcon(ni33c)
	sg.AddIcon(rip33d)
	sg.AddIcon(ni33e)

	GroupResIPsWithVpe(vpc1, "vpe1", []TreeNodeInterface{ripb, rip33d})
	GroupNIsWithVSI(zone3, "vsi2", []TreeNodeInterface{ni33a})
	GroupResIPsWithVpe(vpc1, "vpe3", []TreeNodeInterface{rip33b})
	GroupNIsWithVSI(zone3, "vsi4", []TreeNodeInterface{ni33c})
	GroupNIsWithVSI(zone3, "vsi4", []TreeNodeInterface{ni33e})

	groupedNis33a := []IconTreeNodeInterface{ni33a, rip33b, ni33c, rip33d, ni33e}
	groupedNis33b := []IconTreeNodeInterface{ni33a, rip33b}
	groupedNis33c := []IconTreeNodeInterface{ni33a, rip33b, ni33c}
	groupedNis33d := []IconTreeNodeInterface{ni33c, ni33e}
	gs33a := NewGroupSquareTreeNode(subnet33, groupedNis33a, "groupedNis33a")
	gs33b := NewGroupSquareTreeNode(subnet33, groupedNis33b, "groupedNis33b")
	gs33c := NewGroupSquareTreeNode(subnet33, groupedNis33c, "groupedNis33c")
	gs33d := NewGroupSquareTreeNode(subnet33, groupedNis33d, "groupedNis33d")
	gw1 := NewGatewayTreeNode(zone1, "gw21")

	c1 := NewConnectivityLineTreeNode(network, nie, i1, true, "gconn1")
	c1.SetRouter(nie)
	NewConnectivityLineTreeNode(network, gs13, i2, true, "gconn2")
	NewConnectivityLineTreeNode(network, gs11, gs11, true, "gconn3")
	c2 := NewConnectivityLineTreeNode(network, gs33a, u2, true, "gconn4")
	c2.SetRouter(gw1)
	NewConnectivityLineTreeNode(network, gs33d, gs11, true, "gconn5")
	NewConnectivityLineTreeNode(network, gs33c, gs33b, true, "gconn6")
	return network
}

// /////////////////////////////////////////////////////////////////////////////
func createZone(zones *[][]SquareTreeNodeInterface, vpc *VpcTreeNode, size int, name string) {
	zone := NewZoneTreeNode(vpc, name)
	subnets := make([]SquareTreeNodeInterface, size)
	*zones = append(*zones, subnets)
	for i := 0; i < size; i++ {
		sname := fmt.Sprint(name, i)
		subnets[i] = NewSubnetTreeNode(zone, sname, "", "")
	}
}
func createGroup(zones *[][]SquareTreeNodeInterface, vpc *VpcTreeNode, i1, i2, j1, j2 int) SquareTreeNodeInterface {
	gr := []SquareTreeNodeInterface{}
	for i := i1; i <= i2; i++ {
		for j := j1; j <= j2; j++ {
			gr = append(gr, (*zones)[i][j])
		}
	}
	if len(gr) == 1 {
		return gr[0]
	}
	g := GroupedSubnetsSquare(vpc, gr)
	if g.IsGroupSubnetsSquare() {
		g.(*GroupSubnetsSquareTreeNode).name = fmt.Sprintf("%d-%d,%d,%d", i1, i2, j1, j2)
	}
	return g
}

type groupIndexes struct {
	vpcIndex int
	z1, z2   int
	s1, s2   int
}

func createNetworkSubnetGrouping() SquareTreeNodeInterface {
	groupsIndexes := []groupIndexes{
		{0, 0, 0, 0, 1},
		{0, 1, 1, 0, 1},
		{0, 0, 2, 0, 6},
		{0, 0, 2, 4, 6},
		{0, 3, 3, 1, 2},
		{0, 2, 3, 1, 2},
		{0, 0, 4, 0, 3},
		{0, 0, 5, 0, 3},

		{0, 6, 7, 0, 1},
		{0, 6, 6, 2, 3},
		{0, 7, 8, 1, 2},
	}
	n, _, _ := createNetworkSubnetGroupingGeneric(groupsIndexes)
	return n
}

func createNetworkSubnetGroupingMultiVpc() SquareTreeNodeInterface {
	groupsIndexes := []groupIndexes{
		{0, 0, 3, 0, 1},
		{0, 1, 4, 0, 1},
		{0, 2, 5, 0, 1},
		{0, 3, 6, 0, 1},

		{0, 7, 8, 0, 1},
		{0, 8, 9, 0, 1},

		{1, 10, 12, 0, 1},
		{1, 11, 13, 0, 1},
		{1, 12, 14, 0, 1},

		{2, 15, 16, 0, 1},
		{2, 16, 17, 0, 1},
		{2, 17, 18, 0, 1},
	}
	n, _, _ := createNetworkSubnetGroupingGeneric(groupsIndexes)
	return n
}
func createNetworkSubnetGroupingBug() SquareTreeNodeInterface {
	groupsIndexes := []groupIndexes{
		{0, 0, 1, 4, 4},
		{0, 1, 2, 4, 4},
		{0, 2, 3, 4, 4},

		{0, 0, 2, 0, 3},
		{0, 3, 3, 0, 3},
		{0, 2, 3, 0, 3},
	}
	n, _, _ := createNetworkSubnetGroupingGeneric(groupsIndexes)
	return n
}

func createNetworkSubnetGroupingOverlapping() SquareTreeNodeInterface {
	groupsIndexes := []groupIndexes{
		{0, 0, 1, 4, 4},
		{0, 1, 2, 4, 4},
		{0, 2, 3, 4, 4},

		{0, 0, 2, 0, 2},
	}
	n, groups, zones := createNetworkSubnetGroupingGeneric(groupsIndexes)
	conns := [][]SquareTreeNodeInterface{
		{groups[0], groups[1]},
		{groups[0], groups[2]},
		{groups[1], groups[2]},

		{(*zones)[0][0], (*zones)[0][3]},
		{(*zones)[0][0], (*zones)[3][3]},
		{(*zones)[0][0], (*zones)[3][0]},

		{(*zones)[0][3], (*zones)[0][0]},
		{(*zones)[0][3], (*zones)[3][3]},
		{(*zones)[0][3], (*zones)[3][0]},

		{(*zones)[3][0], (*zones)[0][0]},
		{(*zones)[3][0], (*zones)[0][3]},
		{(*zones)[3][0], (*zones)[3][3]},

		{(*zones)[3][3], (*zones)[0][0]},
		{(*zones)[3][3], (*zones)[0][3]},
		{(*zones)[3][3], (*zones)[3][0]},

		{(*zones)[0][0], (*zones)[0][1]},
		{(*zones)[0][1], (*zones)[0][3]},

		{(*zones)[0][0], (*zones)[1][0]},
		{(*zones)[1][0], (*zones)[3][0]},

		{(*zones)[0][0], (*zones)[1][1]},
		{(*zones)[1][1], (*zones)[3][3]},

		{(*zones)[0][0], (*zones)[1][3]},
		{(*zones)[1][3], (*zones)[0][0]},
		{(*zones)[0][0], (*zones)[3][1]},
		{(*zones)[3][1], (*zones)[0][0]},

		{(*zones)[0][3], (*zones)[3][2]},
		{(*zones)[3][2], (*zones)[0][3]},
		{(*zones)[0][3], (*zones)[2][0]},
		{(*zones)[2][0], (*zones)[0][3]},

		{(*zones)[3][0], (*zones)[2][3]},
		{(*zones)[2][3], (*zones)[3][0]},
		{(*zones)[3][0], (*zones)[0][2]},
		{(*zones)[0][2], (*zones)[3][0]},

		{groups[3], (*zones)[1][0]},
		{(*zones)[1][0], groups[3]},
		{groups[3], (*zones)[1][1]},
		{(*zones)[1][1], groups[3]},
		{groups[3], (*zones)[1][2]},
		{(*zones)[1][2], groups[3]},
	}
	for i, conn := range conns {
		NewConnectivityLineTreeNode(n, conn[0], conn[1], true, fmt.Sprintf("gconn%d %s->%s", i, treeNodeName(conn[0]), treeNodeName(conn[1])))
	}
	return n
}

func createNetworkSubnetGroupingGroupInGroup() SquareTreeNodeInterface {
	groupsIndexes := []groupIndexes{
		{0, 0, 1, 0, 1},
		{0, 0, 1, 2, 3},
		{0, 2, 3, 0, 1},
		{0, 2, 3, 2, 3},

		{0, 0, 3, 0, 3},

		{0, 0, 4, 4, 4},

		{0, 0, 3, 2, 3},
	}
	n, groups, zones := createNetworkSubnetGroupingGeneric(groupsIndexes)
	conns := [][]SquareTreeNodeInterface{
		{groups[0], groups[1]},
		{groups[0], groups[2]},
		{groups[0], groups[3]},
		{groups[1], groups[2]},
		{groups[1], groups[3]},
		{groups[2], groups[3]},

		{groups[4], groups[0]},
		{groups[4], groups[1]},
		{groups[4], groups[2]},
		{groups[4], groups[3]},

		{groups[5], groups[0]},
		{groups[5], groups[1]},
		{groups[5], groups[2]},
		{groups[5], groups[3]},
		{groups[5], groups[4]},

		{groups[0], groups[6]},
		{groups[2], groups[6]},

		{groups[0], groups[0]},

		{groups[5], (*zones)[0][4]},
		{groups[5], (*zones)[1][4]},
		{groups[5], (*zones)[2][4]},
		{groups[5], (*zones)[3][4]},
		{groups[5], (*zones)[4][4]},
	}
	for i, conn := range conns {
		NewConnectivityLineTreeNode(n, conn[0], conn[1], true, fmt.Sprintf("gconn%d %s->%s", i, treeNodeName(conn[0]), treeNodeName(conn[1])))
	}
	return n
}

func createNetworkSubnetGroupingGeneric(groupsIndexes []groupIndexes) (
	network SquareTreeNodeInterface, groups []SquareTreeNodeInterface, zones *[][]SquareTreeNodeInterface) {
	n := NewNetworkTreeNode()
	network = n
	zones = &[][]SquareTreeNodeInterface{}
	cloud1 := NewCloudTreeNode(n, "IBM Cloud")
	publicNetwork := NewPublicNetworkTreeNode(n)
	zoneIndexToVpcIndex := map[int]int{}
	maxVpcIndex := 0
	maxZoneIndex := 0
	maxSubnetIndex := 0
	for _, index := range groupsIndexes {
		for z := index.z1; z <= index.z2; z++ {
			zoneIndexToVpcIndex[z] = index.vpcIndex
			maxVpcIndex = max(maxVpcIndex, index.vpcIndex)
			maxZoneIndex = max(maxZoneIndex, index.z2)
			maxSubnetIndex = max(maxSubnetIndex, index.s2)
		}
	}
	vpcs := make([]*VpcTreeNode, maxVpcIndex+1)
	for i := 0; i <= maxVpcIndex; i++ {
		region := NewRegionTreeNode(cloud1, fmt.Sprintf("north%d", i))
		vpcs[i] = NewVpcTreeNode(region, fmt.Sprintf("vpc%d", i))
	}
	for i := 0; i <= maxZoneIndex; i++ {
		createZone(zones, vpcs[zoneIndexToVpcIndex[i]], maxSubnetIndex+1, fmt.Sprintf("z%d", i))
	}
	groups = make([]SquareTreeNodeInterface, len(groupsIndexes))
	for i, index := range groupsIndexes {
		groups[i] = createGroup(zones, vpcs[index.vpcIndex], index.z1, index.z2, index.s1, index.s2)
	}

	for _, gr := range groups {
		i1 := NewInternetTreeNode(publicNetwork, "I "+treeNodeName(gr))
		NewConnectivityLineTreeNode(network, gr, i1, true, "gconn "+treeNodeName(gr))
	}
	return network, groups, zones
}

func createNetworkGrouping() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	publicNetwork := NewPublicNetworkTreeNode(network)

	cloud1 := NewCloudTreeNode(network, "IBM Cloud")
	region := NewRegionTreeNode(cloud1, "north")
	vpc1 := NewVpcTreeNode(region, "vpc1")
	zone1 := NewZoneTreeNode(vpc1, "zone1")
	subnet11 := NewSubnetTreeNode(zone1, "subnet1", "cidr1", "acl1")
	groupedNis11 := []IconTreeNodeInterface{
		NewNITreeNode(subnet11, "ni1"),
		NewNITreeNode(subnet11, "ni1"),
	}
	subnet12 := NewSubnetTreeNode(zone1, "subnet2", "cidr2", "acl2")
	NewNITreeNode(subnet12, "ni1")
	subnet13 := NewSubnetTreeNode(zone1, "subnet2", "cidr2", "acl2")
	groupedNis13 := []IconTreeNodeInterface{
		NewNITreeNode(subnet13, "ni1"),
		NewNITreeNode(subnet13, "ni1"),
	}
	NewNITreeNode(subnet13, "ni1")

	zone2 := NewZoneTreeNode(vpc1, "zone1")
	subnet21 := NewSubnetTreeNode(zone2, "subnet1", "cidr1", "acl1")
	NewNITreeNode(subnet21, "ni1")
	NewNITreeNode(subnet21, "ni1")
	NewNITreeNode(subnet21, "ni1")
	subnet22 := NewSubnetTreeNode(zone2, "subnet2", "cidr2", "acl2")
	NewNITreeNode(subnet22, "ni1")
	subnet23 := NewSubnetTreeNode(zone2, "subnet2", "cidr2", "acl2")
	groupedNis23 := []IconTreeNodeInterface{
		NewNITreeNode(subnet23, "ni1"),
		NewNITreeNode(subnet23, "ni1"),
		NewNITreeNode(subnet23, "ni1"),
	}

	zone3 := NewZoneTreeNode(vpc1, "zone1")
	subnet31 := NewSubnetTreeNode(zone3, "subnet1", "cidr1", "acl1")
	groupedNis31 := []IconTreeNodeInterface{
		NewNITreeNode(subnet31, "ni1"),
		NewNITreeNode(subnet31, "ni1"),
	}
	NewNITreeNode(subnet31, "ni1")
	subnet32 := NewSubnetTreeNode(zone3, "subnet2", "cidr2", "acl2")
	groupedNis32 := []IconTreeNodeInterface{
		NewNITreeNode(subnet32, "ni1"),
		NewNITreeNode(subnet32, "ni1"),
		NewNITreeNode(subnet32, "ni1"),
		NewNITreeNode(subnet32, "ni1"),
		NewNITreeNode(subnet32, "ni1"),
	}

	subnet33 := NewSubnetTreeNode(zone3, "subnet2", "cidr2", "acl2")
	sg33 := NewSGTreeNode(vpc1, "sg33")
	ni33b := NewNITreeNode(subnet33, "ni1b")
	ni33c := NewNITreeNode(subnet33, "ni1c")
	ni33g := NewNITreeNode(subnet33, "ni1g")
	ni33h := NewNITreeNode(subnet33, "ni1h")
	ni33d := NewNITreeNode(subnet33, "ni1d")
	ni33j := NewNITreeNode(subnet33, "ni1j")
	ni33e := NewNITreeNode(subnet33, "ni1e")
	ni33a := NewNITreeNode(subnet33, "ni1a")
	ni33f := NewNITreeNode(subnet33, "ni1f")
	ni33i := NewNITreeNode(subnet33, "ni1i")
	sg33.AddIcon(ni33b)
	sg33.AddIcon(ni33c)
	sg33.AddIcon(ni33g)
	sg33.AddIcon(ni33h)
	sg33.AddIcon(ni33d)
	sg33.AddIcon(ni33j)
	sg33.AddIcon(ni33e)
	sg33.AddIcon(ni33a)
	sg33.AddIcon(ni33f)
	sg33.AddIcon(ni33i)

	groupedNis33f := []IconTreeNodeInterface{ni33h, ni33i}
	groupedNis33b := []IconTreeNodeInterface{ni33a, ni33b}
	groupedNis33a := []IconTreeNodeInterface{ni33a, ni33b, ni33c, ni33d, ni33e}
	groupedNis33d := []IconTreeNodeInterface{ni33a, ni33e, ni33f}
	groupedNis33c := []IconTreeNodeInterface{ni33c, ni33d, ni33e}
	groupedNis33e := []IconTreeNodeInterface{ni33g, ni33h, ni33i, ni33j}
	groupedNis33g := []IconTreeNodeInterface{ni33c, ni33d}

	for _, ni := range groupedNis11 {
		ni.(*NITreeNode).SetFIP("fip")
	}
	i2 := NewInternetTreeNode(publicNetwork, "Internet2")

	gs13 := NewGroupSquareTreeNode(subnet13, groupedNis13, "groupedNis13")
	gs32 := NewGroupSquareTreeNode(subnet32, groupedNis32, "groupedNis32")
	gs33a := NewGroupSquareTreeNode(subnet33, groupedNis33a, "groupedNis33a")
	gs33b := NewGroupSquareTreeNode(subnet33, groupedNis33b, "groupedNis33b")
	gs33c := NewGroupSquareTreeNode(subnet33, groupedNis33c, "groupedNis33c")
	gs33d := NewGroupSquareTreeNode(subnet33, groupedNis33d, "groupedNis33d")
	gs33e := NewGroupSquareTreeNode(subnet33, groupedNis33e, "groupedNis33e")
	gs33f := NewGroupSquareTreeNode(subnet33, groupedNis33f, "groupedNis33f")
	gs33g := NewGroupSquareTreeNode(subnet33, groupedNis33g, "groupedNis33g")
	gs23 := NewGroupSquareTreeNode(subnet23, groupedNis23, "groupedNis23")
	gs31 := NewGroupSquareTreeNode(subnet31, groupedNis31, "groupedNis31")
	gs11 := NewGroupSquareTreeNode(subnet11, groupedNis11, "groupedNis11")

	NewConnectivityLineTreeNode(network, gs13, gs32, true, "gconn1")
	NewConnectivityLineTreeNode(network, gs33a, i2, false, "gconn2")
	NewConnectivityLineTreeNode(network, gs23, gs11, true, "gconn3")
	NewConnectivityLineTreeNode(network, gs23, gs23, true, "gconn3")
	NewConnectivityLineTreeNode(network, gs32, gs33b, true, "gconn4")
	NewConnectivityLineTreeNode(network, gs31, gs33c, true, "gconn4")
	NewConnectivityLineTreeNode(network, gs31, gs33d, true, "gconn4")
	NewConnectivityLineTreeNode(network, gs33f, gs33e, true, "gconn4")
	NewConnectivityLineTreeNode(network, gs31, gs31, true, "gconn4")
	NewConnectivityLineTreeNode(network, gs33g, i2, true, "gconn4")

	return network
}

func createNetwork2() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	publicNetwork := NewPublicNetworkTreeNode(network)
	NewCloudTreeNode(network, "empty Cloud")
	cloud1 := NewCloudTreeNode(network, "IBM Cloud")
	cloud2 := NewCloudTreeNode(network, "IBM Cloud2")
	i2 := NewInternetTreeNode(publicNetwork, "Internet2")
	i4 := NewUserTreeNode(publicNetwork, "User4")
	i2.SetTooltip([]string{"this is Internet2 tool tip", "with lines"})
	i4.SetTooltip([]string{"this is User4 tool tip", "with lines"})
	region1 := NewRegionTreeNode(cloud1, "north")
	vpc1 := NewVpcTreeNode(region1, "vpc1")
	zone1 := NewZoneTreeNode(vpc1, "zone1")

	region2 := NewRegionTreeNode(cloud2, "north")
	vpc2 := NewVpcTreeNode(region2, "vpc1")
	zone2 := NewZoneTreeNode(vpc2, "zone1")
	subnet2 := NewSubnetTreeNode(zone2, "subnet2", "cidr1", "acl1")
	NewVpcTreeNode(region2, "vpc3")
	ni20 := NewNITreeNode(subnet2, "ni20")
	ni20.SetTooltip([]string{"this is ni20 tool tip", "with lines"})
	NewConnectivityLineTreeNode(network, ni20, i4, false, "conn20")

	NewGatewayTreeNode(zone1, "gw1").SetTooltip([]string{"this is gw1 tool tip", "with lines"})
	is1 := NewInternetServiceTreeNode(vpc1, "is1")
	is1.SetTooltip([]string{"this is is1 tool tip", "with lines"})

	subnet1 := NewSubnetTreeNode(zone1, "subnet1", "cidr1", "acl1")

	sg1 := NewSGTreeNode(vpc1, "sg1")
	ni1 := NewNITreeNode(subnet1, "ni1")
	ni1b := NewNITreeNode(subnet1, "ni1")
	sg1.AddIcon(ni1)
	sg1.AddIcon(ni1b)

	ni1.SetTooltip([]string{"this is ni1 tool tip one line"})
	GroupNIsWithVSI(zone1, "vsi1", []TreeNodeInterface{ni1, ni1b})

	sg2 := NewSGTreeNode(vpc1, "sg2")
	ni2 := NewNITreeNode(subnet1, "ni2")
	sg2.AddIcon(ni2)
	GroupNIsWithVSI(zone1, "vsi2", []TreeNodeInterface{ni2})
	ni2.SetFIP("fip")

	sg3 := NewSGTreeNode(vpc1, "sg3")
	ni3 := NewNITreeNode(subnet1, "ni3")
	sg3.AddIcon(ni3)
	GroupNIsWithVSI(zone1, "vsi2", []TreeNodeInterface{ni2})

	sg4 := NewSGTreeNode(vpc1, "sg4")
	ni4 := NewNITreeNode(subnet1, "ni4")
	sg4.AddIcon(ni4)
	GroupNIsWithVSI(zone1, "vsi2", []TreeNodeInterface{ni2})

	NewConnectivityLineTreeNode(network, ni1, i4, false, "conn1")
	NewConnectivityLineTreeNode(network, i4, ni1, false, "conn1_opp")
	NewConnectivityLineTreeNode(network, ni1, i2, false, "conn2")
	con := NewConnectivityLineTreeNode(network, ni2, is1, false, "conn3")
	con.SetRouter(ni2)
	NewConnectivityLineTreeNode(network, ni3, ni4, false, "conn4")
	NewConnectivityLineTreeNode(network, is1, ni4, false, "conn5")

	return network
}

func createNetworkMultiSG() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	cloud2 := NewCloudTreeNode(network, "IBM Cloud2")

	region2 := NewRegionTreeNode(cloud2, "north")
	vpc2 := NewVpcTreeNode(region2, "vpc2")
	zone1 := NewZoneTreeNode(vpc2, "zone1")
	zone2 := NewZoneTreeNode(vpc2, "zone2")
	sg1 := NewSGTreeNode(vpc2, "sg1")
	sg2 := NewSGTreeNode(vpc2, "sg2")
	sg3 := NewSGTreeNode(vpc2, "sg3")

	subnet1 := NewSubnetTreeNode(zone1, "subnet1", "ip", "key")
	subnet2 := NewSubnetTreeNode(zone2, "subnet2", "ip", "key")

	ni11 := NewNITreeNode(subnet1, "ni11")
	ni12 := NewNITreeNode(subnet1, "ni12")
	ni13 := NewNITreeNode(subnet1, "ni13")
	ni14 := NewNITreeNode(subnet1, "ni14")
	ni15 := NewNITreeNode(subnet1, "ni15")

	ni21 := NewNITreeNode(subnet2, "ni21")
	ni22 := NewNITreeNode(subnet2, "ni22")
	ni23 := NewNITreeNode(subnet2, "ni23")

	sg1.AddIcon(ni11)
	sg2.AddIcon(ni11)
	sg3.AddIcon(ni11)

	sg1.AddIcon(ni12)
	sg2.AddIcon(ni12)
	sg3.AddIcon(ni12)

	sg1.AddIcon(ni21)
	sg2.AddIcon(ni21)

	sg1.AddIcon(ni13)

	sg2.AddIcon(ni22)
	sg3.AddIcon(ni22)

	sg1.AddIcon(ni14)
	sg3.AddIcon(ni14)

	sg1.AddIcon(ni15)
	sg3.AddIcon(ni15)

	sg1.AddIcon(ni23)
	sg3.AddIcon(ni23)

	return network
}

func createNetworkTgw() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	cloud := NewCloudTreeNode(network, "IBM Cloud")
	region := NewRegionTreeNode(cloud, "north")
	nis := make([]IconTreeNodeInterface, 12)
	for i := 0; i < len(nis); i++ {
		vpc := NewVpcTreeNode(region, "vpc1")
		zone := NewZoneTreeNode(vpc, "zone1")
		subnet := NewSubnetTreeNode(zone, "subnet2", "cidr1", "acl1")
		nis[i] = NewNITreeNode(subnet, "ni20")
	}
	for nCon := 2; nCon <= 4; nCon++ {
		tgw1 := NewTransitGatewayTreeNode(region, "tgw1")
		tgw2 := NewTransitGatewayTreeNode(region, "tgw2")
		for j := nCon; j < nCon*2; j++ {
			NewConnectivityLineTreeNode(network, nis[nCon-j/2], nis[nCon+j], true, "").SetRouter(tgw1)
			NewConnectivityLineTreeNode(network, nis[nCon-j/2], nis[nCon+j/2], true, "").SetRouter(tgw2)
		}
	}
	tgw1 := NewTransitGatewayTreeNode(region, "tgw1")
	tgw2 := NewTransitGatewayTreeNode(region, "tgw2")
	tgw3 := NewTransitGatewayTreeNode(region, "tgw3")
	tgw4 := NewTransitGatewayTreeNode(region, "tgw3")
	NewConnectivityLineTreeNode(network, nis[9], nis[10], true, "").SetRouter(tgw1)
	NewConnectivityLineTreeNode(network, nis[9], nis[10], true, "").SetRouter(tgw2)
	NewConnectivityLineTreeNode(network, nis[9], nis[10], true, "").SetRouter(tgw3)
	NewConnectivityLineTreeNode(network, nis[9], nis[10], true, "").SetRouter(tgw4)

	return network
}

func createNetworkAws() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	cloud := NewCloudTreeNode(network, "AWS Cloud")
	region := NewRegionTreeNode(cloud, "north")
	tgw1 := NewTransitGatewayTreeNode(region, "tgw1")
	nis := make([]IconTreeNodeInterface, 6)
	vpc := NewVpcTreeNode(region, "vpc1")
	sg := NewSGTreeNode(vpc, "sg12")
	for i := 0; i < len(nis); i++ {
		zone := NewZoneTreeNode(vpc, "zone1")
		subnet := NewSubnetTreeNode(zone, "subnet2", "cidr1", "acl1")
		subnet.SetIsPrivate(i > 1)
		nis[i] = NewNITreeNode(subnet, "ni20")
		sg.AddIcon(nis[i])
	}
	publicNetwork := NewPublicNetworkTreeNode(network)
	i2 := NewInternetTreeNode(publicNetwork, "Internet2")
	vpc2 := NewVpcTreeNode(region, "vpc2")
	zone := NewZoneTreeNode(vpc2, "zone1")
	subnet := NewSubnetTreeNode(zone, "subnet2", "cidr1", "acl1")
	ni := NewNITreeNode(subnet, "ni20")

	igw1 := NewInternetGatewayTreeNode(vpc, "igw1")
	NewConnectivityLineTreeNode(network, nis[0], i2, true, "").SetRouter(igw1)
	NewConnectivityLineTreeNode(network, nis[1], i2, true, "").SetRouter(igw1)
	NewConnectivityLineTreeNode(network, nis[5], ni, true, "").SetRouter(tgw1)

	lb := newLoadBalancerTreeNode(vpc, "lb", nil)
	NewConnectivityLineTreeNode(network, nis[2], lb, true, "")
	NewConnectivityLineTreeNode(network, nis[3], lb, true, "")
	NewConnectivityLineTreeNode(network, lb, nis[4], false, "")
	return network
}

func createEmptySquaresNetwork() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	cloud := NewCloudTreeNode(network, "Cloud")
	NewPublicNetworkTreeNode(network)
	NewCloudTreeNode(network, "empty cloud")
	region := NewRegionTreeNode(cloud, "north")
	NewRegionTreeNode(cloud, "empty south")
	vpc11 := NewVpcTreeNode(region, "vpc11")
	NewVpcTreeNode(region, "empty vpc12")
	NewZoneTreeNode(vpc11, "empty zone112")
	z111 := NewZoneTreeNode(vpc11, "zone111")
	NewZoneTreeNode(vpc11, "empty zone113")
	z112 := NewZoneTreeNode(vpc11, "zone112")
	NewSubnetTreeNode(z111, "sub1111", "cidr", "acl1111")
	s1112 := NewSubnetTreeNode(z111, "sub1112", "cidr", "acl1112")
	NewSubnetTreeNode(z112, "sub1121", "cidr", "acl1121")
	s1122 := NewSubnetTreeNode(z112, "sub1122", "cidr", "acl1122")
	GroupedSubnetsSquare(vpc11, []SquareTreeNodeInterface{s1112, s1122})

	region2 := NewRegionTreeNode(cloud, "east")
	vpc21 := NewVpcTreeNode(region2, "vpc21")
	NewVpcTreeNode(region, "empty vpc12")
	NewZoneTreeNode(vpc21, "empty zone112")
	z211 := NewZoneTreeNode(vpc21, "zone211")
	NewZoneTreeNode(vpc21, "empty zone113")
	NewSubnetTreeNode(z211, "sub2121", "cidr", "acl2121")
	NewSubnetTreeNode(z211, "sub2122", "cidr", "acl2122")
	NewSubnetTreeNode(z211, "sub2123", "cidr", "acl2123")

	return network
}
