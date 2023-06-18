package drawio

import (
	_ "embed"
	"testing"
)

func TestWithParsing(t *testing.T) {
	n := createNetwork()
	CreateDrawioConnectivityMapFile(n, "fake.drawio")
	n2 := createNetwork2()
	CreateDrawioConnectivityMapFile(n2, "fake2.drawio")
}

func createNetwork() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	i1 := NewInternetTreeNode(network, "i1")
	i2 := NewInternetTreeNode(network, "i2")
	i3 := NewInternetTreeNode(network, "i3")
	i4 := NewUserTreeNode(network, "i4")

	vpc1 := NewVpcTreeNode(network, "vpc1")
	zone11 := NewZoneTreeNode(vpc1, "zone1")

	gw11 := NewGetWayTreeNode(zone11, "gw11")
	is1a := NewInternetServiceTreeNode(vpc1, "is1a")
	is1b := NewInternetServiceTreeNode(vpc1, "is1b")
	is1c := NewInternetServiceTreeNode(vpc1, "is1c")
	is1d := NewInternetServiceTreeNode(vpc1, "is1d")
	is1e := NewInternetServiceTreeNode(vpc1, "is1e")

	sg11 := NewSGTreeNode(vpc1, "sg11")
	sg12 := NewSGTreeNode(vpc1, "sg12")

	subnet111 := NewSubnetTreeNode(zone11, "subnet111", "ip", "key")

	ni1 := NewNITreeNode(subnet111, sg11, "ni1")
	ni2 := NewNITreeNode(subnet111, sg12, "ni2")

	NewVsiTreeNode(zone11, "vsi1", []TreeNodeInterface{ni1, ni2})

	zone12 := NewZoneTreeNode(vpc1, "zone12")
	gw12 := NewGetWayTreeNode(zone12, "gw12")
	subnet112 := NewSubnetTreeNode(zone11, "subnet112", "ip", "key")
	subnet121 := NewSubnetTreeNode(zone12, "subnet121", "ip", "key")
	ni4 := NewNITreeNode(subnet112, sg12, "ni4")
	ni4.SetVsi("svi1")
	ni5 := NewNITreeNode(subnet121, sg11, "ni5")
	ni5.SetVsi("svi2")
	ni5.SetFIP("fip")
	ni5b := NewNITreeNode(subnet121, sg11, "ni5b")
	ni5b.SetVsi("svi3")
	ni5b.SetFIP("fip2")

	vpc2 := NewVpcTreeNode(network, "vpc2")
	zone21 := NewZoneTreeNode(vpc2, "zone21")
	sg21 := NewSGTreeNode(vpc2, "sg21")

	subnet211 := NewSubnetTreeNode(zone21, "subnet211", "ip", "key")

	ni6 := NewNITreeNode(subnet211, sg21, "ni6")
	ni7 := NewNITreeNode(subnet211, sg21, "ni7")
	ni8 := NewNITreeNode(subnet211, sg21, "ni8")
	NewVsiTreeNode(zone21, "vsi2", []TreeNodeInterface{ni6, ni7, ni8})

	zone22 := NewZoneTreeNode(vpc2, "zone22")
	zone23 := NewZoneTreeNode(vpc2, "zone23")
	subnet221 := NewSubnetTreeNode(zone22, "subnet221", "ip", "key")
	subnet222 := NewSubnetTreeNode(zone22, "subnet222", "ip", "key")
	subnet231 := NewSubnetTreeNode(zone23, "subnet231", "ip", "key")
	sg22 := NewSGTreeNode(vpc2, "sg22")

	ni10 := NewNITreeNode(subnet221, sg22, "ni10")
	ni11 := NewNITreeNode(subnet222, sg22, "ni11")
	ni12 := NewNITreeNode(subnet222, sg22, "ni12")
	ni13 := NewNITreeNode(subnet222, sg22, "ni13")
	ni14 := NewNITreeNode(subnet222, sg22, "ni14")

	NewVsiTreeNode(zone22, "vsi3", []TreeNodeInterface{ni10, ni13, ni14})

	NewVsiTreeNode(zone22, "vsi4", []TreeNodeInterface{ni11, ni12})

	ni20 := NewNITreeNode(subnet231, sg22, "ni20")
	ni21 := NewNITreeNode(subnet231, nil, "ni21")
	ni22 := NewNITreeNode(subnet231, sg22, "ni22")
	ni23 := NewNITreeNode(subnet231, sg22, "ni23")
	ni24 := NewNITreeNode(subnet231, nil, "ni24")
	ni25 := NewNITreeNode(subnet231, sg22, "ni25")
	ni26 := NewNITreeNode(subnet231, nil, "ni26")
	ni27 := NewNITreeNode(subnet231, nil, "ni27")
	ni28 := NewNITreeNode(subnet231, sg22, "ni28")
	ni29 := NewNITreeNode(subnet231, sg22, "ni29")

	gw21 := NewGetWayTreeNode(zone21, "gw21")
	gw22 := NewGetWayTreeNode(zone22, "gw22")

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

	c1.SetRouter(gw11, false)
	c2a.SetRouter(ni5, false)
	c2b.SetRouter(ni5, false)
	c2c.SetRouter(ni5, true)
	c3.SetRouter(gw21, false)
	c4.SetRouter(gw22, false)
	c5.SetRouter(gw22, false)
	c6.SetRouter(gw12, false)
	c7.SetRouter(ni5b, false)

	NewConnectivityLineTreeNode(network, ni10, is2, true, "c10")
	NewConnectivityLineTreeNode(network, ni1, is1a, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1b, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1c, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1d, true, "c11")
	NewConnectivityLineTreeNode(network, ni1, is1e, true, "c11")

	NewConnectivityLineTreeNode(network, ni8, ni14, true, "c12")

	NewConnectivityLineTreeNode(network, ni20, ni22, true, "c13")
	NewConnectivityLineTreeNode(network, ni21, ni24, true, "c14")
	NewConnectivityLineTreeNode(network, ni23, ni27, true, "c15")
	NewConnectivityLineTreeNode(network, ni25, ni29, true, "c16")
	NewConnectivityLineTreeNode(network, ni26, ni27, true, "c17")
	NewConnectivityLineTreeNode(network, ni28, ni26, true, "c18")
	NewConnectivityLineTreeNode(network, ni22, ni28, true, "c19")

	return network
}

func createNetwork2() SquareTreeNodeInterface {
	network := NewNetworkTreeNode()
	i2 := NewInternetTreeNode(network, "Internet2")
	i4 := NewUserTreeNode(network, "User4")
	vpc1 := NewVpcTreeNode(network, "vpc1")
	zone1 := NewZoneTreeNode(vpc1, "zone1")

	NewGetWayTreeNode(zone1, "gw1")
	is1 := NewInternetServiceTreeNode(vpc1, "is1")

	subnet1 := NewSubnetTreeNode(zone1, "subnet1", "cidr1", "acl1")

	sg1 := NewSGTreeNode(vpc1, "sg1")
	ni1 := NewNITreeNode(subnet1, sg1, "ni1")
	ni1b := NewNITreeNode(subnet1, sg1, "ni1")
	NewVsiTreeNode(zone1, "vsi1", []TreeNodeInterface{ni1, ni1b})

	sg2 := NewSGTreeNode(vpc1, "sg2")
	ni2 := NewNITreeNode(subnet1, sg2, "ni2")
	NewVsiTreeNode(zone1, "vsi2", []TreeNodeInterface{ni2})
	ni2.SetFIP("fip")

	sg3 := NewSGTreeNode(vpc1, "sg3")
	ni3 := NewNITreeNode(subnet1, sg3, "ni3")
	NewVsiTreeNode(zone1, "vsi2", []TreeNodeInterface{ni2})

	sg4 := NewSGTreeNode(vpc1, "sg4")
	ni4 := NewNITreeNode(subnet1, sg4, "ni4")
	NewVsiTreeNode(zone1, "vsi2", []TreeNodeInterface{ni2})

	NewConnectivityLineTreeNode(network, ni1, i4, false, "conn1")
	NewConnectivityLineTreeNode(network, ni1, i2, false, "conn2")
	con := NewConnectivityLineTreeNode(network, ni2, is1, false, "conn3")
	con.SetRouter(ni2, false)
	NewConnectivityLineTreeNode(network, ni3, ni4, false, "conn4")
	NewConnectivityLineTreeNode(network, is1, ni4, false, "conn5")

	return network
}
