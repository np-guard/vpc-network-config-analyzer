package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

var allTreeNodes = map[vpcmodel.VPCResourceIntf]drawio.TreeNodeInterface{}
var ibmCloudTn *drawio.CloudTreeNode = nil
var vpcTn *drawio.VpcTreeNode = nil
var zoneNameToZonesTreeNodes = map[string]*drawio.ZoneTreeNode{}
var nisToGs = map[vpcmodel.VPCResourceIntf]*drawio.SGTreeNode{}
var nisToPG = map[drawio.TreeNodeInterface]drawio.TreeNodeInterface{}

func theOneVpc(network drawio.TreeNodeInterface, vpcName string) *drawio.VpcTreeNode {
	if ibmCloudTn == nil {
		ibmCloudTn = drawio.NewCloudTreeNode(network.(*drawio.NetworkTreeNode), "IBM Cloud")

	}
	if vpcTn == nil {
		vpcTn = drawio.NewVpcTreeNode(ibmCloudTn, vpcName)
	}
	return vpcTn
}

func (vpc *VPC) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	return theOneVpc(network, vpc.Name())
}

func zoneDrawioTreeNode(network drawio.TreeNodeInterface, zoneName string) *drawio.ZoneTreeNode {
	if _, ok := zoneNameToZonesTreeNodes[zoneName]; !ok {
		zoneNameToZonesTreeNodes[zoneName] = drawio.NewZoneTreeNode(theOneVpc(network, "VPC todo"), zoneName)
	}
	return zoneNameToZonesTreeNodes[zoneName]
}

func (s *Subnet) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[s]; !ok {
		zone := zoneDrawioTreeNode(network, s.ZoneName())
		acl := "acl todo"
		allTreeNodes[s] = drawio.NewSubnetTreeNode(zone, s.Name(), s.cidr, acl)
	}
	return allTreeNodes[s]
}

func (sgl *SecurityGroupLayer) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[sgl]; !ok {
		allTreeNodes[sgl] = drawio.NewSGTreeNode(theOneVpc(network, "VPC todo2"), sgl.Name())
		//todo:
		// for _, sg := range sgl.sgList {
		// 	for _, ni := range sg.members {
		// 		nisToGs[ni] = allTreeNodes[sgl]
		// 	}
		// }
	}
	return allTreeNodes[sgl]
}
func (acl *NaclLayer) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	//todo:
	// for _, acll := range acl.naclList{
	// 	for _, s := range acll.subnets{
	// subnet := s
	// allTreeNodes[subnet].(*drawio.SubnetTreeNode).SetACL(acl.Name())
	// 	}
	// }
	return nil
}

func (ni *NetworkInterface) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[ni]; !ok {
		allTreeNodes[ni] = drawio.NewNITreeNode(
			ni.subnet.DrawioTreeNode(network).(drawio.SquareTreeNodeInterface),
			nisToGs[ni], ni.Name())
	}
	return allTreeNodes[ni]
}
func (iksn *IKSNode) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	return nil
}

func (vsi *Vsi) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if len(vsi.Nodes()) == 0 {
		return nil
	}
	vsiNIs := []drawio.TreeNodeInterface{}
	for _, ni := range vsi.Nodes() {
		vsiNIs = append(vsiNIs, ni.DrawioTreeNode(network))
	}
	drawio.GroupNIsWithVSI(zoneDrawioTreeNode(network, vsi.ZoneName()), vsi.Name(), vsiNIs)
	return nil
}

func (pgw *PublicGateway) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[pgw]; !ok {
		allTreeNodes[pgw] = drawio.NewGatewayTreeNode(zoneDrawioTreeNode(network, pgw.ZoneName()), pgw.Name())
	}
	return allTreeNodes[pgw]
}
func (fip *FloatingIP) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	nitn := fip.Src()[0].DrawioTreeNode(network).(*drawio.NITreeNode)
	nitn.SetFIP(fip.Name())
	return nitn
}
