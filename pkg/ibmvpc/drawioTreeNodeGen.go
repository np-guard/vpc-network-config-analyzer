package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type DrawioGenerator struct {
}

func (gen *DrawioGenerator) Init() {

}

var allTreeNodes = map[vpcmodel.VPCResourceIntf]drawio.TreeNodeInterface{}

var addressToNi = map[string]vpcmodel.VPCResourceIntf{}
var cidrToSubnet = map[string]vpcmodel.VPCResourceIntf{}

func (sg *SecurityGroup) getNi(address string) vpcmodel.VPCResourceIntf { return addressToNi[address] }
func (acl *NACL) getSubnet(cidr string) vpcmodel.VPCResourceIntf        { return cidrToSubnet[cidr] }

var ibmCloudTn *drawio.CloudTreeNode = nil
var vpcTn *drawio.VpcTreeNode = nil

func getVpc(network drawio.TreeNodeInterface, vpcName string) *drawio.VpcTreeNode {
	if ibmCloudTn == nil {
		ibmCloudTn = drawio.NewCloudTreeNode(network.(*drawio.NetworkTreeNode), "IBM Cloud")
	}
	if vpcTn == nil {
		vpcTn = drawio.NewVpcTreeNode(ibmCloudTn, vpcName)
	}
	if vpcName != "" {
		vpcTn.SetName(vpcName)
	}
	return vpcTn
}

func (vpc *VPC) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	return getVpc(network, vpc.Name())
}

var zoneNameToZonesTreeNodes = map[string]*drawio.ZoneTreeNode{}

func zoneDrawioTreeNode(network drawio.TreeNodeInterface, zoneName string) *drawio.ZoneTreeNode {
	if _, ok := zoneNameToZonesTreeNodes[zoneName]; !ok {
		zoneNameToZonesTreeNodes[zoneName] = drawio.NewZoneTreeNode(getVpc(network, ""), zoneName)
	}
	return zoneNameToZonesTreeNodes[zoneName]
}

func (s *Subnet) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[s]; !ok {
		zone := zoneDrawioTreeNode(network, s.ZoneName())
		allTreeNodes[s] = drawio.NewSubnetTreeNode(zone, s.Name(), s.cidr, "")
		// todo
		cidrToSubnet[s.cidr] = s
	}
	return allTreeNodes[s]
}

func (sgl *SecurityGroupLayer) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[sgl]; !ok {
		allTreeNodes[sgl] = drawio.NewSGTreeNode(getVpc(network, ""), sgl.Name())
		for _, sg := range sgl.sgList {
			for niAddress := range sg.members {
				// todo:
				sg.getNi(niAddress).DrawioTreeNode(network).(*drawio.NITreeNode).SetSG(allTreeNodes[sgl].(*drawio.SGTreeNode))
			}
		}
	}
	return allTreeNodes[sgl]
}
func (acll *NaclLayer) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	for _, acl := range acll.naclList {
		for cidr := range acl.subnets {
			// todo
			acl.getSubnet(cidr).DrawioTreeNode(network).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
	}
	return nil
}

func (ni *NetworkInterface) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[ni]; !ok {
		allTreeNodes[ni] = drawio.NewNITreeNode(
			ni.subnet.DrawioTreeNode(network).(drawio.SquareTreeNodeInterface),
			nil, ni.Name())
		//todo:
		addressToNi[ni.address] = ni
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
