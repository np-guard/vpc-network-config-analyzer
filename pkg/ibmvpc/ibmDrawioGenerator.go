package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// to remove:
func SetGlobals(config *vpcmodel.CloudConfig) {

	for k := range addressToNi {
		delete(addressToNi, k)
	}
	for k := range cidrToSubnet {
		delete(cidrToSubnet, k)
	}
	for k := range zoneNameToZones {
		delete(zoneNameToZones, k)
	}
	for _, ns := range config.NodeSets {
		if ns.Kind() == "VPC" {
			oneVpc = ns.(*VPC)
		}
	}

}

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// to remove:
var oneVpc *VPC = nil

// to rewrite:
func (sgl *SecurityGroupLayer) Vpc() *VPC { return oneVpc }

// //////////////////////////////////////////////////////////////////////////
type Zone struct {
	name string
}

// to rewrite:
func (r *Subnet) ZoneS() *Zone        { return resourceZone(r) }
func (r *PublicGateway) ZoneS() *Zone { return resourceZone(r) }
func (r *Vsi) ZoneS() *Zone           { return resourceZone(r) }

// to remove
var zoneNameToZones = map[string]*Zone{}

func resourceZone(res vpcmodel.VPCResourceIntf) *Zone {
	zoneName := res.ZoneName()
	if _, ok := zoneNameToZones[zoneName]; !ok {
		zoneNameToZones[zoneName] = &Zone{name: zoneName}
	}
	return zoneNameToZones[zoneName]
}

// to rewrite:
func (z *Zone) Vpc() *VPC { return oneVpc }

///////////////////////////////////////////////////////////////////////////////////////

// to remove:
var addressToNi = map[string]vpcmodel.VPCResourceIntf{}
var cidrToSubnet = map[string]vpcmodel.VPCResourceIntf{}

func (sg *SecurityGroup) getNi(address string) vpcmodel.VPCResourceIntf { return addressToNi[address] }
func (acl *NACL) getSubnet(cidr string) vpcmodel.VPCResourceIntf        { return cidrToSubnet[cidr] }

// GenerateDrawioTreeNode() implementations:
func (vpc *VPC) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	return drawio.NewVpcTreeNode(gen.Cloud(), vpc.Name())
}

func (z *Zone) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	return drawio.NewZoneTreeNode(gen.TreeNode(z.Vpc()).(*drawio.VpcTreeNode), z.name)
}

func (s *Subnet) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	// to remove:
	cidrToSubnet[s.cidr] = s

	zoneTn := gen.TreeNode(s.ZoneS()).(*drawio.ZoneTreeNode)
	return drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.cidr, "")
}

func (sgl *SecurityGroupLayer) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	tn := drawio.NewSGTreeNode(gen.TreeNode(sgl.Vpc()).(*drawio.VpcTreeNode), sgl.Name())
	for _, sg := range sgl.sgList {
		// the following loop:
		for niAddress := range sg.members {
			gen.TreeNode(sg.getNi(niAddress)).(*drawio.NITreeNode).SetSG(tn)
		}
		// should be replace with:
		// for _, ni := range sg.members {
		// 	gen.TN(ni).(*drawio.NITreeNode).SetSG(sgl.DrawioTN.(*drawio.SGTreeNode))
		// }
	}
	return tn
}

func (acll *NaclLayer) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	for _, acl := range acll.naclList {
		// the following loop:
		for cidr := range acl.subnets {
			gen.TreeNode(acl.getSubnet(cidr)).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
		// should be replace with:
		// for _, sn := range acl.subnets {
		// 	gen.TN(sn).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		// }
	}
	return nil
}

func (ni *NetworkInterface) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	//to remove:
	addressToNi[ni.address] = ni

	return drawio.NewNITreeNode(
		gen.TreeNode(ni.subnet).(drawio.SquareTreeNodeInterface),
		nil, ni.Name())
}
func (iksn *IKSNode) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	return nil
}

func (vsi *Vsi) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if len(vsi.Nodes()) == 0 {
		return nil
	}
	vsiNIs := []drawio.TreeNodeInterface{}
	for _, ni := range vsi.Nodes() {
		vsiNIs = append(vsiNIs, gen.TreeNode(ni))
	}
	zoneTn := gen.TreeNode(vsi.ZoneS()).(*drawio.ZoneTreeNode)
	drawio.GroupNIsWithVSI(zoneTn, vsi.Name(), vsiNIs)
	return nil
}

func (pgw *PublicGateway) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	zoneTn := gen.TreeNode(pgw.ZoneS()).(*drawio.ZoneTreeNode)
	return drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
}

func (fip *FloatingIP) GenerateDrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	nitn := gen.TreeNode(fip.Src()[0]).(*drawio.NITreeNode)
	nitn.SetFIP(fip.Name())
	return nitn
}
