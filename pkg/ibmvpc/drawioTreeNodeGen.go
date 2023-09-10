package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type DrawioGenerator struct {
	network       *drawio.NetworkTreeNode
	publicNetwork *drawio.PublicNetworkTreeNode
	cloud         *drawio.CloudTreeNode
}

func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode            { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode { return gen.publicNetwork }
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode                 { return gen.cloud }

func (gen *DrawioGenerator) Init() {
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.cloud = drawio.NewCloudTreeNode(gen.network, "IBM Cloud")
}


///////////////////////////////////////////////////////////////////////////////////////////////////////
//to remove:
var oneVpc *VPC = nil
func (gen *DrawioGenerator) SetOneVpc(config *vpcmodel.CloudConfig){
	for _, ns := range config.NodeSets {
		if ns.Kind() == "VPC"{
			oneVpc = ns.(*VPC)
		}
	}
}
// to rewrite:
func (sgl *SecurityGroupLayer) Vpc() *VPC { return oneVpc }


////////////////////////////////////////////////////////////////////////////
type Zone struct {
	name string
	DrawioTN 	drawio.TreeNodeInterface
}


func (r *Subnet) ZoneS() *Zone { return resourceZone(r) }
func (r *PublicGateway) ZoneS() *Zone { return resourceZone(r) }
func (r *Vsi) ZoneS() *Zone { return resourceZone(r) }


var zoneNameToZones = map[string]*Zone{}
func resourceZone(res vpcmodel.VPCResourceIntf) *Zone {
	zoneName := res.ZoneName()
	if _, ok := zoneNameToZones[zoneName]; !ok {
		zoneNameToZones[zoneName] = &Zone{name :zoneName}
	}
	return zoneNameToZones[zoneName]
}

// to rewrite:
func (z *Zone) Vpc() *VPC { return oneVpc }
///////////////////////////////////////////////////////////////////////////////////////


//to remove:
var addressToNi = map[string]vpcmodel.VPCResourceIntf{}
var cidrToSubnet = map[string]vpcmodel.VPCResourceIntf{}
func (sg *SecurityGroup) getNi(address string) vpcmodel.VPCResourceIntf { return addressToNi[address] }
func (acl *NACL) getSubnet(cidr string) vpcmodel.VPCResourceIntf        { return cidrToSubnet[cidr] }





func (vpc *VPC) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if vpc.DrawioTN == nil {
		vpc.DrawioTN = drawio.NewVpcTreeNode(gen.Cloud(), vpc.Name())
	}
	return vpc.DrawioTN
}

func (z *Zone) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if z.DrawioTN == nil {
		z.DrawioTN = drawio.NewZoneTreeNode(z.Vpc().DrawioTreeNode(gen).(*drawio.VpcTreeNode), z.name)
	}
	return z.DrawioTN
}

func (s *Subnet) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if s.DrawioTN == nil {
		zoneTn := s.ZoneS().DrawioTreeNode(gen).(*drawio.ZoneTreeNode)
		s.DrawioTN = drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.cidr, "")
		// to remove:
		cidrToSubnet[s.cidr] = s
	}
	return s.DrawioTN
}

func (sgl *SecurityGroupLayer) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if sgl.DrawioTN == nil {
		sgl.DrawioTN = drawio.NewSGTreeNode(sgl.Vpc().DrawioTreeNode(gen).(*drawio.VpcTreeNode), sgl.Name())
		for _, sg := range sgl.sgList {
		// the following loop:
		for niAddress := range sg.members {
			sg.getNi(niAddress).DrawioTreeNode(gen).(*drawio.NITreeNode).SetSG(sgl.DrawioTN.(*drawio.SGTreeNode))
		}
		// should be replace with:
		// for _, ni := range sg.members {
		// 	ni.DrawioTreeNode(gen).(*drawio.NITreeNode).SetSG(sgl.DrawioTN.(*drawio.SGTreeNode))
		// }
}
	}
	return sgl.DrawioTN
}

func (acll *NaclLayer) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	for _, acl := range acll.naclList {
		// the following loop:
		for cidr := range acl.subnets {
			acl.getSubnet(cidr).DrawioTreeNode(gen).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
		// should be replace with:
		// for _, sn := range acl.subnets {
		// 	sn.DrawioTreeNode(gen).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		// }
	}
	return nil
}

func (ni *NetworkInterface) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if ni.DrawioTN == nil {
		ni.DrawioTN = drawio.NewNITreeNode(
			ni.subnet.DrawioTreeNode(gen).(drawio.SquareTreeNodeInterface),
			nil, ni.Name())
		//to remove:
		addressToNi[ni.address] = ni
	}
	return ni.DrawioTN
}
func (iksn *IKSNode) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	return nil
}

func (vsi *Vsi) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if len(vsi.Nodes()) == 0 {
		return nil
	}
	vsiNIs := []drawio.TreeNodeInterface{}
	for _, ni := range vsi.Nodes() {
		vsiNIs = append(vsiNIs, ni.DrawioTreeNode(gen))
	}
	zoneTn := vsi.ZoneS().DrawioTreeNode(gen).(*drawio.ZoneTreeNode)

	drawio.GroupNIsWithVSI(zoneTn, vsi.Name(), vsiNIs)
	return nil
}

func (pgw *PublicGateway) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if pgw.DrawioTN == nil {
		zoneTn := pgw.ZoneS().DrawioTreeNode(gen).(*drawio.ZoneTreeNode)
		pgw.DrawioTN = drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
	}
	return pgw.DrawioTN
}

func (fip *FloatingIP) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	nitn := fip.Src()[0].DrawioTreeNode(gen).(*drawio.NITreeNode)
	nitn.SetFIP(fip.Name())
	return nitn
}
