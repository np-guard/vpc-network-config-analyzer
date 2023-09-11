package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type DrawioGenerator struct {
	network       *drawio.NetworkTreeNode
	publicNetwork *drawio.PublicNetworkTreeNode
	cloud         *drawio.CloudTreeNode
	TNs           map[vpcmodel.DrawioResourceIntf]drawio.TreeNodeInterface
}

func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode             { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode { return gen.publicNetwork }
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode                 { return gen.cloud }

func (gen *DrawioGenerator) Init() {
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.cloud = drawio.NewCloudTreeNode(gen.network, "IBM Cloud")
	gen.TNs = map[vpcmodel.DrawioResourceIntf]drawio.TreeNodeInterface{}

	//to remove:
	for k := range addressToNi {
		delete(addressToNi, k)
	}
	for k := range cidrToSubnet {
		delete(cidrToSubnet, k)
	}
	for k := range zoneNameToZones {
		delete(zoneNameToZones, k)
	}

}

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// to remove:
var oneVpc *VPC = nil

func (gen *DrawioGenerator) SetOneVpc(config *vpcmodel.CloudConfig) {
	for _, ns := range config.NodeSets {
		if ns.Kind() == "VPC" {
			oneVpc = ns.(*VPC)
		}
	}
}

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

// DrawioTreeNode() implementations:
// 1. do we want to have them here? (there are more implementations at vpcmodel, they cant be here)
// 2. most implementations does not use the gen parameter, maybe we can omit it
///////////////////////////////////////////////////////////////////////////////////////////////////////

func (gen *DrawioGenerator) TN(res vpcmodel.DrawioResourceIntf) drawio.TreeNodeInterface {
	if gen.TNs[res] == nil {
		gen.TNs[res] = res.DrawioTreeNode(gen)
	}
	return gen.TNs[res]
}

func (vpc *VPC) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	return drawio.NewVpcTreeNode(gen.Cloud(), vpc.Name())
}

func (z *Zone) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	return drawio.NewZoneTreeNode(gen.TN(z.Vpc()).(*drawio.VpcTreeNode), z.name)
}

func (s *Subnet) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	// to remove:
	cidrToSubnet[s.cidr] = s

	zoneTn := gen.TN(s.ZoneS()).(*drawio.ZoneTreeNode)
	return drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.cidr, "")
}

func (sgl *SecurityGroupLayer) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	tn := drawio.NewSGTreeNode(gen.TN(sgl.Vpc()).(*drawio.VpcTreeNode), sgl.Name())
	for _, sg := range sgl.sgList {
		// the following loop:
		for niAddress := range sg.members {
			// a:= sg.getNi(niAddress)
			// b:= gen.TN(a)
			// c:= b.(*drawio.NITreeNode)

			gen.TN(sg.getNi(niAddress)).(*drawio.NITreeNode).SetSG(tn)
		}
		// should be replace with:
		// for _, ni := range sg.members {
		// 	gen.TN(ni).(*drawio.NITreeNode).SetSG(sgl.DrawioTN.(*drawio.SGTreeNode))
		// }
	}
	return tn
}

func (acll *NaclLayer) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	for _, acl := range acll.naclList {
		// the following loop:
		for cidr := range acl.subnets {
			gen.TN(acl.getSubnet(cidr)).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
		// should be replace with:
		// for _, sn := range acl.subnets {
		// 	gen.TN(sn).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		// }
	}
	return nil
}

func (ni *NetworkInterface) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
		//to remove:
		addressToNi[ni.address] = ni

	return drawio.NewNITreeNode(
			gen.TN(ni.subnet).(drawio.SquareTreeNodeInterface),
			nil, ni.Name())
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
		vsiNIs = append(vsiNIs, gen.TN(ni))
	}
	zoneTn := gen.TN(vsi.ZoneS()).(*drawio.ZoneTreeNode)
	drawio.GroupNIsWithVSI(zoneTn, vsi.Name(), vsiNIs)
	return nil
}

func (pgw *PublicGateway) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	zoneTn := gen.TN(pgw.ZoneS()).(*drawio.ZoneTreeNode)
	return drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
}

func (fip *FloatingIP) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	nitn := gen.TN(fip.Src()[0]).(*drawio.NITreeNode)
	nitn.SetFIP(fip.Name())
	return nitn
}
