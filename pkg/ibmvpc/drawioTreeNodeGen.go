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
var oneVpc *VPC = nil
func (gen *DrawioGenerator) SetOneVpc(config *vpcmodel.CloudConfig){
	for _, ns := range config.NodeSets {
		if ns.Kind() == "VPC"{
			oneVpc = ns.(*VPC)
		}
	}

}

func (sgl *SecurityGroupLayer) Vpc() *VPC { return oneVpc }


////////////////////////////////////////////////////////////////////////////
type Zone struct {
	name string
}


var zoneNameToZones = map[string]*Zone{}

func resourceZone(res vpcmodel.VPCResourceIntf) *Zone {
	zoneName := res.ZoneName()
	if _, ok := zoneNameToZones[zoneName]; !ok {
		zoneNameToZones[zoneName] = &Zone{zoneName}
	}
	return zoneNameToZones[zoneName]
}

func (z *Zone) Vpc() *VPC { return oneVpc }
///////////////////////////////////////////////////////////////////////////////////////


func (z *Zone) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[z]; !ok {
		allTreeNodes[z] = drawio.NewZoneTreeNode(z.Vpc().DrawioTreeNode(gen).(*drawio.VpcTreeNode), z.name)
	}
	return allTreeNodes[z]
}

var allTreeNodes = map[vpcmodel.DrawioResourceIntf]drawio.TreeNodeInterface{}

var addressToNi = map[string]vpcmodel.VPCResourceIntf{}
var cidrToSubnet = map[string]vpcmodel.VPCResourceIntf{}

func (sg *SecurityGroup) getNi(address string) vpcmodel.VPCResourceIntf { return addressToNi[address] }
func (acl *NACL) getSubnet(cidr string) vpcmodel.VPCResourceIntf        { return cidrToSubnet[cidr] }

func (vpc *VPC) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[vpc]; !ok {
		allTreeNodes[vpc] = drawio.NewVpcTreeNode(gen.Cloud(), vpc.Name())
		// todo
	}
	return allTreeNodes[vpc]
}

func (s *Subnet) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[s]; !ok {
		zoneTn := resourceZone(s).DrawioTreeNode(gen).(*drawio.ZoneTreeNode)
		allTreeNodes[s] = drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.cidr, "")
		// todo
		cidrToSubnet[s.cidr] = s
	}
	return allTreeNodes[s]
}


func (sgl *SecurityGroupLayer) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[sgl]; !ok {
		allTreeNodes[sgl] = drawio.NewSGTreeNode(sgl.Vpc().DrawioTreeNode(gen).(*drawio.VpcTreeNode), sgl.Name())
		for _, sg := range sgl.sgList {
			for niAddress := range sg.members {
				// todo:
				sg.getNi(niAddress).DrawioTreeNode(gen).(*drawio.NITreeNode).SetSG(allTreeNodes[sgl].(*drawio.SGTreeNode))
			}
		}
	}
	return allTreeNodes[sgl]
}
func (acll *NaclLayer) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	for _, acl := range acll.naclList {
		for cidr := range acl.subnets {
			// todo
			acl.getSubnet(cidr).DrawioTreeNode(gen).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
	}
	return nil
}

func (ni *NetworkInterface) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[ni]; !ok {
		allTreeNodes[ni] = drawio.NewNITreeNode(
			ni.subnet.DrawioTreeNode(gen).(drawio.SquareTreeNodeInterface),
			nil, ni.Name())
		//todo:
		addressToNi[ni.address] = ni
	}
	return allTreeNodes[ni]
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
	zoneTn := resourceZone(vsi).DrawioTreeNode(gen).(*drawio.ZoneTreeNode)

	drawio.GroupNIsWithVSI(zoneTn, vsi.Name(), vsiNIs)
	return nil
}

func (pgw *PublicGateway) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	if _, ok := allTreeNodes[pgw]; !ok {
		zoneTn := resourceZone(pgw).DrawioTreeNode(gen).(*drawio.ZoneTreeNode)
		allTreeNodes[pgw] = drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
	}
	return allTreeNodes[pgw]
}

func (fip *FloatingIP) DrawioTreeNode(gen vpcmodel.DrawioGeneratorInt) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	nitn := fip.Src()[0].DrawioTreeNode(gen).(*drawio.NITreeNode)
	nitn.SetFIP(fip.Name())
	return nitn
}
