package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// implementations of the GenerateDrawioTreeNode() for resource defined in ibmvpc:
func (v *VPC) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewVpcTreeNode(gen.Cloud(), v.Name())
}

func (z *Zone) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewZoneTreeNode(gen.TreeNode(z.VPC()).(*drawio.VpcTreeNode), z.name)
}

func (s *Subnet) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - handle error
	zone, _ := s.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	return drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.cidr, "")
}

func (sgl *SecurityGroupLayer) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	tn := drawio.NewSGTreeNode(gen.TreeNode(sgl.VPC()).(*drawio.VpcTreeNode), sgl.Name())
	for _, sg := range sgl.sgList {
		for _, ni := range sg.members {
			gen.TreeNode(ni).(*drawio.NITreeNode).SetSG(tn)
		}
	}
	return tn
}

func (nl *NaclLayer) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	for _, acl := range nl.naclList {
		for _, sn := range acl.subnets {
			gen.TreeNode(sn).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
	}
	return nil
}

func (ni *NetworkInterface) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewNITreeNode(
		gen.TreeNode(ni.subnet).(drawio.SquareTreeNodeInterface),
		nil, ni.Name())
}
func (n *IKSNode) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}

func (v *Vsi) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	if len(v.Nodes()) == 0 {
		return nil
	}
	vsiNIs := []drawio.TreeNodeInterface{}
	for _, ni := range v.Nodes() {
		vsiNIs = append(vsiNIs, gen.TreeNode(ni))
	}
	//todo:
	zone, _ := v.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	drawio.GroupNIsWithVSI(zoneTn, v.Name(), vsiNIs)
	return nil
}

func (pgw *PublicGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	//todo:
	zone, _ := pgw.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	return drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
}

func (fip *FloatingIP) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	nitn := gen.TreeNode(fip.Src()[0]).(*drawio.NITreeNode)
	nitn.SetFIP(fip.Name())
	return nitn
}
