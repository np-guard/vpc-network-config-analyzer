package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func (v *VPC) ShowOnSubnetMode() bool                  { return true }
func (z *Zone) ShowOnSubnetMode() bool                 { return true }
func (s *Subnet) ShowOnSubnetMode() bool               { return true }
func (sgl *SecurityGroupLayer) ShowOnSubnetMode() bool { return false }
func (nl *NaclLayer) ShowOnSubnetMode() bool           { return true }
func (ni *NetworkInterface) ShowOnSubnetMode() bool    { return false }
func (n *IKSNode) ShowOnSubnetMode() bool              { return false }
func (r *ReservedIP) ShowOnSubnetMode() bool           { return false }
func (v *Vsi) ShowOnSubnetMode() bool                  { return false }
func (v *Vpe) ShowOnSubnetMode() bool                  { return false }
func (pgw *PublicGateway) ShowOnSubnetMode() bool      { return true }
func (fip *FloatingIP) ShowOnSubnetMode() bool         { return false }
func (tgw *TransitGateway) ShowOnSubnetMode() bool     { return true }

// implementations of the GenerateDrawioTreeNode() for resource defined in ibmvpc:
func (v *VPC) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewVpcTreeNode(gen.Cloud(), v.Name())
}
func (z *Zone) IsExternal() bool { return false }
func (z *Zone) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewZoneTreeNode(gen.TreeNode(z.VPC()).(*drawio.VpcTreeNode), z.name)
}

func (s *Subnet) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - how to handle this error:
	zone, _ := s.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	return drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.cidr, "")
}

func (sgl *SecurityGroupLayer) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	tn := drawio.NewSGTreeNode(gen.TreeNode(sgl.VPC()).(*drawio.VpcTreeNode), sgl.Name())
	for _, sg := range sgl.sgList {
		for _, member := range sg.members {
			tn.AddIcon(gen.TreeNode(member).(drawio.IconTreeNodeInterface))
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
		gen.TreeNode(ni.subnet).(drawio.SquareTreeNodeInterface), ni.Name())
}

func (n *IKSNode) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewNITreeNode(
		gen.TreeNode(n.subnet).(drawio.SquareTreeNodeInterface), n.Name())
}
func (r *ReservedIP) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewResIPTreeNode(
		gen.TreeNode(r.subnet).(drawio.SquareTreeNodeInterface), r.Name())
}

func (v *Vsi) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	if len(v.Nodes()) == 0 {
		return nil
	}
	vsiNIs := make([]drawio.TreeNodeInterface, len(v.Nodes()))
	for i, ni := range v.Nodes() {
		vsiNIs[i] = gen.TreeNode(ni)
	}
	// todo - how to handle this error:
	zone, _ := v.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	drawio.GroupNIsWithVSI(zoneTn, v.Name(), vsiNIs)
	return nil
}

func (v *Vpe) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	if len(v.Nodes()) == 0 {
		return nil
	}
	resIPs := make([]drawio.TreeNodeInterface, len(v.Nodes()))
	for i, resIP := range v.Nodes() {
		resIPs[i] = gen.TreeNode(resIP)
	}
	vpcTn := gen.TreeNode(v.VPC()).(drawio.SquareTreeNodeInterface)
	drawio.GroupResIPsWithVpe(vpcTn, v.Name(), resIPs)
	return nil
}

func (pgw *PublicGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - how to handle this error:
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

func (tgw *TransitGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewTransitGatewayTreeNode(gen.Cloud(), tgw.Name())
}
