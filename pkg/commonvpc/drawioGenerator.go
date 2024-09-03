/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func (nl *NaclLayer) ShowOnSubnetMode() bool           { return true }
func (r *Region) ShowOnSubnetMode() bool               { return true }
func (v *VPC) ShowOnSubnetMode() bool                  { return true }
func (z *Zone) ShowOnSubnetMode() bool                 { return true }
func (s *Subnet) ShowOnSubnetMode() bool               { return true }
func (sgl *SecurityGroupLayer) ShowOnSubnetMode() bool { return false }
func (sg *SecurityGroup) ShowOnSubnetMode() bool       { return false }
func (v *Vsi) ShowOnSubnetMode() bool                  { return false }
func (ni *NetworkInterface) ShowOnSubnetMode() bool    { return false }

func (nl *NaclLayer) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	for _, acl := range nl.NaclList {
		for _, sn := range acl.Subnets {
			gen.TreeNode(sn).(*drawio.SubnetTreeNode).SetACL(acl.Name())
		}
	}
	return nil
}

// for FormattableResource that are not VPCResourceIntf, we implement Kind():
func (r *Region) Kind() string { return "Cloud" }
func (z *Zone) Kind() string   { return "Zone" }

// implementations of the GenerateDrawioTreeNode() for resource defined in ibmvpc:
func (r *Region) IsExternal() bool { return false }
func (r *Region) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewRegionTreeNode(gen.Cloud(), r.Name)
}

func (v *VPC) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewVpcTreeNode(gen.TreeNode(v.Region()).(*drawio.RegionTreeNode), v.Name())
}

func (z *Zone) IsExternal() bool { return false }
func (z *Zone) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewZoneTreeNode(gen.TreeNode(z.VPC()).(*drawio.VpcTreeNode), z.Name)
}

func (s *Subnet) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - how to handle this error:
	zone, _ := s.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	subnetTn := drawio.NewSubnetTreeNode(zoneTn, s.Name(), s.Cidr, "")
	subnetTn.SetIsPrivate(s.IsPrivate())
	return subnetTn
}

func (sgl *SecurityGroupLayer) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	for _, sg := range sgl.SgList {
		// creating the SGs TreeNodes:
		gen.TreeNode(sg)
	}
	return nil
}

func (sg *SecurityGroup) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// creating the SG treeNodes:
	tn := drawio.NewSGTreeNode(gen.TreeNode(sg.VPC()).(*drawio.VpcTreeNode), sg.Name())
	for _, member := range sg.Members {
		// every SG member is added as an icon treeNode to the SG treeNode:
		if mTn := gen.TreeNode(member); mTn != nil {
			tn.AddIcon(mTn.(drawio.IconTreeNodeInterface))
		}
	}
	return tn
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
	return drawio.GroupNIsWithVSI(zoneTn, v.Name(), vsiNIs)
}

func (ni *NetworkInterface) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewNITreeNode(
		gen.TreeNode(ni.Subnet()).(drawio.SquareTreeNodeInterface), ni.Name(), ni.virtual)
}
