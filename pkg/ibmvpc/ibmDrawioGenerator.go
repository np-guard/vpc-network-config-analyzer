/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func (n *IKSNode) ShowOnSubnetMode() bool          { return false }
func (r *ReservedIP) ShowOnSubnetMode() bool       { return false }
func (v *Vpe) ShowOnSubnetMode() bool              { return false }
func (pgw *PublicGateway) ShowOnSubnetMode() bool  { return true }
func (fip *FloatingIP) ShowOnSubnetMode() bool     { return false }
func (tgw *TransitGateway) ShowOnSubnetMode() bool { return true }
func (lb *LoadBalancer) ShowOnSubnetMode() bool    { return true }
func (pip *PrivateIP) ShowOnSubnetMode() bool      { return false }

func (n *IKSNode) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewNITreeNode(
		gen.TreeNode(n.Subnet()).(drawio.SquareTreeNodeInterface), n.Name(), false)
}

func (r *ReservedIP) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewResIPTreeNode(
		gen.TreeNode(r.Subnet()).(drawio.SquareTreeNodeInterface), r.Name())
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
	return drawio.GroupResIPsWithVpe(vpcTn, v.Name(), resIPs)
}

func (pgw *PublicGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - how to handle this error:
	zone, _ := pgw.Zone()
	zoneTn := gen.TreeNode(zone).(*drawio.ZoneTreeNode)
	return drawio.NewGatewayTreeNode(zoneTn, pgw.Name())
}

func (fip *FloatingIP) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	// todo - what if r.Src() is not at size of one?
	itn := gen.TreeNode(fip.Sources()[0])
	if itn != nil {
		itn.(drawio.IconTreeNodeInterface).SetFIP(fip.Name())
	}
	return itn
}

func (tgw *TransitGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewTransitGatewayTreeNode(gen.TreeNode(tgw.Region()).(*drawio.RegionTreeNode), tgw.Name())
}
func (lb *LoadBalancer) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	if len(lb.Nodes()) == 0 {
		return nil
	}
	privateIPs := []drawio.TreeNodeInterface{}
	for _, privateIP := range lb.Nodes() {
		if ipTn := gen.TreeNode(privateIP); ipTn != nil {
			privateIPs = append(privateIPs, ipTn)
		}
	}
	vpcTn := gen.TreeNode(lb.VPC()).(drawio.SquareTreeNodeInterface)
	// here we do not call lb.Name() because lb.Name() add the kind to the name
	return drawio.GroupPrivateIPsWithLoadBalancer(vpcTn, lb.ResourceName, privateIPs)
}
func (pip *PrivateIP) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	if gen.LBAbstraction() {
		return nil
	}
	return drawio.NewPrivateIPTreeNode(
		gen.TreeNode(pip.Subnet()).(drawio.SquareTreeNodeInterface), pip.Name(), pip.original)
}
