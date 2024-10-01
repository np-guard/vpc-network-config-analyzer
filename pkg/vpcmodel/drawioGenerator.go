/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

// DrawioGenerator is the struct that generate the drawio tree.
// its main interface is:
// 1. TreeNode() - generate and returns the drawio tree node of a resource
// 2. the constructor - generate the treeNodes that does not represent a specific resource
// (the constructor creates the publicNetwork tree node, and the Cloud TreeNode)
// the rest of the interface i getters:
// Network(), PublicNetwork(), Cloud()
// returns the tree nodes which are created at the constructor
// please notice:
// creating the cloud treeNode is vendor specific (IBM, aws...).
// currently, the input that distinguish between the vendors is the cloudName, which is provided to NewDrawioGenerator() as parameter.
// we might later give as parameters more information to create the cloud, or create the cloud at the specific pkg.
type DrawioGenerator struct {
	network       *drawio.NetworkTreeNode
	publicNetwork *drawio.PublicNetworkTreeNode
	cloud         *drawio.CloudTreeNode
	treeNodes     map[FormattableResource]drawio.TreeNodeInterface
	lbAbstraction bool
	uc            OutputUseCase
}

func NewDrawioGenerator(cloudName string, lbAbstraction bool, uc OutputUseCase) *DrawioGenerator {
	// creates the top of the tree node - treeNodes that does not represent a specific resource.
	gen := &DrawioGenerator{}
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.cloud = drawio.NewCloudTreeNode(gen.network, cloudName)
	gen.treeNodes = map[FormattableResource]drawio.TreeNodeInterface{}
	gen.lbAbstraction = lbAbstraction
	gen.uc = uc
	return gen
}
func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode             { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode { return gen.publicNetwork }
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode                 { return gen.cloud }
func (gen *DrawioGenerator) LBAbstraction() bool                          { return gen.lbAbstraction }

func (gen *DrawioGenerator) TreeNode(res FormattableResource) drawio.TreeNodeInterface {
	if gen.treeNodes[res] == nil {
		if gen.uc != AllSubnets || res.ShowOnSubnetMode() {
			gen.treeNodes[res] = res.GenerateDrawioTreeNode(gen)
			if gen.treeNodes[res] != nil && gen.treeNodes[res].Kind() == "" {
				gen.treeNodes[res].SetKind(res.Kind())
			}
		}
	}
	return gen.treeNodes[res]
}

// ////////////////////////////////////////////////////////////////////////////////////////////////////////////
// implementations of the GenerateDrawioTreeNode() for resource defined in vpcmodel:

func (exn *ExternalNetwork) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewInternetTreeNode(gen.PublicNetwork(), exn.CidrStr)
}
func (exn *ExternalNetwork) ShowOnSubnetMode() bool     { return true }
func (g *groupedEndpointsElems) ShowOnSubnetMode() bool { return true }
func (g *groupedExternalNodes) ShowOnSubnetMode() bool  { return true }
func (e *edgeInfo) ShowOnSubnetMode() bool              { return true }

// for FormattableResource that are not VPCResourceIntf, we implement Kind():
func (g *groupedEndpointsElems) Kind() string { return "Group of Nodes" }
func (g *groupedExternalNodes) Kind() string  { return "External IPs" }
func (e *edgeInfo) Kind() string              { return "Connection" }

func (g *groupedEndpointsElems) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	if len(*g) == 1 {
		return gen.TreeNode((*g)[0])
	}
	if gen.TreeNode((*g)[0]).IsSquare() && gen.TreeNode((*g)[0]).(drawio.SquareTreeNodeInterface).IsSubnet() {
		groupedSubnetsTNs := make([]drawio.SquareTreeNodeInterface, len(*g))
		for i, node := range *g {
			groupedSubnetsTNs[i] = gen.TreeNode(node).(drawio.SquareTreeNodeInterface)
		}
		vpcTn := groupedSubnetsTNs[0].Parent().Parent().(*drawio.VpcTreeNode)
		return drawio.GroupedSubnetsSquare(vpcTn, groupedSubnetsTNs)
	}
	groupedIconsTNs := make([]drawio.IconTreeNodeInterface, len(*g))
	for i, node := range *g {
		groupedIconsTNs[i] = gen.TreeNode(node).(drawio.IconTreeNodeInterface)
	}
	subnetTn := groupedIconsTNs[0].Parent().(*drawio.SubnetTreeNode)
	return drawio.NewGroupSquareTreeNode(subnetTn, groupedIconsTNs, g.Name())
}

func (g *groupedExternalNodes) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	if len(*g) == 1 {
		return gen.TreeNode((*g)[0])
	}
	tooltip := []string{}
	for _, n := range *g {
		tooltip = append(tooltip, n.CidrStr)
	}
	name := "Various IP ranges"
	if all, _ := isEntirePublicInternetRange(*g); all {
		name = publicInternetNodeName
	} else {
		_, ipBlock := g.toIPBlocks()
		if len(ipBlock.ListToPrint()) == 1 {
			name = ipBlock.String()
		}
	}
	tn := drawio.NewInternetTreeNode(gen.PublicNetwork(), name)
	tn.SetTooltip(tooltip)
	return tn
}

func (e *edgeInfo) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	srcTn := gen.TreeNode(e.src)
	dstTn := gen.TreeNode(e.dst)
	return drawio.NewConnectivityLineTreeNode(gen.Network(), srcTn, dstTn, e.directed, e.label)
}
