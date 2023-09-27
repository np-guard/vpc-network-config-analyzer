package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

// DrawioResourceIntf is the interface of all the resources that are converted to a drawio treeNodes
type DrawioResourceIntf interface {
	GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface
	IsExternal() bool
}

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
	treeNodes     map[DrawioResourceIntf]drawio.TreeNodeInterface
}

func NewDrawioGenerator(cloudName string) *DrawioGenerator {
	// creates the top of the tree node - treeNodes that does not represent a specific resource.
	gen := &DrawioGenerator{}
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.cloud = drawio.NewCloudTreeNode(gen.network, cloudName)
	gen.treeNodes = map[DrawioResourceIntf]drawio.TreeNodeInterface{}
	return gen
}
func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode             { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode { return gen.publicNetwork }
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode                 { return gen.cloud }

func (gen *DrawioGenerator) TreeNode(res DrawioResourceIntf) drawio.TreeNodeInterface {
	if gen.treeNodes[res] == nil {
		gen.treeNodes[res] = res.GenerateDrawioTreeNode(gen)
	}
	return gen.treeNodes[res]
}

// ////////////////////////////////////////////////////////////////////////////////////////////////////////////
// implementations of the GenerateDrawioTreeNode() for resource defined in vpcmodel:
// (currently only ExternalNetwork, will add the grouping resource later)
func (exn *ExternalNetwork) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewInternetTreeNode(gen.PublicNetwork(), exn.CidrStr)
}

func (g *groupedEndpointsElems) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	if len(*g) == 1 {
		return gen.TreeNode((*g)[0])
	}
	subnetTn := gen.TreeNode((*g)[0]).Parent().(*drawio.SubnetTreeNode)
	groupiesTNs := make([]drawio.IconTreeNodeInterface, len(*g))
	for i, ni := range *g {
		groupiesTNs[i] = gen.TreeNode(ni).(drawio.IconTreeNodeInterface)
	}
	return drawio.NewGroupSquareTreeNode(subnetTn,groupiesTNs)
	
}

func (g *groupedExternalNodes) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	if len(*g) == 1 {
		return gen.TreeNode((*g)[0])
	}
	tooltip := []string{}
	for _, n := range *g {
		tooltip = append(tooltip, n.(*ExternalNetwork).Cidr())
	}
	name := "multi cidr"
	if all, _ := isEntirePublicInternetRange(*g); all {
		name = "all ranges"
	}
	tn := drawio.NewInternetTreeNode(gen.PublicNetwork(), name)
	tn.SetTooltip(tooltip)
	return tn
}

func (exn *ExternalNetwork) IsExternal() bool     { return true }
func (g *groupedEndpointsElems) IsExternal() bool { return false }
func (g *groupedExternalNodes) IsExternal() bool  { return true }
