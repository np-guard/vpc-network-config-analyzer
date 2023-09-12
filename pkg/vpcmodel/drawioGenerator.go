package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type DrawioResourceIntf interface {
	GenerateDrawioTreeNode(gen DrawioGeneratorInt) drawio.TreeNodeInterface
}

type DrawioGeneratorInt interface {
	Init(config *CloudConfig)
	Network() *drawio.NetworkTreeNode
	PublicNetwork() *drawio.PublicNetworkTreeNode
	Cloud() *drawio.CloudTreeNode
	TreeNode(res DrawioResourceIntf) drawio.TreeNodeInterface
}

type DrawioGenerator struct {
	network       *drawio.NetworkTreeNode
	publicNetwork *drawio.PublicNetworkTreeNode
	cloud        *drawio.CloudTreeNode
	treeNodes     map[DrawioResourceIntf]drawio.TreeNodeInterface
	cloudName     string
}
func NewDrawioGenerator(cloudName string) *DrawioGenerator {return &DrawioGenerator{cloudName:cloudName}}
func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode {
	return gen.publicNetwork
}
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode { return gen.cloud }

func (gen *DrawioGenerator) Init(config *CloudConfig) {
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.cloud = drawio.NewCloudTreeNode(gen.network, gen.cloudName)
	gen.treeNodes = map[DrawioResourceIntf]drawio.TreeNodeInterface{}
}
func (gen *DrawioGenerator) TreeNode(res DrawioResourceIntf) drawio.TreeNodeInterface {
	if gen.treeNodes[res] == nil {
		gen.treeNodes[res] = res.GenerateDrawioTreeNode(gen)
	}
	return gen.treeNodes[res]
}
///////////////////////////////////////////////////
func (exn *ExternalNetwork) GenerateDrawioTreeNode(gen DrawioGeneratorInt) drawio.TreeNodeInterface {
	return drawio.NewInternetTreeNode(gen.PublicNetwork(), exn.CidrStr)
}
