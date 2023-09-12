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
	TN(res DrawioResourceIntf) drawio.TreeNodeInterface
}

type DrawioGenerator struct {
	network       *drawio.NetworkTreeNode
	publicNetwork *drawio.PublicNetworkTreeNode
	Tcloud        *drawio.CloudTreeNode
	TNs           map[DrawioResourceIntf]drawio.TreeNodeInterface
}

func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode {
	return gen.publicNetwork
}
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode { return gen.Tcloud }

func (gen *DrawioGenerator) Init(config *CloudConfig) {
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.TNs = map[DrawioResourceIntf]drawio.TreeNodeInterface{}
}
func (gen *DrawioGenerator) TN(res DrawioResourceIntf) drawio.TreeNodeInterface {
	if gen.TNs[res] == nil {
		gen.TNs[res] = res.GenerateDrawioTreeNode(gen)
	}
	return gen.TNs[res]
}
func (exn *ExternalNetwork) GenerateDrawioTreeNode(gen DrawioGeneratorInt) drawio.TreeNodeInterface {
	return drawio.NewInternetTreeNode(gen.PublicNetwork(), exn.CidrStr)
}
