package vpcmodel

import (
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

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
	Tcloud         *drawio.CloudTreeNode
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



type DrawioResourceIntf interface {
	GenerateDrawioTreeNode(gen DrawioGeneratorInt) drawio.TreeNodeInterface
}

type CloudConfig struct {
	Nodes            []Node
	NodeSets         []NodeSet
	FilterResources  []FilterTrafficResource
	RoutingResources []RoutingResource
	NameToResource   map[string]VPCResourceIntf
	DrawioGenerator  DrawioGeneratorInt
}

// TODO: consider add this mapping to CloudConfig
func (c *CloudConfig) getSubnetOfNode(n Node) NodeSet {
	for _, nodeSet := range c.NodeSets {
		if nodeSet.Kind() == subnetKind {
			subnetNodes := nodeSet.Nodes()
			if HasNode(subnetNodes, n) {
				return nodeSet
			}
		}
	}
	return nil
}

func (c *CloudConfig) String() string {
	res := "cloud config details:\n"
	lines := []string{}
	for _, node := range c.Nodes {
		lines = append(lines, node.Details()...)
	}
	for _, nodeSet := range c.NodeSets {
		lines = append(lines, nodeSet.Details()...)
	}
	for _, filters := range c.FilterResources {
		lines = append(lines, filters.Details()...)
	}
	for _, r := range c.RoutingResources {
		lines = append(lines, r.Details()...)
	}
	res += strings.Join(lines, "\n")
	return res
}

func (c *CloudConfig) getFilterTrafficResourceOfKind(kind string) FilterTrafficResource {
	for _, filter := range c.FilterResources {
		if filter.Kind() == kind {
			return filter
		}
	}
	return nil
}
