package vpcmodel

import (
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type DrawioGeneratorInt interface {
	Init()
	SetOneVpc(config *CloudConfig)
	Network() *drawio.NetworkTreeNode
	PublicNetwork() *drawio.PublicNetworkTreeNode
	Cloud() *drawio.CloudTreeNode
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
