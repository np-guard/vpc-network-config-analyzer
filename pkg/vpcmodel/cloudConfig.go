package vpcmodel

import (
	"strings"
)

type CloudConfig struct {
	Nodes            []Node
	NodeSets         []NodeSet
	FilterResources  []FilterTrafficResource
	RoutingResources []RoutingResource
	NameToResource   map[string]NamedResourceIntf
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
		lines = addDetailsLine(lines, node.Details())
	}
	for _, nodeSet := range c.NodeSets {
		lines = addDetailsLine(lines, nodeSet.Details())
	}
	for _, filters := range c.FilterResources {
		lines = append(lines, filters.Details()...)
	}
	for _, r := range c.RoutingResources {
		lines = addDetailsLine(lines, r.Details())
	}
	res += strings.Join(lines, "\n")
	return res
}
