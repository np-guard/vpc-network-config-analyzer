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

func (v *CloudConfig) String() string {
	res := "cloud config details:\n"
	lines := []string{}
	for _, node := range v.Nodes {
		lines = addDetailsLine(lines, node.Details())
	}
	for _, nodeSet := range v.NodeSets {
		lines = addDetailsLine(lines, nodeSet.Details())
	}
	for _, filters := range v.FilterResources {
		lines = append(lines, filters.Details()...)
	}
	for _, r := range v.RoutingResources {
		lines = addDetailsLine(lines, r.Details())
	}
	res += strings.Join(lines, "\n")
	return res
}
