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

// GetConnectivityOutputPerEachSubnetSeparately returns string results of connectivity analysis per
// single subnet with its attached nacl, separately per subnet - useful to get understanding of the
// connectivity implied from nacl configuration applied on a certain subnet in the vpc
func (c *CloudConfig) GetConnectivityOutputPerEachSubnetSeparately() string {
	// iterate over all subnets, collect all outputs per subnet connectivity
	for _, r := range c.FilterResources {
		if r.Kind() == NaclLayer {
			return r.GetConnectivityOutputPerEachElemSeparately()
		}
	}
	return ""
}
