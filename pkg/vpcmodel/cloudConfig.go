package vpcmodel

type CloudConfig struct {
	Nodes            []Node
	NodeSets         []NodeSet
	FilterResources  []FilterTrafficResource
	RoutingResources []RoutingResource
	NameToResource   map[string]VPCResourceIntf
	CloudName        string
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

func (c *CloudConfig) getFilterTrafficResourceOfKind(kind string) FilterTrafficResource {
	for _, filter := range c.FilterResources {
		if filter.Kind() == kind {
			return filter
		}
	}
	return nil
}
